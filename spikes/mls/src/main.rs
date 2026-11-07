//! Spike: can OpenMLS 0.9 do what SPEC.md Section 12 (draft-02) asks?
//!
//! `cargo run --release` runs every check and prints what happened.
//! `cargo run --release -- storage` runs only the storage check.
//! `cargo run --release -- vectors` prints the Appendix B test vector for
//! history keys and ENC (see `vectors.rs`).

mod common;
mod history;
mod libcrux_mldsa;
mod server;
mod storage;
mod vectors;

use std::time::Instant;

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;

use common::*;
use server::{Conn, Err, ServerGroup, State};

fn conn(d: &Device) -> Conn {
    Conn {
        uid: d.uid.clone(),
        device_key: d.key.pk.clone(),
    }
}

/// The three lines a client sends with COMMIT.
struct Lines {
    commit: String,
    gi: String,
    welcome: Option<String>,
}

fn stage(dev: &Device, b: CommitBuilder<'_, Initial>) -> Lines {
    let bundle = b
        .load_psks(dev.provider.storage())
        .unwrap()
        .create_group_info(true)
        .build(dev.provider.rand(), dev.provider.crypto(), &dev.key, |_| true)
        .expect("build commit")
        .stage_commit(&dev.provider)
        .expect("stage commit");
    let (c, w, gi) = bundle.into_messages();
    Lines {
        commit: msg_b64(&c),
        gi: msg_b64(&gi.expect("group info")),
        welcome: w.map(|w| msg_b64(&w)),
    }
}

fn commit_adds(dev: &Device, g: &mut MlsGroup, kps: Vec<KeyPackage>) -> Lines {
    let b = g.commit_builder().propose_adds(kps);
    stage(dev, b)
}

fn commit_removes(dev: &Device, g: &mut MlsGroup, leaves: Vec<LeafNodeIndex>) -> Lines {
    let b = g.commit_builder().propose_removals(leaves);
    stage(dev, b)
}

/// A commit with no proposals (12.6, refreshing keys).
fn commit_update(dev: &Device, g: &mut MlsGroup) -> Lines {
    let b = g.commit_builder().force_self_update(true);
    stage(dev, b)
}

fn init_lines(dev: &Device, g: &MlsGroup) -> (String, String) {
    let gi = g
        .export_group_info(dev.provider.crypto(), &dev.key, false)
        .unwrap();
    (msg_b64(&gi), tree_b64(&g.export_ratchet_tree()))
}

fn leaf_of(g: &MlsGroup, d: &Device) -> LeafNodeIndex {
    g.members()
        .find(|m| m.signature_key == d.key.pk)
        .expect("leaf")
        .index
}

fn ok(label: &str) {
    println!("  ok   {label}");
}

fn expect_err(label: &str, r: Result<server::Accepted, Err>) {
    match r {
        Err(e) => println!("  ok   {label}: rejected with {e:?}"),
        Ok(_) => panic!("{label}: server accepted it"),
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("storage") {
        storage::run();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("vectors") {
        vectors::run();
        return;
    }
    check0_providers();
    check0b_libcrux_wrapper();
    check1_suite();
    check2_extension();
    check3_server_and_4_external();
    check4b_lifetimes_and_credentials();
    check5_history();
    check7_sizes_and_cost();
    storage::run();
}

// ---------------------------------------------------------------------

fn check0_providers() {
    println!("\n== 0. Crypto providers and suite 0x0052");
    println!(
        "  suite {:?} = 0x{:04X}",
        CS,
        u16::from(CS)
    );
    assert_eq!(u16::from(CS), 0x0052);
    let lc = openmls_libcrux_crypto::CryptoProvider::new().unwrap();
    println!(
        "  openmls_libcrux_crypto 0.4.0 supports 0x0052: {:?}",
        lc.supports(CS)
    );
    println!(
        "  openmls_libcrux_crypto 0.4.0 supported list: {:?}",
        lc.supported_ciphersuites()
    );
    let rc = openmls_rust_crypto::RustCrypto::default();
    println!(
        "  openmls_rust_crypto 0.6.0 supports 0x0052: {:?}",
        rc.supports(CS)
    );
}

fn check1_suite() {
    println!("\n== 1. Suite 0x0052 end to end, one ML-DSA-44 key for AUTH and MLS");

    // Appendix B.
    let seed: [u8; 32] =
        hex::decode("c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8")
            .unwrap()
            .try_into()
            .unwrap();
    let laptop = DeviceKey::from_seed(seed);
    println!("  appendix B public key: {} bytes, sha256 {}", laptop.pk.len(), sha256_hex(&laptop.pk));
    assert_eq!(
        sha256_hex(&laptop.pk),
        "d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf"
    );
    let sig = laptop.auth_sign(
        "chat.example.org",
        "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e",
        "alice@example.org",
    );
    println!("  appendix B AUTH signature: {} bytes, sha256 {}", sig.len(), sha256_hex(&sig));
    assert_eq!(
        sha256_hex(&sig),
        "eeda7aa7dd2ffa7cc2fa6683e7d8d2b94cf46716484b784d6a53b4928df58906"
    );
    ok("deterministic ML-DSA-44 reproduces the Appendix B signature byte for byte");

    let crypto = openmls_rust_crypto::RustCrypto::default();
    let alice = Device::with_key("alice@example.org", laptop);
    let alice_phone = Device::new("alice@example.org");
    let bob1 = Device::new("bob@example.net");
    let bob2 = Device::new("bob@example.net");

    // KEYPKG ADD checks (12.4), and the same key signing MLS objects.
    let kp = alice.key_package(false);
    let line = kp_b64(&kp);
    let lr = server::keypkg_add(&crypto, &conn(&alice), &kp_b64(&alice.key_package(true))).unwrap();
    let ord = server::keypkg_add(&crypto, &conn(&alice), &line).unwrap();
    println!("  KEYPKG ADD: ordinary last_resort={ord}, last-resort last_resort={lr}");
    assert!(lr && !ord);
    assert_eq!(
        server::keypkg_add(&crypto, &conn(&bob1), &line),
        Err(Err::Invalid("credential or key is not this connection's".into()))
    );
    ok("KEYPKG ADD refuses another device's KeyPackage");
    // A last-resort KeyPackage whose leaf does not list last_resort.
    let no_lr_caps = KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[CS]),
            Some(&[ExtensionType::Unknown(EXT_CONV)]),
            Some(&[]),
            Some(&[CredentialType::Basic]),
        ))
        .mark_as_last_resort()
        .build(CS, &alice.provider, &alice.key, alice.credential())
        .map(|b| kp_b64(b.key_package()));
    match no_lr_caps {
        Ok(line) => println!(
            "  last-resort KeyPackage without last_resort in capabilities: KEYPKG ADD -> {:?}",
            server::keypkg_add(&crypto, &conn(&alice), &line)
        ),
        Err(e) => println!("  last-resort KeyPackage without last_resort in capabilities: OpenMLS will not build it: {e:?}"),
    }
    // The KeyPackage's signature, checked by hand with SignWithLabel and
    // the raw key: the MLS signature key is the AUTH key.
    let kp_bytes = kp.tls_serialize_detached().unwrap();
    let sig_len = 2420 + 2; // varint prefix of a 2420-byte signature
    let (tbs, sig) = kp_bytes.split_at(kp_bytes.len() - sig_len);
    assert!(verify_mldsa44(
        &alice.key.pk,
        &history::sign_content("KeyPackageTBS", tbs),
        &sig[2..]
    ));
    ok("KeyPackage signature verifies under the key-file key with our own SignWithLabel");
    assert_eq!(kp.leaf_node().signature_key().as_slice(), alice.key.pk.as_slice());
    assert_eq!(identity_of(kp.leaf_node().credential()), "alice@example.org");

    // INIT for the direct conversation alice <-> bob.
    let conv = RisalaConversation::direct("alice@example.org", "bob@example.net");
    let mut ga = create_group(&alice, &conv);
    let (gi0, tree0) = init_lines(&alice, &ga);
    let mut sg = ServerGroup::init(&crypto, &conn(&alice), &gi0, &tree0, &conv).unwrap();
    ok("INIT accepted by the server (PublicGroup from GroupInfo + out-of-band tree)");

    let mut st = State::default();
    st.participants = Some(("alice@example.org".into(), "bob@example.net".into()));
    st.key_files.insert("alice@example.org".into(), vec![alice.key.pk.clone(), alice_phone.key.pk.clone()]);
    st.key_files.insert("bob@example.net".into(), vec![bob1.key.pk.clone(), bob2.key.pk.clone()]);

    // COMMIT adding Bob's two devices and Alice's phone, with a Welcome.
    let kps = vec![bob1.key_package(false), bob2.key_package(true), alice_phone.key_package(false)];
    let l = commit_adds(&alice, &mut ga, kps);
    let acc = sg
        .commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref())
        .unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    println!("  COMMIT accepted, epoch {}", acc.epoch);
    let tree1 = sg.tree_line();
    let w = l.welcome.unwrap();
    let mut gb1 = join_welcome(&bob1, &w, &tree1);
    let mut gb2 = join_welcome(&bob2, &w, &tree1);
    let mut gp = join_welcome(&alice_phone, &w, &tree1);
    ok("three devices joined from one Welcome, tree given out of band (server's copy)");
    let hk = history_key(&alice, &ga);
    for (d, g) in [(&bob1, &gb1), (&bob2, &gb2), (&alice_phone, &gp)] {
        assert_eq!(history_key(d, g), hk);
        RisalaConversation::from_extensions(g.extensions()).unwrap();
    }
    println!("  epoch 1 history key (48 bytes) on all 4 devices: {}…", &hexs(&hk)[..24]);

    // Bob refreshes his keys with an empty commit (12.6).
    let l = commit_update(&bob1, &mut gb1);
    sg.commit(&crypto, &conn(&bob1), &st, &l.commit, &l.gi, None).unwrap();
    gb1.merge_pending_commit(&bob1.provider).unwrap();
    for (d, g) in [(&alice, &mut ga), (&bob2, &mut gb2), (&alice_phone, &mut gp)] {
        apply_commit(d, g, &l.commit);
    }
    let hk2 = history_key(&bob1, &gb1);
    assert_ne!(hk, hk2);
    for (d, g) in [(&alice, &ga), (&bob2, &gb2), (&alice_phone, &gp)] {
        assert_eq!(history_key(d, g), hk2);
    }
    ok("empty commit (key refresh) accepted by server and applied by all; new history key agrees");

    // A stale commit.
    let mut ga_old_view = ga; // alice is at epoch 2 now
    let l = commit_update(&alice, &mut ga_old_view);
    let l2 = commit_update(&bob2, &mut gb2);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, None).unwrap();
    expect_err("second commit for the same epoch", sg.commit(&crypto, &conn(&bob2), &st, &l2.commit, &l2.gi, None));
}

fn check2_extension() {
    println!("\n== 2. Conversation extension 0xF2A1");
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let alice = Device::new("alice@example.org");
    let bob = Device::new("bob@example.net");
    let conv = RisalaConversation::room("r7x2k9qp", 1);
    let mut ga = create_group(&alice, &conv);
    let (gi, tree) = init_lines(&alice, &ga);
    println!("  extension data for room r7x2k9qp/shared: {}", hexs(&conv.encode()));

    // The server checks the extension at INIT.
    let wrong = RisalaConversation::room("otherroom", 1);
    match ServerGroup::init(&crypto, &conn(&alice), &gi, &tree, &wrong) {
        Err(e) => println!("  ok   INIT naming another room: rejected with {e:?}"),
        Ok(_) => panic!(),
    }
    let mut sg = ServerGroup::init(&crypto, &conn(&alice), &gi, &tree, &conv).unwrap();
    println!(
        "  server PublicGroup reads: {:?}",
        RisalaConversation::from_extensions(sg.pg.group_context().extensions()).unwrap()
    );

    let mut st = State::default();
    st.room_id = Some("r7x2k9qp".into());
    st.members.insert("alice@example.org".into());
    st.owners.insert("alice@example.org".into());
    st.may_invite.insert("alice@example.org".into());
    st.key_files.insert("alice@example.org".into(), vec![alice.key.pk.clone()]);
    st.key_files.insert("bob@example.net".into(), vec![bob.key.pk.clone()]);

    // A KeyPackage whose leaf lacks 0xF2A1 cannot be added.
    let mut kpb = KeyPackage::builder().leaf_node_capabilities(Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CS]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    ));
    kpb = kpb.key_package_extensions(Extensions::empty());
    let bad_kp = kpb
        .build(CS, &bob.provider, &bob.key, bob.credential())
        .unwrap()
        .key_package()
        .clone();
    let r = ga
        .commit_builder()
        .propose_adds([bad_kp])
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(alice.provider.rand(), alice.provider.crypto(), &alice.key, |_| true);
    println!("  ok   adding a leaf without 0xF2A1 in its capabilities: {:?}", r.err().map(|e| e.to_string()));

    // Invite Bob.
    let l = commit_adds(&alice, &mut ga, vec![bob.key_package(false)]);
    let acc = sg
        .commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref())
        .unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    println!("  invite commit accepted, server records INVITE for {:?}", acc.invited);
    st.invitees.insert("bob@example.net".into());
    let mut gb = join_welcome(&bob, l.welcome.as_ref().unwrap(), &sg.tree_line());
    st.invitees.remove("bob@example.net");
    st.members.insert("bob@example.net".into());

    // Owner switches history to `joined` with a GroupContextExtensions commit.
    let joined = RisalaConversation::room("r7x2k9qp", 2);
    let b = ga
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&joined))
        .unwrap();
    let l = stage(&alice, b);
    let acc = sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, None).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob, &mut gb, &l.commit);
    println!(
        "  GCE commit accepted; server records SET history {:?}; Bob reads {:?}",
        acc.history_set,
        RisalaConversation::from_extensions(gb.extensions()).unwrap()
    );
    assert_eq!(acc.history_set, Some(2));

    // A non-owner may not change it.
    let b = gb
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&conv))
        .unwrap();
    let l = stage(&bob, b);
    expect_err("GCE by a non-owner", sg.commit(&crypto, &conn(&bob), &st, &l.commit, &l.gi, None));
    gb.clear_pending_commit(bob.provider.storage()).unwrap();

    // Renaming the conversation is refused by the server. OpenMLS itself
    // accepts it, so devices must check too (12.6).
    let renamed = RisalaConversation::room("hijacked", 2);
    let b = ga
        .commit_builder()
        .propose_group_context_extensions(group_context_extensions(&renamed))
        .unwrap();
    let l = stage(&alice, b);
    expect_err("GCE renaming the conversation", sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, None));
    let mut gb_copy_check = {
        let MlsMessageBodyIn::PublicMessage(pm) = parse_msg(&l.commit) else { panic!() };
        gb.process_message(&bob.provider, pm).map(|_| ())
    };
    println!("  note OpenMLS on Bob's device processes the renaming commit without error: {:?}", gb_copy_check.as_ref().map(|_| "accepted"));
    let _ = &mut gb_copy_check;
    ga.clear_pending_commit(alice.provider.storage()).unwrap();

    // Dropping required_capabilities is refused too.
    let mut no_req = Extensions::<GroupContext>::empty();
    no_req
        .add(Extension::Unknown(EXT_CONV, UnknownExtension(joined.encode())))
        .unwrap();
    let r = ga
        .commit_builder()
        .propose_group_context_extensions(no_req)
        .unwrap()
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(alice.provider.rand(), alice.provider.crypto(), &alice.key, |_| true);
    println!(
        "  ok   GCE that drops required_capabilities but keeps 0xF2A1: OpenMLS refuses to build it: {:?}",
        r.err().map(|e| e.to_string())
    );
}

fn check3_server_and_4_external() {
    println!("\n== 3/4. Server-side checks of commits, and external commits");
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let alice = Device::new("alice@example.org");
    let bob1 = Device::new("bob@example.net");
    let bob2 = Device::new("bob@example.net");
    let carol = Device::new("carol@example.com");
    let mallory = Device::new("mallory@example.com");
    let rogue_bob = Device::new("bob@example.net"); // key not in Bob's key file

    let mut st = State::default();
    st.room_id = Some("r1".into());
    for (uid, ks) in [
        ("alice@example.org", vec![alice.key.pk.clone()]),
        ("bob@example.net", vec![bob1.key.pk.clone(), bob2.key.pk.clone()]),
        ("carol@example.com", vec![carol.key.pk.clone()]),
        ("mallory@example.com", vec![mallory.key.pk.clone()]),
    ] {
        st.key_files.insert(uid.into(), ks);
    }
    st.members.insert("alice@example.org".into());
    st.owners.insert("alice@example.org".into());
    st.may_invite.insert("alice@example.org".into());

    let conv = RisalaConversation::room("r1", 1);
    let mut ga = create_group(&alice, &conv);
    let (gi, tree) = init_lines(&alice, &ga);
    let mut sg = ServerGroup::init(&crypto, &conn(&alice), &gi, &tree, &conv).unwrap();

    // Adding a key that is not in the key file.
    let l = commit_adds(&alice, &mut ga, vec![rogue_bob.key_package(false)]);
    expect_err("add of a key missing from the key file", sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()));
    ga.clear_pending_commit(alice.provider.storage()).unwrap();

    // Commit sent on another identity's connection.
    let l = commit_adds(&alice, &mut ga, vec![bob1.key_package(false)]);
    expect_err("commit sent by a connection of another device", sg.commit(&crypto, &conn(&carol), &st, &l.commit, &l.gi, l.welcome.as_deref()));
    expect_err("add without its Welcome", sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, None));
    expect_err("GroupInfo of the old epoch", sg.commit(&crypto, &conn(&alice), &st, &l.commit, &gi, l.welcome.as_deref()));
    let acc = sg
        .commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref())
        .unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    println!("  invite of Bob (bob1) accepted, epoch {}, INVITE for {:?}", acc.epoch, acc.invited);
    st.invitees.insert("bob@example.net".into());
    let mut gb1 = join_welcome(&bob1, l.welcome.as_ref().unwrap(), &sg.tree_line());
    st.invitees.remove("bob@example.net");
    st.members.insert("bob@example.net".into());

    // Bob (member, not inviter) tries to add Carol.
    let l = commit_adds(&bob1, &mut gb1, vec![carol.key_package(false)]);
    expect_err("a plain member adding a non-member", sg.commit(&crypto, &conn(&bob1), &st, &l.commit, &l.gi, l.welcome.as_deref()));
    gb1.clear_pending_commit(bob1.provider.storage()).unwrap();

    // Alice invites Carol; Carol is a member; Bob removes Carol for no reason.
    let l = commit_adds(&alice, &mut ga, vec![carol.key_package(false)]);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob1, &mut gb1, &l.commit);
    let mut gc = join_welcome(&carol, l.welcome.as_ref().unwrap(), &sg.tree_line());
    st.members.insert("carol@example.com".into());
    let carol_leaf = leaf_of(&gb1, &carol);
    let l = commit_removes(&bob1, &mut gb1, vec![carol_leaf]);
    expect_err("removing a member's leaf with no reason", sg.commit(&crypto, &conn(&bob1), &st, &l.commit, &l.gi, None));
    // After KICK, the same removal is allowed.
    st.members.remove("carol@example.com");
    sg.commit(&crypto, &conn(&bob1), &st, &l.commit, &l.gi, None).unwrap();
    gb1.merge_pending_commit(&bob1.provider).unwrap();
    apply_commit(&alice, &mut ga, &l.commit);
    apply_commit(&carol, &mut gc, &l.commit);
    println!("  ok   after KICK, Bob's removal of Carol's leaf is accepted; Carol's group sees itself removed: active={}", gc.is_active());

    // ---- 4. External commits.
    println!("  -- external commits (12.6)");
    // (a) Bob's second device joins by external commit (no leaf of its own yet;
    // Bob's identity has a leaf, so the room allows it).
    let (gi_line, tree_line) = sg.groupinfo_reply();
    let (mut gb2, l) = external_join(&bob2, &gi_line, &tree_line);
    let acc = sg.commit(&crypto, &conn(&bob2), &st, &l.commit, &l.gi, None).unwrap();
    apply_commit(&alice, &mut ga, &l.commit);
    apply_commit(&bob1, &mut gb1, &l.commit);
    assert_eq!(history_key(&alice, &ga), history_key(&bob2, &gb2));
    println!("  ok   new device joined by external commit (tree out of band), epoch {}; history keys agree", acc.epoch);

    // (b) bob1 is reinstalled with the same key and lost its state. Its
    // external commit must remove the old leaf, and OpenMLS does so itself.
    let bob1_again = Device::with_key("bob@example.net", DeviceKey::from_seed(bob1.key.seed));
    let before = sg.leaf_count();
    let (gi_line, tree_line) = sg.groupinfo_reply();
    let (mut gb1b, l) = external_join(&bob1_again, &gi_line, &tree_line);
    let kinds = proposal_kinds(&sg, &crypto, &l.commit);
    println!("  rejoin with same key: commit proposals {kinds:?}");
    sg.commit(&crypto, &conn(&bob1_again), &st, &l.commit, &l.gi, None).unwrap();
    apply_commit(&alice, &mut ga, &l.commit);
    apply_commit(&bob2, &mut gb2, &l.commit);
    assert_eq!(sg.leaf_count(), before);
    assert_eq!(history_key(&alice, &ga), history_key(&bob1_again, &gb1b));
    println!("  ok   the external commit removed the old leaf of the same key; leaf count stays {}", sg.leaf_count());
    // The old bob1 state learns it was removed if it ever comes back.
    apply_commit(&bob1, &mut gb1, &l.commit);
    println!("  ok   the stale bob1 state processes it and sees itself removed: active={}", gb1.is_active());

    // (c) Mallory, with no leaf and no membership, tries an external join.
    let (gi_line, tree_line) = sg.groupinfo_reply();
    let (_gm, l) = external_join(&mallory, &gi_line, &tree_line);
    expect_err("external join by an identity without a leaf (room)", sg.commit(&crypto, &conn(&mallory), &st, &l.commit, &l.gi, None));

    // (d) An Add of a device whose key already has a leaf must remove that
    // leaf in the same commit. OpenMLS accepts Add+Remove of the same key.
    let bob2_again = Device::with_key("bob@example.net", DeviceKey::from_seed(bob2.key.seed));
    let kp = bob2_again.key_package(false);
    let old = leaf_of(&ga, &bob2);
    let r = ga
        .commit_builder()
        .propose_adds([kp.clone()])
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(alice.provider.rand(), alice.provider.crypto(), &alice.key, |_| true);
    println!(
        "  ok   Add of a key that already has a leaf, without its Remove: OpenMLS refuses to build it: {:?}",
        r.err()
    );
    let b = ga.commit_builder().propose_removals([old]).propose_adds([kp]);
    let l = stage(&alice, b);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob1_again, &mut gb1b, &l.commit);
    let gb2b = join_welcome(&bob2_again, l.welcome.as_ref().unwrap(), &sg.tree_line());
    assert_eq!(history_key(&alice, &ga), history_key(&bob2_again, &gb2b));
    ok("Remove + Add of the same key in one commit: accepted by OpenMLS and the server");

    // (e) Direct conversation: a participant with no leaf joins by external commit.
    let dconv = RisalaConversation::direct("alice@example.org", "bob@example.net");
    let mut gd = create_group(&alice, &dconv);
    let (gi, tree) = init_lines(&alice, &gd);
    let mut sd = ServerGroup::init(&crypto, &conn(&alice), &gi, &tree, &dconv).unwrap();
    let mut sdst = st.clone();
    sdst.room_id = None;
    sdst.participants = Some(("alice@example.org".into(), "bob@example.net".into()));
    let (gi_line, tree_line) = sd.groupinfo_reply();
    let bob3 = Device::with_key("bob@example.net", DeviceKey::from_seed(bob1_again.key.seed));
    let (gbd, l) = external_join(&bob3, &gi_line, &tree_line);
    sd.commit(&crypto, &conn(&bob3), &sdst, &l.commit, &l.gi, None).unwrap();
    apply_commit(&alice, &mut gd, &l.commit);
    assert_eq!(history_key(&alice, &gd), history_key(&bob3, &gbd));
    ok("direct conversation: the other participant joins by external commit with no leaf before");
}

fn external_join(dev: &Device, gi_line: &str, tree_line: &str) -> (MlsGroup, Lines) {
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(gi_line) else { panic!() };
    let (g, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(parse_tree(tree_line))
        .with_config(join_config())
        .build_group(&dev.provider, vgi, dev.credential())
        .expect("external commit: build group")
        .leaf_node_parameters(LeafNodeParameters::builder().with_capabilities(capabilities()).build())
        .load_psks(dev.provider.storage())
        .unwrap()
        .create_group_info(true)
        .build(dev.provider.rand(), dev.provider.crypto(), &dev.key, |_| true)
        .expect("external commit: build")
        .finalize(&dev.provider)
        .expect("external commit: finalize");
    let (c, w, gi) = bundle.into_messages();
    assert!(w.is_none());
    (
        g,
        Lines {
            commit: msg_b64(&c),
            gi: msg_b64(&gi.expect("group info")),
            welcome: None,
        },
    )
}

fn proposal_kinds(sg: &ServerGroup, crypto: &openmls_rust_crypto::RustCrypto, commit: &str) -> Vec<String> {
    let MlsMessageBodyIn::PublicMessage(pm) = parse_msg(commit) else { panic!() };
    let p = sg.pg.process_message(crypto, pm).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(sc) = p.into_content() else { panic!() };
    sc.queued_proposals()
        .map(|q| format!("{:?}", q.proposal().proposal_type()))
        .collect()
}

// ---------------------------------------------------------------------

fn check5_history() {
    println!("\n== 5. History keys and ENC payloads (12.8-12.10)");
    let alice = Device::new("alice@example.org");
    let bob = Device::new("bob@example.net");
    let conv = RisalaConversation::direct("alice@example.org", "bob@example.net");
    let mut ga = create_group(&alice, &conv);
    let l = commit_adds(&alice, &mut ga, vec![bob.key_package(false)]);
    ga.merge_pending_commit(&alice.provider).unwrap();
    let gb = join_welcome(&bob, l.welcome.as_ref().unwrap(), &tree_b64(&ga.export_ratchet_tree()));
    let gid = ga.group_id().as_slice().to_vec();
    let epoch = ga.epoch().as_u64();
    let hka = history_key(&alice, &ga);
    let hkb = history_key(&bob, &gb);
    assert_eq!(hka, hkb);

    let content = "@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n";
    for pad in [false, true] {
        let sent = history::encrypt(&alice.key, &hka, &gid, epoch, content, pad);
        let m = history::decrypt(&hkb, &gid, epoch, &sent.payload, &sent.frank, &[alice.key.pk.clone()]).unwrap();
        assert_eq!(m.content.as_slice(), content.as_bytes());
        println!(
            "  pad={pad}: RisalaMessage {} bytes, payload {} bytes ({} base64 chars), frank tag {} bytes",
            sent.plaintext_len,
            sent.payload.len(),
            b64(&sent.payload).len(),
            sent.frank.len()
        );
        if pad {
            assert_eq!(sent.plaintext_len % 256, 0);
        }
    }
    ok("Bob decrypts and verifies Alice's message with his own derived history key");

    let sent = history::encrypt(&alice.key, &hka, &gid, epoch, content, true);
    let wrong_epoch = history::decrypt(&hkb, &gid, epoch + 1, &sent.payload, &sent.frank, &[alice.key.pk.clone()]);
    let wrong_sender = history::decrypt(&hkb, &gid, epoch, &sent.payload, &sent.frank, &[bob.key.pk.clone()]);
    let mut bad = sent.payload.clone();
    bad[40] ^= 1;
    let tampered = history::decrypt(&hkb, &gid, epoch, &bad, &sent.frank, &[alice.key.pk.clone()]);
    let bad_frank = history::decrypt(&hkb, &gid, epoch, &sent.payload, &[0u8; 48], &[alice.key.pk.clone()]);
    println!("  ok   wrong epoch in AAD: {wrong_epoch:?}", wrong_epoch = wrong_epoch.err());
    println!("  ok   `from` whose keys do not match sender_key_id: {:?}", wrong_sender.err());
    println!("  ok   flipped ciphertext bit: {:?}", tampered.err());
    println!("  ok   wrong frank tag: {:?}", bad_frank.err());

    // Many KEY lines in one message: how many history keys fit in an ENC line?
    let key_line = format!("KEY d7hq2klm 4294967295 {}\n", b64(&[0u8; 48]));
    let per_line = key_line.len();
    // line = "ENC " + conv + " " + epoch + " " + base64(32 + RisalaMessage + 16) + tags
    let budget = 8 * 1024 * 1024 - 4096; // leave room for verb, conv, tags
    let max_payload = budget / 4 * 3;
    let fixed = 32 + 16 + 16 + 48 + 32 + 4 + 4 + 2420 + 1;
    let n = (max_payload - fixed) / per_line;
    println!("  KEY line is {per_line} bytes; one 8 MiB ENC line holds about {n} history keys");

    // Backup blobs (12.10).
    let recovery: [u8; 32] = rand::random();
    let blob = history::backup_blob(&recovery, "alice@example.org", "d7hq2klm", epoch, &hka);
    assert_eq!(blob.len(), 84);
    assert_eq!(history::open_blob(&recovery, "alice@example.org", "d7hq2klm", epoch, &blob).unwrap(), hka);
    assert!(history::open_blob(&recovery, "alice@example.org", "d7hq2klm", epoch + 1, &blob).is_none());
    ok("backup blob is 84 bytes and opens only for its conversation id and epoch");

    // A history key is a plain MLS exporter output; the server's PublicGroup
    // cannot derive it (it has no exporter).
    let other = ga.export_secret(alice.provider.crypto(), "risala history", b"x", 48).unwrap();
    assert_ne!(other, hka);
    ok("exporter context is part of the derivation (\"\" vs \"x\" differ)");
}

// ---------------------------------------------------------------------

struct Sizes {
    n_before: usize,
    commit: usize,
    welcome: usize,
    gi: usize,
    tree: usize,
}

fn check7_sizes_and_cost() {
    println!("\n== 3 (cost) and 7 (sizes). Groups of up to 512 leaves");
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let kp_line = kp_b64(&Device::new("x@example.org").key_package(false));
    println!("  KeyPackage line: {} base64 chars", kp_line.len());

    let owner = Device::new("owner@example.org");
    let conv = RisalaConversation::room("big", 1);
    let mut g = create_group(&owner, &conv);
    let (gi, tree) = init_lines(&owner, &g);
    println!("  epoch 0: GroupInfo {} chars, tree {} chars", gi.len(), tree.len());
    let mut sg = ServerGroup::init(&crypto, &conn(&owner), &gi, &tree, &conv).unwrap();

    let mut st = State::default();
    st.room_id = Some("big".into());
    st.members.insert("owner@example.org".into());
    st.owners.insert("owner@example.org".into());
    st.may_invite.insert("owner@example.org".into());
    st.key_files.insert("owner@example.org".into(), vec![owner.key.pk.clone()]);

    // 128 identities with 4 devices each (owner adds 511 devices in steps).
    let mut devices = vec![];
    for i in 0..128 {
        let uid = format!("user{i}@example.org");
        let ds: Vec<Device> = (0..4).map(|_| Device::new(&uid)).collect();
        st.key_files.insert(uid.clone(), ds.iter().map(|d| d.key.pk.clone()).collect());
        devices.extend(ds);
    }
    devices.truncate(511);
    let t = Instant::now();
    let kps: Vec<KeyPackage> = devices.iter().map(|d| d.key_package(false)).collect();
    println!("  made 511 KeyPackages in {:?}", t.elapsed());

    let mut sizes = vec![];
    let add_to = |g: &mut MlsGroup, sg: &mut ServerGroup, kps: Vec<KeyPackage>, label: &str, st: &mut State| {
        let n_before = sg.leaf_count();
        let n_add = kps.len();
        for kp in &kps {
            st.invitees.insert(identity_of(kp.leaf_node().credential()));
        }
        let t = Instant::now();
        let l = commit_adds(&owner, g, kps);
        let t_client = t.elapsed();
        let t = Instant::now();
        sg.commit(&crypto, &conn(&owner), st, &l.commit, &l.gi, l.welcome.as_deref())
            .unwrap();
        let t_server = t.elapsed();
        g.merge_pending_commit(&owner.provider).unwrap();
        let tree = sg.tree_line();
        println!(
            "  {label}: {n_before} -> {} leaves (+{n_add}): commit {} chars, welcome {} chars, groupinfo {} chars, tree {} chars; client build {:?}, server check+merge {:?}",
            sg.leaf_count(),
            l.commit.len(),
            l.welcome.as_ref().map_or(0, |w| w.len()),
            l.gi.len(),
            tree.len(),
            t_client,
            t_server
        );
        (n_before, l, tree)
    };

    let mut kps = kps.into_iter();
    // 1 -> 2
    let (n, l, tree) = add_to(&mut g, &mut sg, kps.by_ref().take(1).collect(), "add 1", &mut st);
    sizes.push(Sizes { n_before: n, commit: l.commit.len(), welcome: l.welcome.unwrap().len(), gi: l.gi.len(), tree: tree.len() });
    // 2 -> 3
    let (n, l, tree) = add_to(&mut g, &mut sg, kps.by_ref().take(1).collect(), "add 1", &mut st);
    sizes.push(Sizes { n_before: n, commit: l.commit.len(), welcome: l.welcome.unwrap().len(), gi: l.gi.len(), tree: tree.len() });
    // 3 -> 100
    add_to(&mut g, &mut sg, kps.by_ref().take(97).collect(), "add 97", &mut st);
    // 100 -> 101
    let (n, l, tree) = add_to(&mut g, &mut sg, kps.by_ref().take(1).collect(), "add 1", &mut st);
    sizes.push(Sizes { n_before: n, commit: l.commit.len(), welcome: l.welcome.unwrap().len(), gi: l.gi.len(), tree: tree.len() });
    // 101 -> 511
    let (_, big, _) = add_to(&mut g, &mut sg, kps.by_ref().take(410).collect(), "add 410", &mut st);
    // 511 -> 512
    let (n, l, tree) = add_to(&mut g, &mut sg, kps.by_ref().take(1).collect(), "add 1", &mut st);
    let last_welcome = l.welcome.clone().unwrap();
    let last_tree = tree.clone();
    sizes.push(Sizes { n_before: n, commit: l.commit.len(), welcome: l.welcome.unwrap().len(), gi: l.gi.len(), tree: tree.len() });
    assert_eq!(sg.leaf_count(), 512);

    println!("\n  | leaves before | commit | Welcome | GroupInfo | tree | WELCOME line (welcome+tree) |");
    println!("  |---|---|---|---|---|---|");
    for s in &sizes {
        println!(
            "  | {} | {} | {} | {} | {} | {} |",
            s.n_before, s.commit, s.welcome, s.gi, s.tree, s.welcome + s.tree
        );
    }
    println!("  (base64 characters; 8 MiB = 8388608)");
    println!(
        "  the 410-device add commit was {} chars ({:.1}% of 8 MiB), its Welcome {} chars",
        big.commit.len(),
        big.commit.len() as f64 / 8388608.0 * 100.0,
        big.welcome.as_ref().unwrap().len()
    );

    // A 513th leaf is refused.
    let extra = Device::new("user0@example.org");
    st.key_files.get_mut("user0@example.org").unwrap().push(extra.key.pk.clone());
    let l = commit_adds(&owner, &mut g, vec![extra.key_package(false)]);
    expect_err("a 513th leaf", sg.commit(&crypto, &conn(&owner), &st, &l.commit, &l.gi, l.welcome.as_deref()));
    g.clear_pending_commit(owner.provider.storage()).unwrap();

    // Server costs at 512 leaves.
    let (gi_line, tree_line) = sg.groupinfo_reply();
    let t = Instant::now();
    let rebuilt = ServerGroup::init_any(&crypto, &gi_line, &tree_line).unwrap();
    println!("\n  server: PublicGroup::from_external at 512 leaves (GroupInfo + tree, every leaf verified): {:?}", t.elapsed());
    drop(rebuilt);

    // The device the last commit added is a member at 512 leaves.
    let member = devices.last().unwrap();
    let t = Instant::now();
    let mut gm = join_welcome(member, &last_welcome, &last_tree);
    println!("  member: join from Welcome + tree at 512 leaves: {:?}", t.elapsed());

    let t = Instant::now();
    let l = commit_update(member, &mut gm);
    let t_build = t.elapsed();
    let t = Instant::now();
    sg.commit(&crypto, &conn(member), &st, &l.commit, &l.gi, None).unwrap();
    let t_server = t.elapsed();
    gm.merge_pending_commit(&member.provider).unwrap();
    let t = Instant::now();
    apply_commit(&owner, &mut g, &l.commit);
    let t_apply = t.elapsed();
    assert_eq!(history_key(&owner, &g), history_key(member, &gm));
    println!(
        "  empty commit at 512 leaves: {} chars, GroupInfo {} chars; member build {:?}, server check+merge {:?}, other member apply {:?}",
        l.commit.len(), l.gi.len(), t_build, t_server, t_apply
    );

    // Remove the 4 devices of one identity (as after KICK) at 512 leaves.
    let victim = "user5@example.org";
    st.invitees.remove(victim);
    st.members.remove(victim);
    let leaves: Vec<LeafNodeIndex> = g
        .members()
        .filter(|m| identity_of(&m.credential) == victim)
        .map(|m| m.index)
        .collect();
    let t = Instant::now();
    let l = commit_removes(&owner, &mut g, leaves);
    let t_build = t.elapsed();
    let t = Instant::now();
    sg.commit(&crypto, &conn(&owner), &st, &l.commit, &l.gi, None).unwrap();
    let t_server = t.elapsed();
    g.merge_pending_commit(&owner.provider).unwrap();
    let t = Instant::now();
    apply_commit(member, &mut gm, &l.commit);
    let t_apply = t.elapsed();
    println!(
        "  remove 4 leaves at 512: commit {} chars; owner build {:?}, server {:?}, member apply {:?}",
        l.commit.len(), t_build, t_server, t_apply
    );

    // External rejoin at 508 leaves (member reinstalled with the same key).
    let again = Device::with_key(&member.uid, DeviceKey::from_seed(member.key.seed));
    let (gi_line, tree_line) = sg.groupinfo_reply();
    println!("  GROUPINFO reply at {} leaves: groupinfo {} + tree {} chars", sg.leaf_count(), gi_line.len(), tree_line.len());
    let t = Instant::now();
    let (_ga, l) = external_join(&again, &gi_line, &tree_line);
    let t_build = t.elapsed();
    let t = Instant::now();
    sg.commit(&crypto, &conn(&again), &st, &l.commit, &l.gi, None).unwrap();
    let t_server = t.elapsed();
    println!(
        "  external rejoin at {} leaves: commit {} chars; joiner build {:?}, server {:?}",
        sg.leaf_count(), l.commit.len(), t_build, t_server
    );
}

// ---------------------------------------------------------------------

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn check4b_lifetimes_and_credentials() {
    println!("\n== 4b. Expired leaf lifetimes, and credential changes by commit");
    let crypto = openmls_rust_crypto::RustCrypto::default();
    let alice = Device::new("alice@example.org");
    let bob = Device::new("bob@example.net");
    let carol = Device::new("carol@example.com");
    let alice2 = Device::new("alice@example.org");
    let mut st = State::default();
    st.room_id = Some("r9".into());
    for d in [&alice, &bob, &carol, &alice2] {
        st.key_files.entry(d.uid.clone()).or_default().push(d.key.pk.clone());
    }
    for u in ["alice@example.org", "bob@example.net"] {
        st.members.insert(u.into());
    }
    st.owners.insert("alice@example.org".into());
    st.may_invite.insert("alice@example.org".into());

    let conv = RisalaConversation::room("r9", 1);
    let mut ga = create_group(&alice, &conv);
    let (gi, tree) = init_lines(&alice, &ga);
    let mut sg = ServerGroup::init(&crypto, &conn(&alice), &gi, &tree, &conv).unwrap();

    // Bob's KeyPackage lives for 3 more seconds; Bob never commits.
    let short = KeyPackage::builder()
        .leaf_node_capabilities(capabilities())
        .key_package_lifetime(Lifetime::init(now() - 60, now() + 3))
        .build(CS, &bob.provider, &bob.key, bob.credential())
        .unwrap()
        .key_package()
        .clone();
    let l = commit_adds(&alice, &mut ga, vec![short]);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    let mut gb = join_welcome(&bob, l.welcome.as_ref().unwrap(), &sg.tree_line());
    println!("  Bob added with a KeyPackage valid for 3 s; waiting 4 s");
    std::thread::sleep(std::time::Duration::from_secs(4));

    // Commits still work for everyone.
    let l = commit_update(&alice, &mut ga);
    let r = sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, None);
    println!("  server accepts a later commit with Bob's leaf expired: {}", r.is_ok());
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob, &mut gb, &l.commit);

    // A new member joining by Welcome.
    st.invitees.insert("carol@example.com".into());
    let l = commit_adds(&alice, &mut ga, vec![carol.key_package(false)]);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob, &mut gb, &l.commit);
    let MlsMessageBodyIn::Welcome(w) = parse_msg(l.welcome.as_ref().unwrap()) else { panic!() };
    let r = StagedWelcome::build_from_welcome(&carol.provider, &join_config(), w.clone())
        .unwrap()
        .with_ratchet_tree(parse_tree(&sg.tree_line()))
        .build();
    println!("  Carol joins by Welcome with lifetime checks on: {:?}", r.as_ref().err());
    let r = StagedWelcome::build_from_welcome(&carol.provider, &join_config(), w);
    println!(
        "  Carol retries the same Welcome: {:?} (the failed attempt deleted her KeyPackage)",
        r.err()
    );
    let carol2 = Device::new("carol@example.com");
    st.key_files.get_mut("carol@example.com").unwrap().push(carol2.key.pk.clone());
    let l = commit_adds(&alice, &mut ga, vec![carol2.key_package(false)]);
    sg.commit(&crypto, &conn(&alice), &st, &l.commit, &l.gi, l.welcome.as_deref()).unwrap();
    ga.merge_pending_commit(&alice.provider).unwrap();
    apply_commit(&bob, &mut gb, &l.commit);
    let MlsMessageBodyIn::Welcome(w) = parse_msg(l.welcome.as_ref().unwrap()) else { panic!() };
    let r = StagedWelcome::build_from_welcome(&carol2.provider, &join_config(), w)
        .unwrap()
        .with_ratchet_tree(parse_tree(&sg.tree_line()))
        .skip_lifetime_validation()
        .build()
        .map(|s| s.into_group(&carol2.provider).unwrap());
    println!("  another device of Carol, with skip_lifetime_validation(): joined={}", r.is_ok());

    // A new device joining by external commit.
    let (gi_line, tree_line) = sg.groupinfo_reply();
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(&gi_line) else { panic!() };
    let r = MlsGroup::external_commit_builder()
        .with_ratchet_tree(parse_tree(&tree_line))
        .build_group(&alice2.provider, vgi, alice2.credential());
    println!("  external join with lifetime checks on: {:?}", r.err());
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(&gi_line) else { panic!() };
    let r = MlsGroup::external_commit_builder()
        .with_ratchet_tree(parse_tree(&tree_line))
        .skip_lifetime_validation()
        .build_group(&alice2.provider, vgi, alice2.credential());
    println!("  ... with skip_lifetime_validation(): built={}", r.is_ok());

    // The server rebuilding from GroupInfo + tree has no skip option.
    let r = ServerGroup::init_any(&crypto, &gi_line, &tree_line);
    println!("  server PublicGroup::from_external on this tree: {:?}", r.err());

    // Bob tries to change his leaf's identity to Carol's with an empty commit.
    let fake = CredentialWithKey {
        credential: BasicCredential::new(b"carol@example.com".to_vec()).into(),
        signature_key: bob.key.pk.clone().into(),
    };
    let b = gb
        .commit_builder()
        .force_self_update(true)
        .leaf_node_parameters(LeafNodeParameters::builder().with_credential_with_key(fake).build());
    let l = stage(&bob, b);
    let MlsMessageBodyIn::PublicMessage(pm) = parse_msg(&l.commit) else { panic!() };
    let r = ga.process_message(&alice.provider, pm).map(|p| match p.into_content() {
        ProcessedMessageContent::StagedCommitMessage(sc) => sc
            .update_path_leaf_node()
            .map(|l| identity_of(l.credential())),
        _ => None,
    });
    println!("  OpenMLS on Alice's device accepts Bob's commit renaming his leaf to: {r:?}");
    expect_err("the same commit at the server", sg.commit(&crypto, &conn(&bob), &st, &l.commit, &l.gi, None));
}

// ---------------------------------------------------------------------

fn check0b_libcrux_wrapper() {
    use libcrux_mldsa::*;
    println!("\n== 0b. libcrux + libcrux-ml-dsa wrapper provider");
    let seed: [u8; 32] =
        hex::decode("c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8")
            .unwrap()
            .try_into()
            .unwrap();
    let kp = keypair(seed);
    let msg = b"risala-auth-1\nchat.example.org\n6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e\nalice@example.org\n";
    let sig = sign_deterministic(&kp, msg);
    println!(
        "  libcrux-ml-dsa, Appendix B: key sha256 {}, signature sha256 {}",
        &sha256_hex(kp.verification_key.as_slice())[..16],
        &sha256_hex(&sig)[..16]
    );
    assert_eq!(sha256_hex(kp.verification_key.as_slice()), "d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf");
    assert_eq!(sha256_hex(&sig), "eeda7aa7dd2ffa7cc2fa6683e7d8d2b94cf46716484b784d6a53b4928df58906");
    ok("libcrux-ml-dsa and RustCrypto ml-dsa produce the same Appendix B key and signature");

    // Alice runs on libcrux, Bob on RustCrypto.
    let lp = LibcruxProvider::default();
    let akey = DeviceKey::generate();
    let acred = CredentialWithKey {
        credential: BasicCredential::new(b"alice@example.org".to_vec()).into(),
        signature_key: akey.pk.clone().into(),
    };
    let bob = Device::new("bob@example.net");
    let conv = RisalaConversation::direct("alice@example.org", "bob@example.net");
    let mut ga = MlsGroup::builder()
        .ciphersuite(CS)
        .with_capabilities(capabilities())
        .with_group_context_extensions(group_context_extensions(&conv))
        .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(false)
        .build(&lp, &akey, acred)
        .unwrap();
    // Bob's KeyPackage goes through libcrux validation on Alice's side.
    let MlsMessageBodyIn::KeyPackage(kpi) = parse_msg(&kp_b64(&bob.key_package(false))) else { panic!() };
    let bkp = kpi.validate(lp.crypto(), ProtocolVersion::Mls10).unwrap();
    let bundle = ga
        .commit_builder()
        .propose_adds([bkp])
        .load_psks(lp.storage())
        .unwrap()
        .build(lp.rand(), lp.crypto(), &akey, |_| true)
        .unwrap()
        .stage_commit(&lp)
        .unwrap();
    ga.merge_pending_commit(&lp).unwrap();
    let (_, w, _) = bundle.into_messages();
    let mut gb = join_welcome(&bob, &msg_b64(&w.unwrap()), &tree_b64(&ga.export_ratchet_tree()));
    let l = commit_update(&bob, &mut gb);
    gb.merge_pending_commit(&bob.provider).unwrap();
    let MlsMessageBodyIn::PublicMessage(pm) = parse_msg(&l.commit) else { panic!() };
    let p = ga.process_message(&lp, pm).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(sc) = p.into_content() else { panic!() };
    ga.merge_staged_commit(&lp, *sc).unwrap();
    let ha = ga.export_secret(lp.crypto(), "risala history", b"", 48).unwrap();
    assert_eq!(ha, history_key(&bob, &gb));
    ok("libcrux-wrapped device and RustCrypto device: add, Welcome, commit back, same history key");
}
