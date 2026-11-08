//! Unit tests of leaf confirmation's pieces. The behaviour between real
//! clients is tested in `client/confirm/tests.rs`.

use super::*;
use crate::store::Store;

fn host() -> risala_proto::names::ServerAddr {
    "chat.test".parse().unwrap()
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn leaf(uid_: &str) -> LeafRow {
    LeafRow {
        leaf: 1,
        uid: uid(uid_),
        device_id: Some([1; 48]),
        signature_key: vec![1],
        display_name: None,
        updated: None,
        self_removed: false,
        resync_seq: None,
    }
}

fn status(store: &Store, identity: &RisalaIdentity) -> DeviceStatus {
    store
        .write(|tx| Ok(DevicesTable.device(tx, identity)))
        .unwrap()
        .0
}

/// The devices table gives a device's keys once its record is accepted,
/// and says when it is not current or not known (4.4, 4.5).
#[test]
fn the_devices_table_names_current_devices() {
    let store = Store::open_in_memory().unwrap();
    let key = SigningKey::from_seed([7; 32]);
    let device = key.device_id();
    let alice = RisalaIdentity::device(uid("alice@example.org"), device);
    assert_eq!(status(&store, &alice), DeviceStatus::Unknown);

    let attestation = AttestationKey::from_seed(zeroize::Zeroizing::new([9; 32]));
    store
        .write(|tx| {
            tx.conn().execute(
                "INSERT INTO devices (uid, device_id, device_key, attestation_key, label, added, state)
                 VALUES ('alice@example.org', ?1, ?2, ?3, 'phone', 0, 'current')",
                rusqlite::params![
                    &device.as_bytes()[..],
                    &key.public_key()[..],
                    attestation.public_key()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        status(&store, &alice),
        DeviceStatus::Current {
            device_key: key.public_key().to_vec(),
            attestation_key: attestation.public_key().to_vec(),
        }
    );

    // A device id that is not the hash of the key listed for it.
    let wrong = RisalaIdentity::device(
        uid("alice@example.org"),
        risala_mls::identity::DeviceId::from_bytes([0; 48]),
    );
    store
        .write(|tx| {
            tx.conn().execute(
                "INSERT INTO devices (uid, device_id, device_key, attestation_key, label, added, state)
                 VALUES ('alice@example.org', ?1, ?2, ?3, 'other', 0, 'current')",
                rusqlite::params![
                    &[0u8; 48][..],
                    &key.public_key()[..],
                    attestation.public_key()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(status(&store, &wrong), DeviceStatus::NotCurrent);

    // Its record still pending (4.5): not known yet.
    let set = |state: &str| {
        store
            .write(|tx| {
                tx.conn()
                    .execute("UPDATE devices SET state = ?1", [state])?;
                Ok(())
            })
            .unwrap();
    };
    set("pending");
    assert_eq!(status(&store, &alice), DeviceStatus::Unknown);
    // Removed by a record.
    set("removed");
    assert_eq!(status(&store, &alice), DeviceStatus::NotCurrent);
    // A guest has no device.
    assert_eq!(
        status(&store, &RisalaIdentity::guest(uid("~sam"))),
        DeviceStatus::NotCurrent
    );
}

/// Who removes an impostor (12.7): any member, except that in a room
/// only owners remove an owner's leaf and only owners and moderators a
/// moderator's; nobody for a check in a public room; and a device always
/// removes a leaf of its own identity.
#[test]
fn who_may_remove_an_impostor() {
    let owner = uid("owner@example.org");
    let moderator = uid("mod@example.org");
    let member = uid("member@example.org");
    let mut room = RisalaConversation::private_room(host(), [1; 16], "room", &owner);
    room.mods.push(moderator.clone());
    let owner_leaf = leaf("owner@example.org");
    let mod_leaf = leaf("mod@example.org");
    let member_leaf = leaf("member@example.org");

    assert!(may_remove(&room, &member, &leaf("other@example.org")));
    assert!(!may_remove(&room, &member, &owner_leaf));
    assert!(!may_remove(&room, &member, &mod_leaf));
    assert!(may_remove(&room, &moderator, &mod_leaf));
    assert!(!may_remove(&room, &moderator, &owner_leaf));
    assert!(may_remove(&room, &owner, &owner_leaf));
    assert!(may_remove(&room, &owner, &member_leaf));
    // Its own identity's leaf.
    assert!(may_remove(&room, &member, &member_leaf));

    let direct = RisalaConversation::direct(host(), [1; 16], &owner, &member);
    assert!(may_remove(&direct, &member, &owner_leaf));

    let public =
        RisalaConversation::public_room(host(), [1; 16], &"#lobby".parse().unwrap(), &owner);
    assert!(!may_remove(&public, &owner, &member_leaf));
}

/// A leaf confirmed by an ATTEST is confirmed until its grace hour ends;
/// one confirmed pairwise has no end (12.10).
#[test]
fn leaf_states_lapse_at_their_end() {
    let row = LeafConfirmationRow {
        leaf: 1,
        signature_key: vec![1],
        state: LeafConfirmation::Confirmed,
        until: Some(1_000),
        since_seq: 0,
        repair_at: None,
    };
    assert!(row.confirmed_at(999));
    assert!(!row.confirmed_at(1_000));
    let pairwise = LeafConfirmationRow {
        until: None,
        ..row.clone()
    };
    assert!(pairwise.confirmed_at(u64::MAX));
    let impostor = LeafConfirmationRow {
        state: LeafConfirmation::Impostor,
        ..pairwise
    };
    assert!(!impostor.confirmed_at(0));
}

/// Leaf confirmation does nothing for a conversation it has no state for,
/// and the engine without settings does nothing at all.
#[test]
fn nothing_to_do_without_state() {
    let store = Store::open_in_memory().unwrap();
    let cx = Context {
        store: store.clone(),
        account: AccountId(1),
    };
    let mut engine = ConfirmEngine::default();
    assert!(
        engine
            .handle(
                &cx,
                &Input::Tick {
                    now: Timestamp::MIN
                }
            )
            .is_empty()
    );
    let confirm = Confirm::default();
    let actions = store
        .write_with(|tx| confirm.tick(tx, AccountId(1)))
        .unwrap()
        .0;
    assert!(actions.is_empty());
}
