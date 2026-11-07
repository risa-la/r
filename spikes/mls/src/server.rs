//! The server side of 12.5: INIT and COMMIT, checked with OpenMLS
//! `PublicGroup` only (no private keys).

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, VLBytes};
use openmls::prelude::*;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;

use crate::common::*;

pub const MAX_LEAVES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Err {
    Stale(String),
    Invalid(String),
    Forbidden(String),
}

fn invalid<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> Err + '_ {
    move |e| Err::Invalid(format!("{what}: {e:?}"))
}

/// What the server knows about a conversation, outside MLS.
#[derive(Default, Clone)]
pub struct State {
    /// uid -> device keys in its key file (4.4).
    pub key_files: BTreeMap<String, Vec<Vec<u8>>>,
    /// Direct: the two participants. Room: unused.
    pub participants: Option<(String, String)>,
    pub room_id: Option<String>,
    pub members: BTreeSet<String>,
    pub invitees: BTreeSet<String>,
    /// Who may invite (6.4): owners and mods, for this spike.
    pub may_invite: BTreeSet<String>,
    pub owners: BTreeSet<String>,
}

impl State {
    fn key_listed(&self, uid: &str, key: &[u8]) -> bool {
        self.key_files
            .get(uid)
            .is_some_and(|ks| ks.iter().any(|k| k == key))
    }
    fn is_room(&self) -> bool {
        self.room_id.is_some()
    }
    /// 12.5 rule 3: who may commit at all.
    fn may_commit(&self, uid: &str) -> bool {
        match &self.participants {
            Some((a, b)) => uid == a || uid == b,
            None => self.members.contains(uid) || self.invitees.contains(uid),
        }
    }
}

/// The connection that sent the command (after AUTH, 4.5).
pub struct Conn {
    pub uid: String,
    pub device_key: Vec<u8>,
}

pub struct ServerGroup {
    pub pg: PublicGroup,
    storage: MemoryStorage,
    pub group_info: String,
}

pub struct Accepted {
    pub epoch: u64,
    pub invited: Vec<String>,
    pub history_set: Option<u8>,
}

/// Parse `<groupinfo>` and check it belongs right after `ctx`, signed by
/// leaf `signer` with key `signer_key`, with `tag` as confirmation tag.
/// GroupInfo = GroupContext || extensions<V> || MAC<V> || uint32 signer || sig<V>
fn check_group_info(
    crypto: &RustCrypto,
    gi_line: &str,
    ctx: &GroupContext,
    tag: Option<&ConfirmationTag>,
    signer: LeafNodeIndex,
    signer_key: &SignaturePublicKey,
) -> Result<(), Err> {
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(gi_line) else {
        return Err(Err::Invalid("not a GroupInfo".into()));
    };
    let bytes = vgi.tls_serialize_detached().unwrap();
    let ctx_bytes = ctx.tls_serialize_detached().unwrap();
    if !bytes.starts_with(&ctx_bytes) {
        return Err(Err::Invalid("GroupInfo context is not the new epoch's".into()));
    }
    let mut r = &bytes[ctx_bytes.len()..];
    let _ext = VLBytes::tls_deserialize(&mut r).map_err(invalid("gi ext"))?;
    let gi_tag = VLBytes::tls_deserialize(&mut r).map_err(invalid("gi tag"))?;
    let gi_signer = u32::tls_deserialize(&mut r).map_err(invalid("gi signer"))?;
    if let Some(tag) = tag {
        let want = tag.tls_serialize_detached().unwrap();
        let got = gi_tag.tls_serialize_detached().unwrap();
        if want != got {
            return Err(Err::Invalid("GroupInfo confirmation tag".into()));
        }
    }
    if gi_signer != signer.u32() {
        return Err(Err::Invalid("GroupInfo signer is not the committer".into()));
    }
    let ext = vgi.extensions();
    if ext.external_pub().is_none() {
        return Err(Err::Invalid("GroupInfo without external_pub".into()));
    }
    if ext.ratchet_tree().is_some() {
        return Err(Err::Invalid("GroupInfo with ratchet_tree".into()));
    }
    let pk = OpenMlsSignaturePublicKey::from_signature_key(
        signer_key.clone(),
        CS.signature_algorithm(),
    );
    vgi.verify(crypto, &pk)
        .map_err(|_| Err::Invalid("GroupInfo signature".into()))?;
    Ok(())
}

impl ServerGroup {
    /// INIT <conv> <groupinfo> <tree>
    pub fn init(
        crypto: &RustCrypto,
        conn: &Conn,
        gi_line: &str,
        tree_line: &str,
        expected: &RisalaConversation,
    ) -> Result<Self, Err> {
        let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(gi_line) else {
            return Err(Err::Invalid("not a GroupInfo".into()));
        };
        if vgi.ciphersuite() != CS {
            return Err(Err::Invalid("cipher suite".into()));
        }
        if vgi.epoch().as_u64() != 0 {
            return Err(Err::Invalid("INIT not at epoch 0".into()));
        }
        if vgi.group_id().as_slice().len() != 32 {
            return Err(Err::Invalid("group id is not 32 bytes".into()));
        }
        if vgi.extensions().external_pub().is_none() || vgi.extensions().ratchet_tree().is_some()
        {
            return Err(Err::Invalid("GroupInfo extensions".into()));
        }
        let storage = MemoryStorage::default();
        let (pg, _gi) = PublicGroup::from_external(
            crypto,
            &storage,
            parse_tree(tree_line),
            vgi,
            ProposalStore::new(),
        )
        .map_err(invalid("from_external"))?;
        let members: Vec<_> = pg.members().collect();
        if members.len() != 1 {
            return Err(Err::Invalid("INIT group must have one leaf".into()));
        }
        let m = &members[0];
        if m.signature_key != conn.device_key || identity_of(&m.credential) != conn.uid {
            return Err(Err::Forbidden("leaf is not this connection's device".into()));
        }
        check_conv_ext(pg.group_context().extensions(), expected)?;
        Ok(Self {
            pg,
            storage,
            group_info: gi_line.to_string(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.pg.group_context().epoch().as_u64()
    }

    pub fn leaf_count(&self) -> usize {
        self.pg.members().count()
    }

    /// COMMIT <conv> <commit> <groupinfo> [<welcome>]
    pub fn commit(
        &mut self,
        crypto: &RustCrypto,
        conn: &Conn,
        st: &State,
        commit_line: &str,
        gi_line: &str,
        welcome_line: Option<&str>,
    ) -> Result<Accepted, Err> {
        let MlsMessageBodyIn::PublicMessage(pm) = parse_msg(commit_line) else {
            return Err(Err::Invalid("commit is not a PublicMessage".into()));
        };
        // Rule 1: the current epoch.
        if pm.epoch() != self.pg.group_context().epoch() {
            return Err(Err::Stale(format!(
                "commit for epoch {}, group is at {}",
                pm.epoch().as_u64(),
                self.epoch()
            )));
        }
        if pm.content_type() != ContentType::Commit {
            return Err(Err::Invalid("not a commit".into()));
        }
        let tag = pm.confirmation_tag().cloned();
        // Rule 2: valid as far as an outsider can check.
        let processed = self
            .pg
            .process_message(crypto, pm)
            .map_err(invalid("process_message"))?;
        let sender = processed.sender().clone();
        let committer_uid = identity_of(processed.credential());
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Err::Invalid("not a commit".into()));
        };

        // Rule 3: the committer.
        let external = matches!(sender, Sender::NewMemberCommit);
        let committer_key: SignaturePublicKey = match &sender {
            Sender::Member(i) => self.pg.leaf(*i).unwrap().signature_key().clone(),
            Sender::NewMemberCommit => staged
                .update_path_leaf_node()
                .ok_or(Err::Invalid("external commit without path".into()))?
                .signature_key()
                .clone(),
            _ => return Err(Err::Forbidden("sender type".into())),
        };
        if committer_key.as_slice() != conn.device_key.as_slice() || committer_uid != conn.uid {
            return Err(Err::Forbidden("committer is not this connection's device".into()));
        }
        if !st.may_commit(&conn.uid) {
            return Err(Err::Forbidden("committer may not change the group".into()));
        }
        if let Some(leaf) = staged.update_path_leaf_node() {
            // Not in the spec yet: the path leaf must keep the committer's
            // identity and key (no credential or key change by commit).
            if leaf.signature_key().as_slice() != conn.device_key.as_slice()
                || identity_of(leaf.credential()) != conn.uid
            {
                return Err(Err::Forbidden("path leaf changes identity or key".into()));
            }
        }
        if external {
            // 12.6: an external commit by an identity with no leaf yet is
            // allowed only for a direct conversation's participant.
            let had_leaf = self
                .pg
                .members()
                .any(|m| identity_of(&m.credential) == conn.uid);
            if st.is_room() && !had_leaf {
                return Err(Err::Forbidden("external join without a leaf of the identity".into()));
            }
            if !st.key_listed(&conn.uid, &conn.device_key) {
                return Err(Err::Forbidden("joiner key not in key file".into()));
            }
        }

        // Rule 4: proposals.
        let mut adds: Vec<(String, Vec<u8>)> = vec![];
        let mut removed: Vec<LeafNodeIndex> = vec![];
        let mut history_set = None;
        let mut n_remove = 0;
        // Keys that this commit adds: their old leaves may be removed
        // (12.5 Add rule; missing from the Remove rule in draft-02).
        let re_added: Vec<Vec<u8>> = staged
            .queued_proposals()
            .filter_map(|qp| match qp.proposal() {
                Proposal::Add(a) => Some(a.key_package().leaf_node().signature_key().as_slice().to_vec()),
                _ => None,
            })
            .collect();
        for qp in staged.queued_proposals() {
            if qp.proposal_or_ref_type() != ProposalOrRefType::Proposal {
                return Err(Err::Forbidden("proposal by reference".into()));
            }
            match qp.proposal() {
                Proposal::Add(a) => {
                    let leaf = a.key_package().leaf_node();
                    let uid = identity_of(leaf.credential());
                    let key = leaf.signature_key().as_slice().to_vec();
                    if !st.key_listed(&uid, &key) {
                        return Err(Err::Forbidden(format!("add {uid}: key not in key file")));
                    }
                    let ok = match &st.participants {
                        Some((a, b)) => &uid == a || &uid == b,
                        None => {
                            st.members.contains(&uid)
                                || st.invitees.contains(&uid)
                                || st.may_invite.contains(&conn.uid)
                        }
                    };
                    if !ok {
                        return Err(Err::Forbidden(format!("add {uid}: not allowed")));
                    }
                    adds.push((uid, key));
                }
                Proposal::Remove(r) => {
                    n_remove += 1;
                    let leaf = self
                        .pg
                        .leaf(r.removed())
                        .ok_or(Err::Invalid("remove of blank leaf".into()))?;
                    let uid = identity_of(leaf.credential());
                    let key = leaf.signature_key().as_slice();
                    if external {
                        if key != conn.device_key.as_slice() {
                            return Err(Err::Forbidden(
                                "external commit removes another device's leaf".into(),
                            ));
                        }
                    } else {
                        let ok = uid == conn.uid
                            || !st.key_listed(&uid, key)
                            || re_added.iter().any(|k| k == key)
                            || (st.is_room()
                                && !st.members.contains(&uid)
                                && !st.invitees.contains(&uid));
                        if !ok {
                            return Err(Err::Forbidden(format!("remove {uid}: no reason")));
                        }
                    }
                    removed.push(r.removed());
                }
                Proposal::GroupContextExtensions(g) => {
                    if !st.is_room() || !st.owners.contains(&conn.uid) || external {
                        return Err(Err::Forbidden("GroupContextExtensions".into()));
                    }
                    let old =
                        RisalaConversation::from_extensions(self.pg.group_context().extensions())
                            .map_err(Err::Invalid)?;
                    let new = RisalaConversation::from_extensions(g.extensions())
                        .map_err(Err::Invalid)?;
                    if new.kind != old.kind || new.name != old.name {
                        return Err(Err::Forbidden("GCE changes more than history".into()));
                    }
                    // The rest of the extension list must stay the same.
                    let want = group_context_extensions(&new);
                    if g.extensions() != &want {
                        return Err(Err::Forbidden("GCE changes other extensions".into()));
                    }
                    history_set = Some(new.history);
                }
                Proposal::ExternalInit(_) if external => {}
                other => {
                    return Err(Err::Forbidden(format!("proposal {:?}", other.proposal_type())));
                }
            }
        }
        if external && n_remove > 1 {
            return Err(Err::Forbidden("external commit with more than one Remove".into()));
        }
        // An Add of a key that already has a leaf must remove that leaf.
        for (_, key) in &adds {
            if let Some(m) = self.pg.members().find(|m| &m.signature_key == key)
                && !removed.contains(&m.index)
            {
                return Err(Err::Forbidden("add of a key that has a leaf".into()));
            }
        }
        // Rule 5: size.
        let after = self.leaf_count() + adds.len() + usize::from(external) - removed.len();
        if after > MAX_LEAVES {
            return Err(Err::Forbidden(format!("group would have {after} leaves")));
        }
        // Welcome present exactly when the commit adds devices.
        if adds.is_empty() != welcome_line.is_none() {
            return Err(Err::Invalid("welcome presence".into()));
        }
        // GroupInfo of the new epoch.
        let signer = if external {
            self.pg.ext_commit_sender_index(&staged).unwrap()
        } else {
            match sender {
                Sender::Member(i) => i,
                _ => unreachable!(),
            }
        };
        check_group_info(
            crypto,
            gi_line,
            staged.group_context(),
            tag.as_ref(),
            signer,
            &committer_key,
        )?;
        // The conversation extension: only `history` may change.
        let new_conv = RisalaConversation::from_extensions(staged.group_context().extensions())
            .map_err(Err::Invalid)?;
        let old_conv = RisalaConversation::from_extensions(self.pg.group_context().extensions())
            .map_err(Err::Invalid)?;
        if (new_conv.kind, &new_conv.name) != (old_conv.kind, &old_conv.name) {
            return Err(Err::Forbidden("conversation extension changed".into()));
        }

        let invited: Vec<String> = if st.is_room() {
            adds.iter()
                .map(|(u, _)| u.clone())
                .filter(|u| !st.members.contains(u) && !st.invitees.contains(u))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        } else {
            vec![]
        };

        self.pg
            .merge_commit(&self.storage, *staged)
            .map_err(invalid("merge"))?;
        self.group_info = gi_line.to_string();
        Ok(Accepted {
            epoch: self.epoch(),
            invited,
            history_set,
        })
    }

    /// GROUPINFO: the stored GroupInfo and the current tree.
    pub fn groupinfo_reply(&self) -> (String, String) {
        (
            self.group_info.clone(),
            tree_b64(&self.pg.export_ratchet_tree()),
        )
    }

    pub fn tree_line(&self) -> String {
        tree_b64(&self.pg.export_ratchet_tree())
    }
}

pub fn check_conv_ext(ext: &Extensions<GroupContext>, expected: &RisalaConversation) -> Result<(), Err> {
    let got = RisalaConversation::from_extensions(ext).map_err(Err::Invalid)?;
    if &got != expected {
        return Err(Err::Invalid(format!("conversation extension {got:?}")));
    }
    let req = ext
        .required_capabilities()
        .ok_or(Err::Invalid("no required_capabilities".into()))?;
    if !req.extension_types().contains(&ExtensionType::Unknown(EXT_CONV)) {
        return Err(Err::Invalid("0xF2A1 not required".into()));
    }
    Ok(())
}

/// KEYPKG ADD (12.4). Returns whether it is a last-resort KeyPackage.
pub fn keypkg_add(crypto: &RustCrypto, conn: &Conn, line: &str) -> Result<bool, Err> {
    let MlsMessageBodyIn::KeyPackage(kpi) = parse_msg(line) else {
        return Err(Err::Invalid("not a KeyPackage".into()));
    };
    // Signatures, lifetime, init key != encryption key, extensions listed
    // in capabilities: all inside validate().
    let kp = kpi
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(invalid("KeyPackage"))?;
    if kp.ciphersuite() != CS {
        return Err(Err::Invalid("cipher suite".into()));
    }
    let leaf = kp.leaf_node();
    if leaf.signature_key().as_slice() != conn.device_key.as_slice()
        || identity_of(leaf.credential()) != conn.uid
    {
        return Err(Err::Invalid("credential or key is not this connection's".into()));
    }
    if !leaf
        .capabilities()
        .extensions()
        .contains(&ExtensionType::Unknown(EXT_CONV))
    {
        return Err(Err::Invalid("leaf does not support 0xF2A1".into()));
    }
    Ok(kp.last_resort())
}

impl ServerGroup {
    /// Rebuild from a stored GroupInfo and tree, without INIT's checks
    /// (used to measure the cost).
    pub fn init_any(crypto: &RustCrypto, gi_line: &str, tree_line: &str) -> Result<Self, Err> {
        let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(gi_line) else {
            return Err(Err::Invalid("not a GroupInfo".into()));
        };
        let storage = MemoryStorage::default();
        let (pg, _) = PublicGroup::from_external(
            crypto,
            &storage,
            parse_tree(tree_line),
            vgi,
            ProposalStore::new(),
        )
        .map_err(invalid("from_external"))?;
        Ok(Self {
            pg,
            storage,
            group_info: gi_line.to_string(),
        })
    }
}
