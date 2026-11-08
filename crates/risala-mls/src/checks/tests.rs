//! The group checks and key checks over hand-made views (12.7), for rules
//! that are awkward to reach with real groups.

use super::*;

const T: u64 = 1_800_000_000_000;
const MIN: u64 = 60 * 1000;
const HOUR: u64 = 60 * MIN;

struct NoFacts;

impl KeyFacts for NoFacts {
    fn current_device_key(&self, _: &Uid, _: &DeviceId) -> Fact<Option<Vec<u8>>> {
        Fact::Known(None)
    }

    fn device_removed(&self, _: &Uid, _: &DeviceId) -> Fact<bool> {
        Fact::Known(false)
    }

    fn identity_retired(&self, _: &Uid) -> Fact<bool> {
        Fact::Known(false)
    }
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn leaf(index: u32, who: &str, updated: u64) -> LeafView {
    leaf_of_device(index, who, index as u8, updated)
}

fn leaf_of_device(index: u32, who: &str, device: u8, updated: u64) -> LeafView {
    let uid = uid(who);
    let identity = if uid.is_guest() {
        RisalaIdentity::guest(uid)
    } else {
        RisalaIdentity::device(uid, DeviceId([device; 48]))
    };
    LeafView {
        index: LeafNodeIndex::new(index),
        identity: Some(identity),
        profile: Some(RisalaProfile::new("", updated).unwrap()),
        signature_key: vec![index as u8; 4],
        from_key_package: false,
        lifetime_end: None,
        encryption_key_ok: true,
    }
}

fn room(kind: ConversationKind) -> RisalaConversation {
    let owner = uid("o@x.org");
    let mut conv = match kind {
        ConversationKind::PublicRoom => {
            RisalaConversation::public_room("h.org", [0; 16], &"#r".parse().unwrap(), &owner)
        }
        _ => RisalaConversation::private_room("h.org", [0; 16], "R", &owner),
    };
    conv.mods.push(uid("m@x.org"));
    conv
}

/// Owner o (leaf 0), moderator m (1), member p (2 and 3), all updated at
/// `T`, in epoch 20.
fn group(conv: &RisalaConversation) -> GroupView {
    GroupView {
        epoch: 20,
        conversation: Ok(conv.clone()),
        leaves: vec![
            leaf(0, "o@x.org", T),
            leaf(1, "m@x.org", T),
            leaf(2, "p@x.org", T),
            leaf(3, "p@x.org", T),
        ],
    }
}

/// A commit by leaf `by` that refreshes its leaf at `T`, with streak 1.
fn commit(group: &GroupView, by: u32, proposals: Vec<ProposalView>) -> CommitView {
    let mut path = group.leaf(LeafNodeIndex::new(by)).unwrap().clone();
    path.profile = Some(RisalaProfile::new("", T).unwrap().with_streak(1));
    path.from_key_package = false;
    CommitView {
        committer: Committer::Member(LeafNodeIndex::new(by)),
        proposals,
        path_leaf: Some(path),
        new_conversation: group.conversation.clone(),
        pending_self_removes: Vec::new(),
    }
}

fn at(t: u64) -> CommitPost {
    CommitPost {
        t,
        next: Some([1; 48]),
    }
}

/// A history that has seen everything.
fn full() -> History {
    History::created(0)
}

fn check(group: &GroupView, commit: &CommitView) -> Result<Verdict, CommitError> {
    check_commit(group, commit, &full(), &at(T))
}

fn remove(indices: &[u32]) -> Vec<ProposalView> {
    indices
        .iter()
        .map(|i| ProposalView::Remove(LeafNodeIndex::new(*i)))
        .collect()
}

#[test]
fn paths_and_proposal_kinds() {
    let g = group(&room(ConversationKind::PrivateRoom));
    assert_eq!(check(&g, &commit(&g, 2, vec![])), Ok(Verdict::default()));
    let mut no_path = commit(&g, 2, vec![]);
    no_path.path_leaf = None;
    assert_eq!(check(&g, &no_path), Err(CommitError::NoPath));
    // `next` is required (12.6).
    assert_eq!(
        check_commit(
            &g,
            &commit(&g, 2, vec![]),
            &full(),
            &CommitPost { t: T, next: None }
        ),
        Err(CommitError::NextToken)
    );
    let odd = commit(&g, 2, vec![ProposalView::NotAllowed("x")]);
    assert_eq!(check(&g, &odd), Err(CommitError::Proposal("x")));
    let init = commit(&g, 2, vec![ProposalView::ExternalInit]);
    assert!(matches!(check(&g, &init), Err(CommitError::Proposal(_))));
    // The extension changes only through a proposal.
    let mut sneaky = commit(&g, 0, vec![]);
    sneaky.new_conversation.as_mut().unwrap().topic = "t".into();
    assert!(matches!(check(&g, &sneaky), Err(CommitError::Extension(_))));
    let mut topic = sneaky.clone();
    topic.proposals.push(ProposalView::GroupContextExtensions);
    let verdict = check(&g, &topic).unwrap();
    assert!(verdict.authority);
    // External commits only in public rooms.
    let mut external = commit(&g, 2, vec![ProposalView::ExternalInit]);
    external.committer = Committer::External;
    assert_eq!(check(&g, &external), Err(CommitError::External));
}

#[test]
fn leaves_keep_their_credential_and_key() {
    let conv = room(ConversationKind::PrivateRoom);
    let g = group(&conv);
    let mut other = commit(&g, 2, vec![]);
    other.path_leaf.as_mut().unwrap().identity =
        Some(RisalaIdentity::device(uid("p@x.org"), DeviceId([9; 48])));
    assert_eq!(check(&g, &other), Err(CommitError::Leaf));
    let mut no_profile = commit(&g, 2, vec![]);
    no_profile.path_leaf.as_mut().unwrap().profile = None;
    assert_eq!(check(&g, &no_profile), Err(CommitError::Leaf));
    let mut bad_key = commit(&g, 2, vec![]);
    bad_key.path_leaf.as_mut().unwrap().encryption_key_ok = false;
    assert_eq!(check(&g, &bad_key), Err(CommitError::Leaf));

    // A new signature key: not in a pairwise group, once the leaf has
    // committed; yes while it holds its KeyPackage's leaf (12.3).
    let mut rotate = commit(&g, 2, vec![]);
    rotate.path_leaf.as_mut().unwrap().signature_key = vec![42; 4];
    assert_eq!(check(&g, &rotate), Err(CommitError::Leaf));
    let mut fresh = g.clone();
    fresh.leaves[2].from_key_package = true;
    assert_eq!(check(&fresh, &rotate), Ok(Verdict::default()));

    // In an epochal group, once per period by the profiles' times.
    let mut epochal = conv.clone();
    epochal.confirm = ConfirmMode::Epochal;
    let mut g = group(&epochal);
    let day = T / PERIOD_MS * PERIOD_MS;
    for leaf in &mut g.leaves {
        leaf.profile = Some(RisalaProfile::new("", day).unwrap());
    }
    let rotate_at = |updated| {
        let mut c = commit(&g, 2, vec![]);
        let path = c.path_leaf.as_mut().unwrap();
        path.signature_key = vec![42; 4];
        path.profile = Some(RisalaProfile::new("", updated).unwrap().with_streak(1));
        check_commit(&g, &c, &full(), &at(updated))
    };
    assert_eq!(rotate_at(day + PERIOD_MS - 1), Err(CommitError::Leaf));
    assert_eq!(rotate_at(day + PERIOD_MS), Ok(Verdict::default()));
}

/// `updated` (12.3): never below the leaf's previous one, and within 10
/// minutes of the post's `t`.
#[test]
fn updated_bounds() {
    let g = group(&room(ConversationKind::PrivateRoom));
    let c = commit(&g, 2, vec![]);
    for (t, ok) in [
        (T, true),
        (T + 10 * MIN, true),
        (T - 10 * MIN, true),
        (T + 10 * MIN + 1, false),
        (T - 10 * MIN - 1, false),
    ] {
        assert_eq!(check_commit(&g, &c, &full(), &at(t)).is_ok(), ok, "{t}");
    }
    let mut back = c.clone();
    back.path_leaf.as_mut().unwrap().profile =
        Some(RisalaProfile::new("", T - 1).unwrap().with_streak(1));
    assert_eq!(
        check_commit(&g, &back, &full(), &at(T)),
        Err(CommitError::Updated)
    );
}

/// Streaks (12.3, 12.7).
#[test]
fn streaks() {
    let g = group(&room(ConversationKind::PrivateRoom));
    let with_streak = |streak: u8, updated: u64, proposals: Vec<ProposalView>| {
        let mut c = commit(&g, 2, proposals);
        c.path_leaf.as_mut().unwrap().profile =
            Some(RisalaProfile::new("", updated).unwrap().with_streak(streak));
        c
    };
    // Someone else started the epoch: 1.
    let mut history = full();
    history.started_by = Some(0);
    assert!(check_commit(&g, &with_streak(1, T, vec![]), &history, &at(T)).is_ok());
    assert_eq!(
        check_commit(&g, &with_streak(2, T, vec![]), &history, &at(T)),
        Err(CommitError::Streak)
    );
    // Leaf 2 started it, with streak 3: the next is 4, which needs 10
    // minutes since its previous `updated`, or only removals of its own
    // identity's leaves.
    history.started_by = Some(2);
    let mut g3 = g.clone();
    g3.leaves[2].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(3));
    let check3 = |c: &CommitView, t| check_commit(&g3, c, &history, &at(t));
    assert_eq!(
        check3(&with_streak(1, T, vec![]), T),
        Err(CommitError::Streak)
    );
    assert_eq!(
        check3(&with_streak(4, T, vec![]), T),
        Err(CommitError::Streak)
    );
    assert!(check3(&with_streak(4, T + 10 * MIN, vec![]), T + 10 * MIN).is_ok());
    assert!(check3(&with_streak(4, T, remove(&[3])), T).is_ok());
    assert_eq!(
        check3(&with_streak(4, T, remove(&[0, 3])), T),
        Err(CommitError::Streak)
    );
    // Capped at 255.
    let mut g255 = g.clone();
    g255.leaves[2].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(255));
    assert!(
        check_commit(
            &g255,
            &with_streak(255, T + 10 * MIN, vec![]),
            &history,
            &at(T + 10 * MIN)
        )
        .is_ok()
    );
}

#[test]
fn removes_and_kicks() {
    let conv = room(ConversationKind::PublicRoom);
    let g = group(&conv);
    // Your own leaves, a SelfRemove's.
    assert!(check(&g, &commit(&g, 2, remove(&[3]))).is_ok());
    let verdict = check(&g, &commit(&g, 0, remove(&[1]))).unwrap();
    assert!(verdict.authority, "an owner kicks a moderator");
    let mut pending = commit(&g, 2, remove(&[0]));
    assert_eq!(check(&g, &pending), Err(CommitError::Remove));
    pending.pending_self_removes.push(LeafNodeIndex::new(0));
    assert!(check(&g, &pending).is_ok());
    // A kick removes every leaf of the identity.
    assert!(check(&g, &commit(&g, 1, remove(&[2, 3]))).is_ok());
    assert_eq!(
        check(&g, &commit(&g, 1, remove(&[2]))),
        Err(CommitError::Remove)
    );
    // Moderators kick plain members only; nobody kicks the last owner.
    assert_eq!(
        check(&g, &commit(&g, 1, remove(&[0]))),
        Err(CommitError::Remove)
    );
    let mut two_owners = conv.clone();
    two_owners.owners.push(uid("m@x.org"));
    two_owners.mods.clear();
    let g2 = group(&two_owners);
    assert!(check(&g2, &commit(&g2, 1, remove(&[0]))).is_ok());
    // A leaf removed twice.
    let twice = commit(
        &g,
        2,
        vec![
            ProposalView::Remove(LeafNodeIndex::new(3)),
            ProposalView::SelfRemove(LeafNodeIndex::new(3)),
        ],
    );
    assert!(matches!(check(&g, &twice), Err(CommitError::Proposal(_))));
    // Outside public rooms, any other removal is for a key check (12.7).
    let private = group(&room(ConversationKind::PrivateRoom));
    let verdict = check(&private, &commit(&private, 2, remove(&[0]))).unwrap();
    assert_eq!(verdict.key_check_removals, vec![LeafNodeIndex::new(0)]);
    // In a direct conversation, nobody is kicked.
    let direct = RisalaConversation::direct("h.org", [0; 16], &uid("o@x.org"), &uid("p@x.org"));
    let mut gd = group(&direct);
    gd.leaves.remove(1);
    let verdict = check(&gd, &commit(&gd, 0, remove(&[2, 3]))).unwrap();
    assert_eq!(verdict.key_check_removals.len(), 2);
    assert!(!verdict.authority);
}

/// Stale leaves (12.7): by the upper median, at most max(1, n/10).
#[test]
fn stale_leaves() {
    let conv = room(ConversationKind::PublicRoom);
    let day = 24 * HOUR;
    let mut g = group(&conv);
    g.leaves[0].profile = Some(RisalaProfile::new("", T - 36 * day).unwrap());
    g.leaves[1].profile = Some(RisalaProfile::new("", T - 36 * day).unwrap());
    // Sorted: T-36d, T-36d, T, T; position 2 is T.
    assert_eq!(g.median_updated(), Some(T));
    assert_eq!(g.stale_leaves().len(), 2);
    assert_eq!(g.max_stale_removals(), 1);
    // One of them, by a plain member, is fine; two are not.
    assert!(check(&g, &commit(&g, 2, remove(&[0]))).is_ok());
    assert_eq!(
        check(&g, &commit(&g, 2, remove(&[0, 1]))),
        Err(CommitError::Remove)
    );
    // In a two-leaf group the upper median lets either side replace the
    // other.
    let two = GroupView {
        epoch: 1,
        conversation: Ok(conv.clone()),
        leaves: vec![leaf(0, "o@x.org", T - 36 * day), leaf(1, "m@x.org", T)],
    };
    assert_eq!(two.stale_leaves(), vec![LeafNodeIndex::new(0)]);
    // A leaf that never committed counts its KeyPackage's lifetime end.
    let mut fresh = g.clone();
    fresh.leaves[0].from_key_package = true;
    fresh.leaves[0].lifetime_end = Some(T);
    assert_eq!(fresh.stale_leaves(), vec![LeafNodeIndex::new(1)]);
}

/// Update proposals (12.6, 12.7): only in epochal groups, with streak 0,
/// `updated` checked against the Update's own post.
#[test]
fn updates() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves[3].profile = Some(RisalaProfile::new("", T - 2 * HOUR).unwrap());
    let update = |updated: u64, streak: u8| {
        let mut l = leaf(3, "p@x.org", updated);
        l.profile = Some(RisalaProfile::new("", updated).unwrap().with_streak(streak));
        ProposalView::Update {
            sender: LeafNodeIndex::new(3),
            leaf: Box::new(l),
            reference: vec![7; 48],
        }
    };
    let mut history = full();
    history.note_update(&[7; 48], T - 30 * MIN);
    let c = commit(&g, 2, vec![update(T - 30 * MIN, 0)]);
    assert!(check_commit(&g, &c, &history, &at(T)).is_ok());
    // Its `updated` is judged by its own post's `t`, not the commit's.
    let c = commit(&g, 2, vec![update(T, 0)]);
    assert_eq!(
        check_commit(&g, &c, &history, &at(T)),
        Err(CommitError::Updated)
    );
    let c = commit(&g, 2, vec![update(T - 30 * MIN, 1)]);
    assert_eq!(
        check_commit(&g, &c, &history, &at(T)),
        Err(CommitError::Streak)
    );
    // Not seen: the rest still holds, and the time goes unchecked.
    let c = commit(&g, 2, vec![update(T, 0)]);
    assert_eq!(
        check_commit(&g, &c, &full(), &at(T)).unwrap().unchecked,
        vec!["the time of an Update proposal"]
    );
    // Not in a pairwise group.
    let pairwise = group(&room(ConversationKind::PrivateRoom));
    let c = commit(&pairwise, 2, vec![update(T, 0)]);
    assert!(matches!(
        check_commit(&pairwise, &c, &history, &at(T)),
        Err(CommitError::Proposal(_))
    ));
    // Nor by a guest in a public room.
    let mut with_guest = g.clone();
    with_guest.leaves[3] = leaf(3, "~sam", T);
    let mut guest_update = leaf(3, "~sam", T);
    guest_update.profile = None;
    let c = commit(
        &with_guest,
        2,
        vec![ProposalView::Update {
            sender: LeafNodeIndex::new(3),
            leaf: Box::new(guest_update),
            reference: vec![7; 48],
        }],
    );
    assert_eq!(
        check_commit(&with_guest, &c, &history, &at(T)),
        Err(CommitError::Guest)
    );
}

#[test]
fn guests_and_bans() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves.push(leaf(4, "~sam", T));
    // Anyone may remove a guest leaf (6.1).
    assert!(check(&g, &commit(&g, 2, remove(&[4]))).is_ok());
    // A guest's leaf may not commit in a public room (12.6).
    let mut by_guest = commit(&g, 4, vec![]);
    by_guest.path_leaf.as_mut().unwrap().profile = None;
    assert_eq!(check(&g, &by_guest), Err(CommitError::Guest));
    // Guests none must remove the guests in the same commit.
    let mut none = commit(&g, 0, vec![ProposalView::GroupContextExtensions]);
    none.new_conversation.as_mut().unwrap().guests = GuestMode::None;
    assert_eq!(check(&g, &none), Err(CommitError::LeftBehind));
    none.proposals
        .push(ProposalView::Remove(LeafNodeIndex::new(4)));
    assert!(check(&g, &none).is_ok());
    // A ban must remove the identity's leaves, and its role.
    let mut ban = commit(&g, 1, vec![ProposalView::GroupContextExtensions]);
    ban.new_conversation
        .as_mut()
        .unwrap()
        .bans
        .push(uid("p@x.org"));
    assert_eq!(check(&g, &ban), Err(CommitError::LeftBehind));
    ban.proposals.extend(remove(&[2, 3]));
    assert!(check(&g, &ban).is_ok());
}

/// A room whose owners are gone: moderators act as owners (6.3).
#[test]
fn ownerless_rooms() {
    let conv = room(ConversationKind::PrivateRoom);
    let mut g = group(&conv);
    let mut rename = commit(&g, 1, vec![ProposalView::GroupContextExtensions]);
    rename.new_conversation.as_mut().unwrap().name = "New".into();
    assert!(matches!(check(&g, &rename), Err(CommitError::Extension(_))));
    g.leaves.remove(0);
    assert!(check(&g, &rename).is_ok());
    assert_eq!(g.effective_role(&uid("m@x.org")), Role::Owner);
}

/// One leaf per device outside public rooms (12.7); joins check it too.
#[test]
fn one_leaf_per_device() {
    let conv = room(ConversationKind::PrivateRoom);
    let mut g = group(&conv);
    g.leaves[3] = leaf_of_device(3, "p@x.org", 2, T);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::SameDevice)
    );
    let expect = JoinExpectation {
        host: "h.org".into(),
        own_uid: uid("p@x.org"),
        public_room: None,
    };
    assert_eq!(check_join(&g, &expect), Err(JoinError::SameDevice));
    // A public room's leaves may share a device until the earlier one is
    // removed as inactive.
    let mut public = g.clone();
    public.conversation = Ok(room(ConversationKind::PublicRoom));
    assert!(check(&public, &commit(&public, 0, vec![])).is_ok());
}

/// A public room's earlier leaf of the same device, once inactive for 48
/// hours (12.7).
#[test]
fn inactive_leaves() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    let old = T - 49 * HOUR;
    g.leaves[3] = leaf_of_device(3, "p@x.org", 2, old);
    // By a moderator? No: a moderator would kick all of p's leaves. By the
    // owner of another leaf, a plain member q.
    g.leaves.push(leaf(4, "q@x.org", T));
    let c = commit(&g, 4, remove(&[3]));
    assert!(check(&g, &c).is_ok());
    // Added recently: not inactive.
    let mut history = full();
    history.added_at.insert(3, T - HOUR);
    assert_eq!(
        check_commit(&g, &c, &history, &at(T)),
        Err(CommitError::Remove)
    );
    // Without a later copy of the same device, not removable.
    let mut alone = g.clone();
    alone.leaves[2] = leaf_of_device(2, "p@x.org", 9, T);
    assert_eq!(check(&alone, &c), Err(CommitError::Remove));
}

/// Within 24 hours after a resync commit, leaves that neither committed
/// nor were added since (12.7).
#[test]
fn after_a_resync() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves.push(leaf(4, "q@x.org", T));
    // Leaf 1 last committed 30 hours ago: no impostor repair is possible.
    g.leaves[1].profile = Some(RisalaProfile::new("", T - 30 * HOUR).unwrap());
    let c = commit(&g, 4, remove(&[1]));
    let mut history = full();
    history.resync = Some(ResyncState {
        t: T - HOUR,
        active: [4].into(),
    });
    assert!(check_commit(&g, &c, &history, &at(T)).is_ok());
    // A leaf that has committed since is not removable.
    history.resync.as_mut().unwrap().active.insert(1);
    assert_eq!(
        check_commit(&g, &c, &history, &at(T)),
        Err(CommitError::Remove)
    );
    // Nor after 24 hours.
    history.resync.as_mut().unwrap().active.remove(&1);
    let mut late = c.clone();
    late.path_leaf.as_mut().unwrap().profile = Some(
        RisalaProfile::new("", T + 24 * HOUR)
            .unwrap()
            .with_streak(1),
    );
    assert_eq!(
        check_commit(&g, &late, &history, &at(T + 24 * HOUR)),
        Err(CommitError::Remove)
    );
    // A device that joined since cannot tell, unless the leaf committed
    // since it joined.
    let joined = History::joined(20, 0, T - HOUR, 4);
    assert_eq!(
        check_commit(&g, &c, &joined, &at(T)).unwrap().unchecked,
        vec!["a removal after a resync"]
    );
    // If leaf 1 committed after this device joined, it is no straggler.
    let mut active = g.clone();
    active.leaves[1].profile = Some(RisalaProfile::new("", T - 10 * MIN).unwrap());
    let c = commit(&active, 4, remove(&[1]));
    assert_eq!(
        check_commit(&active, &c, &joined, &at(T))
            .unwrap()
            .unchecked,
        vec!["an impostor repair"],
        "it may still be an impostor this device cannot judge"
    );
    let mut quiet = joined.clone();
    quiet.since_t = T - 25 * HOUR;
    assert_eq!(
        check_commit(&active, &c, &quiet, &at(T)),
        Err(CommitError::Remove)
    );
}

/// Resync commits, the only external commits (12.7).
#[test]
fn resync_commits() {
    let conv = room(ConversationKind::PublicRoom);
    let g = group(&conv);
    let mut history = full();
    history.started_by = Some(1);
    let resync = |identity: RisalaIdentity, proposals: Vec<ProposalView>| {
        let mut path = leaf(9, identity.uid.as_str(), T);
        path.identity = Some(identity);
        path.profile = Some(RisalaProfile::new("", T).unwrap().with_streak(1));
        CommitView {
            committer: Committer::External,
            proposals,
            path_leaf: Some(path),
            new_conversation: Ok(conv.clone()),
            pending_self_removes: Vec::new(),
        }
    };
    let p = RisalaIdentity::device(uid("p@x.org"), DeviceId([2; 48]));
    let mut good = vec![ProposalView::ExternalInit];
    good.extend(remove(&[1]));
    let verdict = check_commit(&g, &resync(p.clone(), good.clone()), &history, &at(T)).unwrap();
    assert!(verdict.resync);
    // It must remove the GroupInfo's signer.
    assert_eq!(
        check_commit(
            &g,
            &resync(p.clone(), vec![ProposalView::ExternalInit]),
            &history,
            &at(T)
        ),
        Err(CommitError::External)
    );
    // Nothing else, but its own inactive earlier leaf.
    let mut more = good.clone();
    more.extend(remove(&[0]));
    assert_eq!(
        check_commit(&g, &resync(p.clone(), more), &history, &at(T)),
        Err(CommitError::Remove)
    );
    let mut own = good.clone();
    own.extend(remove(&[2]));
    assert_eq!(
        check_commit(&g, &resync(p.clone(), own.clone()), &history, &at(T)),
        Err(CommitError::Remove),
        "not inactive"
    );
    let mut g_old = g.clone();
    g_old.leaves[2].profile = Some(RisalaProfile::new("", T - 49 * HOUR).unwrap());
    assert!(check_commit(&g_old, &resync(p.clone(), own), &history, &at(T)).is_ok());
    // Only by an identity that already has a leaf.
    let stranger = RisalaIdentity::device(uid("z@x.org"), DeviceId([7; 48]));
    assert_eq!(
        check_commit(&g, &resync(stranger, good.clone()), &history, &at(T)),
        Err(CommitError::External)
    );
    let guest = RisalaIdentity::guest(uid("~sam"));
    assert_eq!(
        check_commit(&g, &resync(guest, good.clone()), &history, &at(T)),
        Err(CommitError::External)
    );
    // With streak 1.
    let mut streak = resync(p.clone(), good.clone());
    streak.path_leaf.as_mut().unwrap().profile =
        Some(RisalaProfile::new("", T).unwrap().with_streak(2));
    assert_eq!(
        check_commit(&g, &streak, &history, &at(T)),
        Err(CommitError::Streak)
    );
    // Never outside a public room.
    let private = group(&room(ConversationKind::PrivateRoom));
    assert_eq!(
        check_commit(&private, &resync(p, good), &history, &at(T)),
        Err(CommitError::External)
    );
}

/// What a History keeps and looks back on (12.7, 12.9).
#[test]
fn history() {
    let conv = room(ConversationKind::PrivateRoom);
    let before = group(&conv);
    let mut history = full();
    // Leaf 1 (a moderator) kicks p (2, 3) and changes the topic, at T.
    let mut c = commit(&before, 1, remove(&[2, 3]));
    c.proposals.push(ProposalView::GroupContextExtensions);
    c.new_conversation.as_mut().unwrap().topic = "taken".into();
    let verdict = check_commit(&before, &c, &history, &at(T)).unwrap();
    assert!(verdict.authority);
    let mut after = before.clone();
    after.epoch = 21;
    after.leaves.truncate(2);
    after.conversation = c.new_conversation.clone();
    history.record(&before, &c, &verdict, &after, &at(T));
    assert_eq!(history.started_by, Some(1));
    assert_eq!(history.epoch_end(20), Some(T));
    let record = &history.commits[0];
    assert_eq!(record.removed.len(), 2);
    assert!(record.removed.iter().all(|r| r.how == Removal::Kick));
    assert!(record.extension_change.is_some());
    // p was kicked: not added back by just anyone.
    assert_eq!(
        history.may_add_back(&uid("p@x.org"), 21),
        Lookup::Known(false)
    );
    // An impostor repair by o undoes it: the topic goes back.
    let mut repair = commit(&after, 0, remove(&[1]));
    repair.proposals.push(ProposalView::GroupContextExtensions);
    repair.new_conversation = Ok(conv.clone());
    let mut post = at(T + HOUR);
    post.next = Some([2; 48]);
    let mut by_member = after.clone();
    by_member.leaves.push(leaf(4, "q@x.org", T));
    let mut repair_q = commit(&by_member, 4, remove(&[1]));
    repair_q.path_leaf.as_mut().unwrap().profile =
        Some(RisalaProfile::new("", T + HOUR).unwrap().with_streak(1));
    repair_q
        .proposals
        .push(ProposalView::GroupContextExtensions);
    repair_q.new_conversation = Ok(conv.clone());
    let verdict = check_commit(&by_member, &repair_q, &history, &post).unwrap();
    assert_eq!(verdict.repairs, vec![LeafNodeIndex::new(1)]);
    // More than 24 hours later, there is nothing left to undo.
    let mut late = repair_q.clone();
    late.path_leaf.as_mut().unwrap().profile = Some(
        RisalaProfile::new("", T + 25 * HOUR)
            .unwrap()
            .with_streak(1),
    );
    assert!(matches!(
        check_commit(&by_member, &late, &history, &at(T + 25 * HOUR)),
        Err(CommitError::Extension(_))
    ));
    let _ = repair;
    // RESYNC lines are kept for 16 epochs.
    history.note_resync(LeafNodeIndex::new(0), 21);
    assert_eq!(
        history.posted_resync(LeafNodeIndex::new(0), 36),
        Lookup::Known(true)
    );
    assert_eq!(
        history.posted_resync(LeafNodeIndex::new(0), 37),
        Lookup::Known(false)
    );
    // A device that joined in epoch 30 cannot tell for epoch 40.
    let joined = History::joined(30, 0, T, 2);
    assert_eq!(
        joined.posted_resync(LeafNodeIndex::new(0), 40),
        Lookup::Unknown
    );
    assert_eq!(
        joined.posted_resync(LeafNodeIndex::new(0), 45),
        Lookup::Known(false)
    );
}

/// Old commits beyond both windows are dropped.
#[test]
fn history_prunes() {
    let conv = room(ConversationKind::PrivateRoom);
    let mut history = full();
    let mut before = group(&conv);
    for i in 0..40u64 {
        before.epoch = i;
        let mut after = before.clone();
        after.epoch = i + 1;
        let t = T + i * 3 * 24 * HOUR;
        let c = commit(&before, 2, vec![]);
        history.record(&before, &c, &Verdict::default(), &after, &at(t));
    }
    // 16 epochs back, and 72 hours (24 + 48) by `t`.
    // The commits of epochs 25 to 39, of the last 16 as of epoch 40.
    assert_eq!(history.commits.len(), 15);
    assert_eq!(history.commits[0].epoch, 25);
}

#[test]
fn key_checks_of_removals_and_committers() {
    struct Removed;
    impl KeyFacts for Removed {
        fn current_device_key(&self, _: &Uid, _: &DeviceId) -> Fact<Option<Vec<u8>>> {
            Fact::Known(None)
        }
        fn device_removed(&self, uid: &Uid, _: &DeviceId) -> Fact<bool> {
            Fact::Known(uid.as_str() == "o@x.org")
        }
        fn identity_retired(&self, uid: &Uid) -> Fact<bool> {
            Fact::Known(uid.as_str() == "m@x.org")
        }
    }
    let g = group(&room(ConversationKind::PrivateRoom));
    let c = commit(&g, 2, remove(&[0, 1]));
    let verdict = check(&g, &c).unwrap();
    assert_eq!(verdict.key_check_removals.len(), 2);
    // o's device was removed by record, m's identity retired: both
    // removals hold.
    assert_eq!(key_checks(&g, &c, &verdict, &Removed), KeyReport::default());
    // Neither: both are repaired.
    let report = key_checks(&g, &c, &verdict, &NoFacts);
    assert_eq!(report.failed_removals.len(), 2);
    // A committer whose device was removed by record is an impostor.
    let c = commit(&g, 0, vec![]);
    let report = key_checks(&g, &c, &check(&g, &c).unwrap(), &Removed);
    assert!(report.committer_removed);
    // Public rooms have no key checks.
    let public = group(&room(ConversationKind::PublicRoom));
    let c = commit(&public, 0, vec![]);
    assert_eq!(
        key_checks(&public, &c, &Verdict::default(), &Removed),
        KeyReport::default()
    );
}

fn crowd(conv: &RisalaConversation, identities: u32, per: u32) -> GroupView {
    let mut leaves = vec![leaf(0, "o@x.org", T)];
    for i in 1..identities {
        for j in 0..per {
            let mut l = leaf(i * per + j, &format!("u{i}@x.org"), T);
            l.index = LeafNodeIndex::new(i * per + j);
            l.identity = Some(RisalaIdentity::device(
                l.uid().unwrap().clone(),
                DeviceId([j as u8; 48]),
            ));
            leaves.push(l);
        }
    }
    GroupView {
        epoch: 1,
        conversation: Ok(conv.clone()),
        leaves,
    }
}

#[test]
fn limits() {
    let conv = room(ConversationKind::PrivateRoom);
    // 256 members while pairwise is fine, 257 is not (6.2).
    let g = crowd(&conv, 256, 1);
    assert!(check(&g, &commit(&g, 0, vec![])).is_ok());
    let g = crowd(&conv, 257, 1);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::TooLarge)
    );
    // Whoever takes it past 256 moves it to epochal (6.2): a plain member
    // may, in that commit. Here the room is already past, so it is allowed.
    let mut go = commit(&g, 5, vec![ProposalView::GroupContextExtensions]);
    go.new_conversation.as_mut().unwrap().confirm = ConfirmMode::Epochal;
    assert!(check(&g, &go).is_ok());
    let mut epochal = conv.clone();
    epochal.confirm = ConfirmMode::Epochal;
    let g = crowd(&epochal, 257, 1);
    assert!(check(&g, &commit(&g, 0, vec![])).is_ok());
    // 1,000 identities and 4,096 leaves in a private room (6.1).
    let g = crowd(&epochal, 1001, 1);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::TooLarge)
    );
    let g = crowd(&epochal, 400, 11);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::TooLarge)
    );
    let public = room(ConversationKind::PublicRoom);
    let g = crowd(&public, 1001, 1);
    assert!(check(&g, &commit(&g, 0, vec![])).is_ok());
}

#[test]
fn joining() {
    let conv = room(ConversationKind::PrivateRoom);
    let expect = JoinExpectation {
        host: "h.org".into(),
        own_uid: uid("p@x.org"),
        public_room: None,
    };
    let g = group(&conv);
    assert_eq!(check_join(&g, &expect), Ok(()));
    let mut other_host = expect.clone();
    other_host.host = "x.org".into();
    assert_eq!(
        check_join(&g, &other_host),
        Err(JoinError::WrongConversation)
    );
    let mut public = expect.clone();
    public.public_room = Some(("#r".parse().unwrap(), [0; 16]));
    assert_eq!(check_join(&g, &public), Err(JoinError::WrongConversation));
    let mut guest = g.clone();
    guest.leaves.push(leaf(4, "~sam", 1));
    assert_eq!(check_join(&guest, &expect), Err(JoinError::Guest));
    let mut banned = g.clone();
    banned
        .conversation
        .as_mut()
        .unwrap()
        .bans
        .push(uid("p@x.org"));
    assert_eq!(check_join(&banned, &expect), Err(JoinError::Banned));
    let mut no_profile = g.clone();
    no_profile.leaves[1].profile = None;
    assert_eq!(check_join(&no_profile, &expect), Err(JoinError::Leaf));
    let mut bad_key = g.clone();
    bad_key.leaves[3].encryption_key_ok = false;
    assert_eq!(check_join(&bad_key, &expect), Err(JoinError::Leaf));
    let mut no_identity = g.clone();
    no_identity.leaves[1].identity = None;
    assert_eq!(check_join(&no_identity, &expect), Err(JoinError::Leaf));
    let big = crowd(&conv, 1001, 1);
    assert_eq!(check_join(&big, &expect), Err(JoinError::TooLarge));

    // A guest's report conversation: the guest has exactly one leaf.
    let report = RisalaConversation::direct("h.org", [0; 16], &uid("~sam"), &uid("p@x.org"));
    let mut r = GroupView {
        epoch: 1,
        conversation: Ok(report),
        leaves: vec![leaf(0, "~sam", T), leaf(1, "p@x.org", T)],
    };
    r.leaves[0].profile = None;
    assert_eq!(check_join(&r, &expect), Ok(()));
    r.leaves.push(leaf(2, "~sam", T));
    assert_eq!(check_join(&r, &expect), Err(JoinError::Guest));
}

/// In a guest's report conversation, the guest's leaf adds nobody once the
/// identity has leaves (12.7); and its commits have no profile to check.
#[test]
fn report_conversations() {
    let report = RisalaConversation::direct("h.org", [0; 16], &uid("~sam"), &uid("p@x.org"));
    let mut g = GroupView {
        epoch: 1,
        conversation: Ok(report),
        leaves: vec![leaf(0, "~sam", T), leaf(1, "p@x.org", T)],
    };
    g.leaves[0].profile = None;
    let mut c = commit(&g, 0, vec![]);
    c.path_leaf.as_mut().unwrap().profile = None;
    assert!(check(&g, &c).is_ok());
}
