//! The group checks and key checks over hand-made views (12.7), for rules
//! that are awkward to reach with real groups.

use openmls::prelude::Lifetime;
use openmls_memory_storage::MemoryStorage;

use super::*;
use crate::Provider;
use crate::keypackage::{build_key_package, make_join_key_package_with, make_key_package_with};
use crate::mldsa::{LeafKey, SigningKey};

const T: u64 = 1_800_000_000_000;
const MIN: u64 = 60 * 1000;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;

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
        RisalaIdentity::device(uid, DeviceId::from_bytes([device; 48]))
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
        ConversationKind::PublicRoom => RisalaConversation::public_room(
            "h.org".parse().unwrap(),
            [0; 16],
            &"#r".parse().unwrap(),
            &owner,
        ),
        _ => RisalaConversation::private_room("h.org".parse().unwrap(), [0; 16], "R", &owner),
    };
    conv.mods.push(uid("m@x.org"));
    conv
}

fn view(conv: &RisalaConversation, leaves: Vec<LeafView>) -> GroupView {
    GroupView {
        epoch: 20,
        conversation: Ok(conv.clone()),
        leaves,
        started_by: None,
        moved_box: None,
    }
}

/// Owner o (leaf 0), moderator m (1), member p (2 and 3), all updated at
/// `T`, in epoch 20.
fn group(conv: &RisalaConversation) -> GroupView {
    view(
        conv,
        vec![
            leaf(0, "o@x.org", T),
            leaf(1, "m@x.org", T),
            leaf(2, "p@x.org", T),
            leaf(3, "p@x.org", T),
        ],
    )
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

/// The same commit, with the committer's new `updated` and `streak`.
fn at_time(mut c: CommitView, updated: u64, streak: u8) -> CommitView {
    c.path_leaf.as_mut().unwrap().profile =
        Some(RisalaProfile::new("", updated).unwrap().with_streak(streak));
    c
}

fn at(t: u64) -> CommitPost {
    CommitPost::at(t, Some([1; 48]))
}

fn check(group: &GroupView, commit: &CommitView) -> Result<Verdict, CommitError> {
    check_commit(group, commit, &at(T))
}

fn remove(indices: &[u32]) -> Vec<ProposalView> {
    indices
        .iter()
        .map(|i| ProposalView::Remove(LeafNodeIndex::new(*i)))
        .collect()
}

fn idx(i: u32) -> LeafNodeIndex {
    LeafNodeIndex::new(i)
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
        check_commit(&g, &commit(&g, 2, vec![]), &CommitPost::at(T, None)),
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
    other.path_leaf.as_mut().unwrap().identity = Some(RisalaIdentity::device(
        uid("p@x.org"),
        DeviceId::from_bytes([9; 48]),
    ));
    assert_eq!(check(&g, &other), Err(CommitError::Leaf));
    let mut no_profile = commit(&g, 2, vec![]);
    no_profile.path_leaf.as_mut().unwrap().profile = None;
    assert_eq!(check(&g, &no_profile), Err(CommitError::Leaf));
    let mut bad_key = commit(&g, 2, vec![]);
    bad_key.path_leaf.as_mut().unwrap().encryption_key_ok = false;
    assert_eq!(check(&g, &bad_key), Err(CommitError::Leaf));

    // A new signature key outside epochal groups: only while the leaf's
    // source is still `key_package` (12.3).
    let mut rotate = commit(&g, 2, vec![]);
    rotate.path_leaf.as_mut().unwrap().signature_key = vec![42; 4];
    assert_eq!(check(&g, &rotate), Err(CommitError::Leaf));
    let mut fresh = g.clone();
    fresh.leaves[2].from_key_package = true;
    assert_eq!(check(&fresh, &rotate), Ok(Verdict::default()));

    // In an epochal group, only if the post's `t` is in a later period
    // than the leaf's previous `updated` minus 10 minutes (12.3).
    let mut epochal = conv.clone();
    epochal.confirm = ConfirmMode::Epochal;
    let day = T / PERIOD_MS * PERIOD_MS;
    let with_updated = |updated: u64| {
        let mut g = group(&epochal);
        for leaf in &mut g.leaves {
            leaf.profile = Some(RisalaProfile::new("", updated).unwrap());
        }
        g
    };
    let rotate_at = |g: &GroupView, t| {
        let mut c = at_time(commit(g, 2, vec![]), t, 1);
        c.path_leaf.as_mut().unwrap().signature_key = vec![42; 4];
        check_commit(g, &c, &at(t))
    };
    // Changed at 10 minutes into the day or later: not again that day.
    for updated in [day + 10 * MIN, day + PERIOD_MS / 2] {
        let g = with_updated(updated);
        assert_eq!(rotate_at(&g, updated), Err(CommitError::Leaf));
        assert_eq!(rotate_at(&g, day + PERIOD_MS - 1), Err(CommitError::Leaf));
        assert_eq!(rotate_at(&g, day + PERIOD_MS), Ok(Verdict::default()));
    }
    // A change in the day's first 10 minutes counts as the day before's,
    // so a second one that day is allowed, once 12.3's bounds on
    // `updated` are met.
    let g = with_updated(day + 10 * MIN - 1);
    assert_eq!(rotate_at(&g, day + 10 * MIN), Ok(Verdict::default()));
    // A clock 10 minutes ahead just before midnight: `updated` is past
    // midnight, yet the leaf may change its key in the new day.
    let g = with_updated(day + 5 * MIN);
    assert_eq!(rotate_at(&g, day + 20 * MIN), Ok(Verdict::default()));
    // A leaf added from a last-resort KeyPackage made at any time of the
    // day may change its key at once (12.3).
    for made in [day, day + 30 * MIN, day + PERIOD_MS - 1] {
        let g = with_updated(crate::keypackage::last_resort_updated(made));
        assert_eq!(rotate_at(&g, made), Ok(Verdict::default()));
    }
    // The bound in the day before: `updated` 10 minutes before midnight.
    let g = with_updated(day - 10 * MIN);
    assert_eq!(rotate_at(&g, day - MIN), Err(CommitError::Leaf));
    assert_eq!(rotate_at(&g, day), Ok(Verdict::default()));
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
        assert_eq!(check_commit(&g, &c, &at(t)).is_ok(), ok, "{t}");
    }
    let back = at_time(c, T - 1, 1);
    assert_eq!(check(&g, &back), Err(CommitError::Updated));
}

/// Streaks count per identity, from the leaf that started the epoch
/// (12.3, 12.7).
#[test]
fn streaks() {
    let g = group(&room(ConversationKind::PrivateRoom));
    // In the first epoch, or after another identity's commit: 1.
    assert!(check(&g, &at_time(commit(&g, 2, vec![]), T, 1)).is_ok());
    let mut by_o = g.clone();
    by_o.started_by = Some(idx(0));
    by_o.leaves[0].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(3));
    assert!(check(&by_o, &at_time(commit(&by_o, 2, vec![]), T, 1)).is_ok());
    assert_eq!(
        check(&by_o, &at_time(commit(&by_o, 2, vec![]), T, 4)),
        Err(CommitError::Streak)
    );
    // p's other device (leaf 3) started it with streak 3: p's next commit,
    // from either device, carries 4, which needs 10 minutes since the
    // highest `updated` of p's leaves that committed, or only removals of
    // p's own leaves.
    let mut g3 = g.clone();
    g3.started_by = Some(idx(3));
    g3.leaves[3].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(3));
    let c = |updated, proposals| at_time(commit(&g3, 2, proposals), updated, 4);
    assert_eq!(
        check(&g3, &at_time(commit(&g3, 2, vec![]), T, 1)),
        Err(CommitError::Streak)
    );
    assert_eq!(check(&g3, &c(T, vec![])), Err(CommitError::Streak));
    assert!(check_commit(&g3, &c(T + 10 * MIN, vec![]), &at(T + 10 * MIN)).is_ok());
    assert!(check(&g3, &c(T, remove(&[3]))).is_ok());
    assert_eq!(check(&g3, &c(T, remove(&[0, 3]))), Err(CommitError::Streak));
    // A leaf of p that never committed, with a later `updated` (a copy of
    // p's credential in a KeyPackage), does not hold p back.
    let mut copy = g3.clone();
    copy.leaves
        .push(leaf_of_device(4, "p@x.org", 9, T + 9 * MIN));
    copy.leaves[4].from_key_package = true;
    assert!(check_commit(&copy, &c(T + 10 * MIN, vec![]), &at(T + 10 * MIN)).is_ok());
    let mut committed = copy.clone();
    committed.leaves[4].from_key_package = false;
    assert_eq!(
        check_commit(&committed, &c(T + 10 * MIN, vec![]), &at(T + 10 * MIN)),
        Err(CommitError::Streak)
    );
    // No limit in the conversation with yourself.
    let me = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("p@x.org"),
        &uid("p@x.org"),
    );
    let mut mine = view(
        &me,
        vec![leaf(2, "p@x.org", T), leaf_of_device(3, "p@x.org", 3, T)],
    );
    mine.started_by = Some(idx(3));
    mine.leaves[1].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(9));
    assert!(check(&mine, &at_time(commit(&mine, 2, vec![]), T, 10)).is_ok());
    // Capped at 255.
    let mut g255 = g3.clone();
    g255.leaves[3].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(255));
    let c = at_time(commit(&g255, 2, vec![]), T + 10 * MIN, 255);
    assert!(check_commit(&g255, &c, &at(T + 10 * MIN)).is_ok());
}

#[test]
fn removes_and_kicks() {
    let conv = room(ConversationKind::PublicRoom);
    let g = group(&conv);
    // Your own leaves, a SelfRemove's.
    let verdict = check(&g, &commit(&g, 2, remove(&[3]))).unwrap();
    assert!(verdict.authority, "removes its identity's other leaf");
    let verdict = check(&g, &commit(&g, 0, remove(&[1]))).unwrap();
    assert!(verdict.authority, "an owner kicks a moderator");
    let mut pending = commit(&g, 2, remove(&[0]));
    assert_eq!(check(&g, &pending), Err(CommitError::Remove));
    pending.pending_self_removes.push(idx(0));
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
            ProposalView::Remove(idx(3)),
            ProposalView::SelfRemove(idx(3)),
        ],
    );
    assert!(matches!(check(&g, &twice), Err(CommitError::Proposal(_))));
    // Outside public rooms, any other removal is for a check (12.7): an
    // authority commit.
    let private = group(&room(ConversationKind::PrivateRoom));
    let verdict = check(&private, &commit(&private, 2, remove(&[0]))).unwrap();
    assert_eq!(verdict.check_removals, vec![idx(0)]);
    assert!(verdict.authority);
    // In a direct conversation, nobody is kicked: removing the other
    // participant's leaves is for a check.
    let direct = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("o@x.org"),
        &uid("p@x.org"),
    );
    let mut gd = group(&direct);
    gd.leaves.remove(1);
    let verdict = check(&gd, &commit(&gd, 0, remove(&[2, 3]))).unwrap();
    assert_eq!(verdict.check_removals.len(), 2);
}

/// A commit removes for a check the leaves of one identity at most (12.7).
#[test]
fn check_removals_of_one_identity() {
    let g = group(&room(ConversationKind::PrivateRoom));
    let mut g = g;
    g.leaves.push(leaf(4, "q@x.org", T));
    // Two of p's leaves: fine.
    assert!(check(&g, &commit(&g, 4, remove(&[2, 3]))).is_ok());
    // o's and m's: not by a plain member.
    assert_eq!(
        check(&g, &commit(&g, 4, remove(&[0, 1]))),
        Err(CommitError::CheckRemovals)
    );
    // Nor by an owner, whose kick of m goes with a check of p's leaf: the
    // kick is a role's, p's single leaf is for a check, which is fine; but
    // two identities' leaves for a check are not.
    assert!(check(&g, &commit(&g, 0, remove(&[1, 2]))).is_ok());
    assert_eq!(
        check(&g, &commit(&g, 1, remove(&[0, 2]))),
        Err(CommitError::CheckRemovals)
    );
}

/// Stale leaves (12.7): activity times, capped at the post's `t`, against
/// the median.
#[test]
fn stale_leaves() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves[0].profile = Some(RisalaProfile::new("", T - 36 * DAY).unwrap());
    g.leaves[1].profile = Some(RisalaProfile::new("", T - 36 * DAY).unwrap());
    // Sorted: T-36d, T-36d, T, T; position 2 is T.
    assert_eq!(g.median_activity(T), Some(T));
    assert_eq!(g.stale_leaves(T), vec![idx(0), idx(1)]);
    assert_eq!(g.bulk_limit(), 1);
    assert!(check(&g, &commit(&g, 2, remove(&[0]))).is_ok());
    // In a two-leaf group either side may replace the other.
    let two = view(
        &conv,
        vec![leaf(0, "o@x.org", T - 36 * DAY), leaf(1, "m@x.org", T)],
    );
    assert_eq!(two.stale_leaves(T), vec![idx(0)]);
    // A leaf that never committed counts its KeyPackage's lifetime end,
    // but nothing counts as newer than the post: just-added leaves from
    // long-lived KeyPackages neither push the median into the future nor
    // are stale themselves.
    let mut fresh = g.clone();
    for leaf in &mut fresh.leaves[2..] {
        leaf.from_key_package = true;
        leaf.lifetime_end = Some(T + 12 * 7 * DAY);
        leaf.profile = Some(RisalaProfile::new("", T - 40 * DAY).unwrap());
    }
    assert_eq!(fresh.leaves[2].activity_time(T), T);
    assert_eq!(fresh.median_activity(T), Some(T));
    assert_eq!(fresh.stale_leaves(T), vec![idx(0), idx(1)]);
    fresh.leaves[0].from_key_package = true;
    fresh.leaves[0].lifetime_end = Some(T - 10 * DAY);
    assert_eq!(fresh.stale_leaves(T), vec![idx(1)]);
}

/// A member without a role removes at most max(1, floor(n/10)) stale
/// leaves, guest leaves, copies and never-used leaves together, besides
/// its own identity's (12.7).
#[test]
fn bulk_limit() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves.push(leaf(4, "~sam", T));
    g.leaves.push(leaf(5, "~kim", T));
    g.leaves.push(leaf(6, "q@x.org", T));
    // A plain member: one guest is fine, two are not.
    assert!(check(&g, &commit(&g, 6, remove(&[4]))).is_ok());
    assert_eq!(
        check(&g, &commit(&g, 6, remove(&[4, 5]))),
        Err(CommitError::Bulk)
    );
    // Its own identity's leaves do not count.
    assert!(check(&g, &commit(&g, 2, remove(&[3, 4]))).is_ok());
    // Owners and moderators are exempt.
    assert!(check(&g, &commit(&g, 1, remove(&[4, 5]))).is_ok());
    // In a group of 20 leaves, a plain member removes up to 2.
    let mut big = g.clone();
    for i in 7..20 {
        big.leaves.push(leaf(i, &format!("~g{i}"), T));
    }
    assert_eq!(big.bulk_limit(), 2);
    assert!(check(&big, &commit(&big, 6, remove(&[4, 5]))).is_ok());
    assert_eq!(
        check(&big, &commit(&big, 6, remove(&[4, 5, 7]))),
        Err(CommitError::Bulk)
    );
}

/// Copies in a public room (12.7): a leaf of the same device as another
/// that has committed or been Updated, with a lower `updated`.
#[test]
fn copies() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves[3] = leaf_of_device(3, "p@x.org", 2, T - HOUR);
    g.leaves.push(leaf(4, "q@x.org", T));
    assert!(g.is_copy(&g.leaves[3]));
    assert!(!g.is_copy(&g.leaves[2]));
    // Anyone removes it.
    assert!(check(&g, &commit(&g, 4, remove(&[3]))).is_ok());
    // Not the newer one.
    assert_eq!(
        check(&g, &commit(&g, 4, remove(&[2]))),
        Err(CommitError::Remove)
    );
    // Not if the newer one has neither committed nor been Updated: a copy
    // of someone's credential never pushes their leaf out.
    let mut unused = g.clone();
    unused.leaves[2].from_key_package = true;
    assert!(!unused.is_copy(&unused.leaves[3]));
    assert_eq!(
        check(&unused, &commit(&unused, 4, remove(&[3]))),
        Err(CommitError::Remove)
    );
    // Not with the other leaf removed in the same commit.
    assert_eq!(
        check(&g, &commit(&g, 4, remove(&[2, 3]))),
        Err(CommitError::Remove)
    );
    // Outside public rooms two leaves of one device are not allowed at all.
    let mut private = g.clone();
    private.conversation = Ok(room(ConversationKind::PrivateRoom));
    assert_eq!(
        check(&private, &commit(&private, 4, vec![])),
        Err(CommitError::SameDevice)
    );
}

/// Never-used leaves in a public room (12.7): by owners and moderators,
/// whatever the uid, without kicking it; by anyone after 8 days.
#[test]
fn never_used_leaves() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.leaves[0] = leaf(0, "o@x.org", T);
    g.leaves.push(leaf(4, "q@x.org", T));
    g.leaves[3].from_key_package = true;
    g.leaves[3].profile = Some(RisalaProfile::new("", T - 7 * DAY).unwrap());
    // A moderator removes it alone, without kicking p: an authority commit.
    let verdict = check(&g, &commit(&g, 1, remove(&[3]))).unwrap();
    assert!(verdict.authority);
    // A plain member, not yet.
    assert_eq!(
        check(&g, &commit(&g, 4, remove(&[3]))),
        Err(CommitError::Remove)
    );
    // After 8 days, anyone.
    let mut old = g.clone();
    old.leaves[3].profile = Some(RisalaProfile::new("", T - 8 * DAY - 1).unwrap());
    let verdict = check(&old, &commit(&old, 4, remove(&[3]))).unwrap();
    assert!(!verdict.authority);
    // A leaf that has committed is never "unused".
    let mut used = old.clone();
    used.leaves[3].from_key_package = false;
    assert_eq!(
        check(&used, &commit(&used, 1, remove(&[3]))),
        Err(CommitError::Remove)
    );
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
            sender: idx(3),
            leaf: Box::new(l),
            reference: vec![7; 48],
        }
    };
    let mut state = EpochState::default();
    state.note_proposal(&[7; 48], T - 30 * MIN);
    let post = state.post(T, Some([1; 48]));
    let c = commit(&g, 2, vec![update(T - 30 * MIN, 0)]);
    assert!(check_commit(&g, &c, &post).is_ok());
    // Its `updated` is judged by its own post's `t`, not the commit's.
    let c = commit(&g, 2, vec![update(T, 0)]);
    assert_eq!(check_commit(&g, &c, &post), Err(CommitError::Updated));
    let c = commit(&g, 2, vec![update(T - 30 * MIN, 1)]);
    assert_eq!(check_commit(&g, &c, &post), Err(CommitError::Streak));
    // A post the device did not note: it cannot judge, and refuses.
    let c = commit(&g, 2, vec![update(T, 0)]);
    assert!(matches!(
        check_commit(&g, &c, &at(T)),
        Err(CommitError::Proposal(_))
    ));
    // Not in a pairwise group.
    let pairwise = group(&room(ConversationKind::PrivateRoom));
    let c = commit(&pairwise, 2, vec![update(T, 0)]);
    assert!(matches!(
        check_commit(&pairwise, &c, &post),
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
            sender: idx(3),
            leaf: Box::new(guest_update),
            reference: vec![7; 48],
        }],
    );
    assert_eq!(
        check_commit(&with_guest, &c, &post),
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
    none.proposals.push(ProposalView::Remove(idx(4)));
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
        host: "h.org".parse().unwrap(),
        own_uid: uid("p@x.org"),
        public_room: None,
    };
    assert_eq!(check_join(&g, &expect), Err(JoinError::SameDevice));
    // A public room's leaves may share a device until one goes as a copy.
    let mut public = g.clone();
    public.conversation = Ok(room(ConversationKind::PublicRoom));
    assert!(check(&public, &commit(&public, 0, vec![])).is_ok());
}

/// Moving the mailbox (7.8, 12.7): any member, in a commit with no other
/// proposal, to the box derived from the epoch.
#[test]
fn mailbox_moves() {
    let conv = room(ConversationKind::PrivateRoom);
    let mut g = group(&conv);
    let derived = [0x77; 16];
    let mut moved = commit(&g, 2, vec![ProposalView::GroupContextExtensions]);
    moved.new_conversation.as_mut().unwrap().mailbox = derived;
    // A device that cannot derive the box refuses any move.
    assert!(matches!(check(&g, &moved), Err(CommitError::Extension(_))));
    g.moved_box = Some(derived);
    let verdict = check(&g, &moved).unwrap();
    assert!(!verdict.authority);
    // Another box is not allowed.
    let mut elsewhere = moved.clone();
    elsewhere.new_conversation.as_mut().unwrap().mailbox = [0x78; 16];
    assert!(matches!(
        check(&g, &elsewhere),
        Err(CommitError::Extension(_))
    ));
    // Nor a move with another proposal.
    let mut more = moved.clone();
    more.proposals.extend(remove(&[3]));
    assert!(matches!(check(&g, &more), Err(CommitError::Extension(_))));
}

/// External commits (12.7): resync commits and owners' and moderators'
/// rejoins, in public rooms only.
#[test]
fn external_commits() {
    let conv = room(ConversationKind::PublicRoom);
    let mut g = group(&conv);
    g.started_by = Some(idx(1));
    let external = |who: &str, device: u8, proposals: Vec<ProposalView>| {
        let mut path = leaf_of_device(9, who, device, T);
        path.profile = Some(RisalaProfile::new("", T).unwrap().with_streak(1));
        CommitView {
            committer: Committer::External,
            proposals,
            path_leaf: Some(path),
            new_conversation: Ok(conv.clone()),
            pending_self_removes: Vec::new(),
        }
    };
    let with = |indices: &[u32]| {
        let mut p = vec![ProposalView::ExternalInit];
        p.extend(remove(indices));
        p
    };
    // A resync by p, who has a leaf: removes the leaf that started the
    // epoch, and may remove p's own.
    let verdict = check(&g, &external("p@x.org", 7, with(&[1]))).unwrap();
    assert_eq!(verdict.external, Some(External::Resync));
    assert_eq!(
        check(&g, &external("p@x.org", 7, with(&[1, 2])))
            .unwrap()
            .external,
        Some(External::Resync)
    );
    // It must remove the starter, and nothing else of another identity.
    assert_eq!(
        check(&g, &external("p@x.org", 7, with(&[]))),
        Err(CommitError::External)
    );
    assert_eq!(
        check(&g, &external("p@x.org", 7, with(&[0]))),
        Err(CommitError::Remove)
    );
    assert_eq!(
        check(&g, &external("p@x.org", 7, with(&[1, 0]))),
        Err(CommitError::Remove)
    );
    // Only by an identity that had a leaf, and never a guest.
    assert_eq!(
        check(&g, &external("z@x.org", 7, with(&[1]))),
        Err(CommitError::External)
    );
    assert_eq!(
        check(&g, &external("~sam", 0, with(&[1]))),
        Err(CommitError::External)
    );
    // Exactly one ExternalInit, and no other kind of proposal.
    let mut two = with(&[1]);
    two.push(ProposalView::ExternalInit);
    assert_eq!(
        check(&g, &external("p@x.org", 7, two)),
        Err(CommitError::External)
    );
    // A rejoin by an owner or moderator: only its own leaves, if any.
    let verdict = check(&g, &external("o@x.org", 7, with(&[0]))).unwrap();
    assert_eq!(verdict.external, Some(External::Rejoin));
    let mut no_m = g.clone();
    no_m.leaves.remove(1);
    no_m.started_by = Some(idx(0));
    assert_eq!(
        check(&no_m, &external("m@x.org", 7, with(&[])))
            .unwrap()
            .external,
        Some(External::Rejoin)
    );
    assert_eq!(
        check(&g, &external("o@x.org", 7, with(&[2]))),
        Err(CommitError::Remove)
    );
    // Streaks follow the identity of the leaf that started the epoch: o
    // started it here, so o's rejoin carries o's streak plus 1.
    let mut by_o = g.clone();
    by_o.started_by = Some(idx(0));
    by_o.leaves[0].profile = Some(RisalaProfile::new("", T).unwrap().with_streak(1));
    assert_eq!(
        check(&by_o, &external("o@x.org", 7, with(&[0]))),
        Err(CommitError::Streak)
    );
    let mut c = external("o@x.org", 7, with(&[0]));
    c.path_leaf.as_mut().unwrap().profile = Some(RisalaProfile::new("", T).unwrap().with_streak(2));
    assert!(check(&by_o, &c).is_ok());
    // A banned identity may not.
    let mut banned = g.clone();
    banned
        .conversation
        .as_mut()
        .unwrap()
        .bans
        .push(uid("p@x.org"));
    assert_eq!(
        check(&banned, &external("p@x.org", 7, with(&[1]))),
        Err(CommitError::Add)
    );
    // `updated` near the post's `t`.
    let mut late = external("p@x.org", 7, with(&[1]));
    late.path_leaf.as_mut().unwrap().profile =
        Some(RisalaProfile::new("", T + HOUR).unwrap().with_streak(1));
    assert_eq!(check(&g, &late), Err(CommitError::Updated));
    // Never outside a public room.
    let mut private = g.clone();
    private.conversation = Ok(room(ConversationKind::PrivateRoom));
    assert_eq!(
        check(&private, &external("p@x.org", 7, with(&[1]))),
        Err(CommitError::External)
    );
}

type TestProvider = Provider<MemoryStorage>;

fn provider() -> TestProvider {
    Provider::new(MemoryStorage::default()).unwrap()
}

/// A KeyPackage of `who`'s device `seed`, made at `updated`, valid around
/// `T`.
fn key_package(provider: &TestProvider, who: &str, seed: u8, updated: u64) -> KeyPackage {
    let s = T / 1000;
    make_key_package_with(
        provider,
        &SigningKey::from_seed([seed; 32]),
        &uid(who),
        &RisalaProfile::new("", updated).unwrap(),
        false,
        Lifetime::init(s - 3600, s + 3600),
    )
    .unwrap()
    .key_package
}

fn device_of(seed: u8) -> DeviceId {
    SigningKey::from_seed([seed; 32]).device_id()
}

fn add(key_package: KeyPackage) -> ProposalView {
    ProposalView::Add {
        key_package: Box::new(key_package),
        by_external_proposal: false,
    }
}

/// Who may add whom outside public rooms (12.7).
#[test]
fn adds() {
    let provider = provider();
    let conv = room(ConversationKind::PrivateRoom);
    let mut g = group(&conv);
    g.leaves.push(leaf(4, "q@x.org", T));
    // p, a plain member, adds a device of its own, and q adds one of p's,
    // whose identity has a leaf.
    assert!(
        check(
            &g,
            &commit(&g, 2, vec![add(key_package(&provider, "p@x.org", 50, T))])
        )
        .is_ok()
    );
    let verdict = check(
        &g,
        &commit(&g, 4, vec![add(key_package(&provider, "p@x.org", 51, T))]),
    )
    .unwrap();
    assert!(!verdict.authority);
    // Not once the same commit removes p's last leaves for a check: "has a
    // leaf" means after the commit.
    let mut c = commit(&g, 4, remove(&[2, 3]));
    c.proposals
        .push(add(key_package(&provider, "p@x.org", 52, T)));
    assert_eq!(check(&g, &c), Err(CommitError::Add));
    // A device whose stale leaf the same commit removes, by anyone.
    let mut stale = g.clone();
    stale.leaves[3] = leaf(3, "p@x.org", T - 40 * DAY);
    stale.leaves[3].identity = Some(RisalaIdentity::device(uid("p@x.org"), device_of(53)));
    stale.leaves[2] = leaf(2, "r@x.org", T);
    let mut c = commit(&stale, 4, remove(&[3]));
    c.proposals
        .push(add(key_package(&provider, "p@x.org", 53, T)));
    assert!(check(&stale, &c).is_ok());
    // Not another device of p in its place.
    let mut c = commit(&stale, 4, remove(&[3]));
    c.proposals
        .push(add(key_package(&provider, "p@x.org", 54, T)));
    assert_eq!(check(&stale, &c), Err(CommitError::Add));
    // A new identity: an invitation, by owners and moderators only.
    let invite = || vec![add(key_package(&provider, "n@x.org", 60, T))];
    assert_eq!(check(&g, &commit(&g, 2, invite())), Err(CommitError::Add));
    assert!(check(&g, &commit(&g, 1, invite())).unwrap().authority);
    // One listed in `mods`: owners only.
    let mut listed = conv.clone();
    listed.mods.push(uid("n@x.org"));
    let gl = group(&listed);
    assert_eq!(check(&gl, &commit(&gl, 1, invite())), Err(CommitError::Add));
    assert!(check(&gl, &commit(&gl, 0, invite())).is_ok());
    // An added leaf's `updated` no more than 10 minutes after the post's
    // `t`.
    let future = vec![add(key_package(&provider, "p@x.org", 55, T + 11 * MIN))];
    assert_eq!(check(&g, &commit(&g, 2, future)), Err(CommitError::Updated));
    // Never a banned identity.
    let mut banned = conv.clone();
    banned.bans.push(uid("n@x.org"));
    let gb = group(&banned);
    assert_eq!(check(&gb, &commit(&gb, 0, invite())), Err(CommitError::Add));
    // In a direct conversation, either participant's devices, by anyone.
    let direct = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("o@x.org"),
        &uid("p@x.org"),
    );
    let mut gd = group(&direct);
    gd.leaves.remove(1);
    assert!(
        check(
            &gd,
            &commit(&gd, 0, vec![add(key_package(&provider, "p@x.org", 56, T))])
        )
        .is_ok()
    );
    assert_eq!(check(&gd, &commit(&gd, 0, invite())), Err(CommitError::Add));
}

/// In a public room, only external Add proposals, by reference, with no
/// binding and `streak` 0 (12.7).
#[test]
fn public_room_adds() {
    let provider = provider();
    let conv = room(ConversationKind::PublicRoom);
    let g = group(&conv);
    let s = T / 1000;
    let identity = RisalaIdentity::device(uid("n@x.org"), DeviceId::from_bytes([60; 48]));
    let join = |profile: &RisalaProfile| {
        make_join_key_package_with(
            &provider,
            &identity,
            Some(profile),
            Lifetime::init(s - 3600, s + 3600),
        )
        .unwrap()
        .key_package
    };
    let kp = join(&RisalaProfile::new("", T).unwrap());
    let by_reference = ProposalView::Add {
        key_package: Box::new(kp.clone()),
        by_external_proposal: true,
    };
    assert!(check(&g, &commit(&g, 2, vec![by_reference])).is_ok());
    assert_eq!(
        check(&g, &commit(&g, 2, vec![add(kp)])),
        Err(CommitError::Add)
    );
    // An added leaf's streak is 0.
    let leaf_key = LeafKey::generate().unwrap();
    let bundle = build_key_package(
        &provider,
        &leaf_key,
        identity.credential_with_key(leaf_key.public_key()),
        vec![
            RisalaProfile::new("", T)
                .unwrap()
                .with_streak(1)
                .to_extension(),
        ],
        Vec::new(),
        Lifetime::init(s - 3600, s + 3600),
    )
    .unwrap();
    let streaky = ProposalView::Add {
        key_package: Box::new(bundle.key_package().clone()),
        by_external_proposal: true,
    };
    assert_eq!(
        check(&g, &commit(&g, 2, vec![streaky])),
        Err(CommitError::Streak)
    );
}

/// The `t` of proposals' posts and the starter of the epoch (12.3, 12.7).
#[test]
fn epoch_state() {
    let mut state = EpochState::created();
    assert_eq!(state.started_by, None);
    state.note_proposal(&[1; 48], T);
    state.note_proposal(&[1; 48], T + 1);
    let post = state.post(T + 5, None);
    assert_eq!(post.proposal_time(&[1; 48]), Some(T));
    assert_eq!(post.proposal_time(&[2; 48]), None);
    let state = EpochState::started_by(idx(3));
    assert_eq!(state.started_by, Some(3));
    assert!(state.proposal_times.is_empty());
    let g = group(&room(ConversationKind::PrivateRoom));
    assert_eq!(g.expected_streak(&uid("p@x.org")), 1);
}

/// Facts for the key checks of removals.
struct Facts {
    removed: &'static [&'static str],
    retired: &'static [&'static str],
    forked: &'static [&'static str],
    current: bool,
    unknown: bool,
}

impl Facts {
    fn none() -> Facts {
        Facts {
            removed: &[],
            retired: &[],
            forked: &[],
            current: true,
            unknown: false,
        }
    }

    fn fact(&self, value: bool) -> Fact<bool> {
        if self.unknown {
            Fact::Unknown
        } else {
            Fact::Known(value)
        }
    }
}

impl KeyFacts for Facts {
    fn current_device_key(&self, _: &Uid, _: &DeviceId) -> Fact<Option<Vec<u8>>> {
        if self.unknown {
            return Fact::Unknown;
        }
        Fact::Known(self.current.then(|| vec![1]))
    }

    fn device_removed(&self, uid: &Uid, _: &DeviceId) -> Fact<bool> {
        self.fact(self.removed.contains(&uid.as_str()))
    }

    fn identity_retired(&self, uid: &Uid) -> Fact<bool> {
        self.fact(self.retired.contains(&uid.as_str()))
    }

    fn forked_or_missing(&self, uid: &Uid) -> Fact<bool> {
        self.fact(self.forked.contains(&uid.as_str()))
    }
}

/// The key checks of removals for a check (12.7): a reason the device can
/// see, or a removal it could not check; only for its own identity's leaf
/// can it find the removal failed.
#[test]
fn key_checks_of_removals() {
    let g = group(&room(ConversationKind::PrivateRoom));
    // Leaf 2 (p) removes o's leaf for a check.
    let c = commit(&g, 2, remove(&[0]));
    let verdict = check(&g, &c).unwrap();
    let as_m = uid("m@x.org");
    let seen = Seen {
        own_uid: &as_m,
        resyncs: &[],
        impostors: &[],
    };
    // No reason m can see: it stands, with a warning naming p.
    let report = key_checks(&g, &c, &verdict, &Facts::none(), &seen);
    assert_eq!(report.unexplained_removals, vec![idx(0)]);
    assert!(report.failed_removals.is_empty());
    // A reason: removed by record, retired, forked or keys missing (which
    // never "fail"), a RESYNC m read, or an impostor to m.
    for facts in [
        Facts {
            removed: &["o@x.org"],
            ..Facts::none()
        },
        Facts {
            retired: &["o@x.org"],
            ..Facts::none()
        },
        Facts {
            forked: &["o@x.org"],
            ..Facts::none()
        },
    ] {
        assert_eq!(
            key_checks(&g, &c, &verdict, &facts, &seen),
            KeyReport::default()
        );
    }
    for (resyncs, impostors) in [(&[idx(0)][..], &[][..]), (&[][..], &[idx(0)][..])] {
        let seen = Seen {
            own_uid: &as_m,
            resyncs,
            impostors,
        };
        assert_eq!(
            key_checks(&g, &c, &verdict, &Facts::none(), &seen),
            KeyReport::default()
        );
    }
    // o's own device knows: its device is current and o is neither forked
    // nor missing its keys, so the removal failed, and it adds the device
    // again.
    let as_o = uid("o@x.org");
    let own = Seen {
        own_uid: &as_o,
        resyncs: &[],
        impostors: &[],
    };
    let report = key_checks(&g, &c, &verdict, &Facts::none(), &own);
    assert_eq!(report.failed_removals.len(), 1);
    // Not if o is forked, nor if the device is no longer current.
    let forked = Facts {
        forked: &["o@x.org"],
        ..Facts::none()
    };
    assert_eq!(
        key_checks(&g, &c, &verdict, &forked, &own),
        KeyReport::default()
    );
    let gone = Facts {
        current: false,
        ..Facts::none()
    };
    assert_eq!(
        key_checks(&g, &c, &verdict, &gone, &own),
        KeyReport::default()
    );
    // Unknown for now: checked again later.
    let unknown = Facts {
        unknown: true,
        ..Facts::none()
    };
    let report = key_checks(&g, &c, &verdict, &unknown, &own);
    assert_eq!(report.unchecked_removals, vec![idx(0)]);
    assert!(report.committer_unchecked);
    // A committer whose device was removed by record is an impostor.
    let c = commit(&g, 0, vec![]);
    let removed = Facts {
        removed: &["o@x.org"],
        ..Facts::none()
    };
    let report = key_checks(&g, &c, &check(&g, &c).unwrap(), &removed, &seen);
    assert!(report.committer_removed);
    // Public rooms have no key checks.
    let public = group(&room(ConversationKind::PublicRoom));
    let c = commit(&public, 0, vec![]);
    assert_eq!(
        key_checks(&public, &c, &Verdict::default(), &removed, &seen),
        KeyReport::default()
    );
}

/// A device that sees a leaf of its own identity remove another of its
/// identity's current devices, without adding it again, tells the user
/// (12.7).
#[test]
fn own_identity_removals() {
    let g = group(&room(ConversationKind::PrivateRoom));
    let c = commit(&g, 2, remove(&[3]));
    let verdict = check(&g, &c).unwrap();
    let as_p = uid("p@x.org");
    let seen = Seen {
        own_uid: &as_p,
        resyncs: &[],
        impostors: &[],
    };
    let report = key_checks(&g, &c, &verdict, &Facts::none(), &seen);
    assert_eq!(report.own_removed_by_own, vec![idx(3)]);
    let gone = Facts {
        current: false,
        ..Facts::none()
    };
    assert!(
        key_checks(&g, &c, &verdict, &gone, &seen)
            .own_removed_by_own
            .is_empty()
    );
    let as_m = uid("m@x.org");
    let other = Seen {
        own_uid: &as_m,
        ..seen
    };
    assert!(
        key_checks(&g, &c, &verdict, &Facts::none(), &other)
            .own_removed_by_own
            .is_empty()
    );
}

fn crowd(conv: &RisalaConversation, identities: u32, per: u32) -> GroupView {
    let mut leaves = vec![leaf(0, "o@x.org", T)];
    for i in 1..identities {
        for j in 0..per {
            let mut l = leaf(i * per + j, &format!("u{i}@x.org"), T);
            l.identity = Some(RisalaIdentity::device(
                l.uid().unwrap().clone(),
                DeviceId::from_bytes([j as u8; 48]),
            ));
            leaves.push(l);
        }
    }
    view(conv, leaves)
}

#[test]
fn limits() {
    let conv = room(ConversationKind::PrivateRoom);
    // 256 identities while pairwise is fine, 257 is not (6.2, 12.7).
    let g = crowd(&conv, 256, 1);
    assert!(check(&g, &commit(&g, 0, vec![])).is_ok());
    let g = crowd(&conv, 257, 1);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::TooLarge)
    );
    // Whoever takes it past 256 moves it to epochal (6.2): a plain member
    // may, in that commit.
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
    // A direct conversation holds at most 128 leaves (12.7).
    let direct = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("o@x.org"),
        &uid("u1@x.org"),
    );
    let g = crowd(&direct, 2, 127);
    assert_eq!(g.leaves.len(), 128);
    assert!(check(&g, &commit(&g, 0, vec![])).is_ok());
    let g = crowd(&direct, 2, 128);
    assert_eq!(
        check(&g, &commit(&g, 0, vec![])),
        Err(CommitError::TooLarge)
    );
}

#[test]
fn joining() {
    let conv = room(ConversationKind::PrivateRoom);
    let expect = JoinExpectation {
        host: "h.org".parse().unwrap(),
        own_uid: uid("p@x.org"),
        public_room: None,
    };
    let g = group(&conv);
    assert_eq!(check_join(&g, &expect), Ok(()));
    let mut other_host = expect.clone();
    other_host.host = "x.org".parse().unwrap();
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
    let report = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("~sam"),
        &uid("p@x.org"),
    );
    let mut r = view(&report, vec![leaf(0, "~sam", T), leaf(1, "p@x.org", T)]);
    r.leaves[0].profile = None;
    assert_eq!(check_join(&r, &expect), Ok(()));
    r.leaves.push(leaf(2, "~sam", T));
    assert_eq!(check_join(&r, &expect), Err(JoinError::Guest));
}

/// In a guest's report conversation, the guest's leaf's commits have no
/// profile to check (12.7).
#[test]
fn report_conversations() {
    let report = RisalaConversation::direct(
        "h.org".parse().unwrap(),
        [0; 16],
        &uid("~sam"),
        &uid("p@x.org"),
    );
    let mut g = view(&report, vec![leaf(0, "~sam", T), leaf(1, "p@x.org", T)]);
    g.leaves[0].profile = None;
    let mut c = commit(&g, 0, vec![]);
    c.path_leaf.as_mut().unwrap().profile = None;
    assert!(check(&g, &c).is_ok());
}

/// Device-side helpers (12.7): the clock warning, and the leaves of its own
/// identity a device must replace.
#[test]
fn device_helpers() {
    assert!(!clock_disagrees(T, T + HOUR));
    assert!(clock_disagrees(T, T + HOUR + 1));
    assert!(clock_disagrees(T + HOUR + 1, T));
    let conv = room(ConversationKind::PrivateRoom);
    let mut g = group(&conv);
    g.leaves[3].profile = Some(RisalaProfile::new("", T - 9 * DAY).unwrap());
    let p = uid("p@x.org");
    // Retention of 7 days: older than 8 days goes.
    assert_eq!(
        own_leaves_to_replace(&g, &p, idx(2), 7 * DAY, T),
        vec![idx(3)]
    );
    assert!(own_leaves_to_replace(&g, &p, idx(2), 8 * DAY, T).is_empty());
    // Its own leaf never.
    assert!(own_leaves_to_replace(&g, &p, idx(3), 7 * DAY, T).is_empty());
    // A leaf that never committed counts its KeyPackage's lifetime end.
    g.leaves[3].from_key_package = true;
    g.leaves[3].lifetime_end = Some(T + DAY);
    assert!(own_leaves_to_replace(&g, &p, idx(2), 7 * DAY, T).is_empty());
    // Not in public rooms, where the device joins again by itself.
    let mut public = group(&room(ConversationKind::PublicRoom));
    public.leaves[3].profile = Some(RisalaProfile::new("", T - 9 * DAY).unwrap());
    assert!(own_leaves_to_replace(&public, &p, idx(2), 7 * DAY, T).is_empty());
}
