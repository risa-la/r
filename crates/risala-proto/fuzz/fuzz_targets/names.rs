//! Strings into every `FromStr` of the name, value and key types (SPEC
//! 2.2, 3.4, 3.5, 4.4, 4.5, 5.3, 5.7, 6.2, 7.2, 10.2, 10.6, 12), and into
//! the text functions (3.4, 5.5).
//!
//! Whatever parses must display as a string that parses back to the same
//! value and displays the same again.

#![no_main]

use std::fmt::{Debug, Display};
use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use risala_proto::auth::{Nonce, PublicKey, Signature};
use risala_proto::error::ErrorCode;
use risala_proto::fingerprint::Fingerprint;
use risala_proto::frame::check_line;
use risala_proto::keyfile::KeyEntry;
use risala_proto::mls::{
    BackupBlob, Ciphertext, CommitMessage, Content, Frank, FrankKey, GroupInfo, KeyPackage,
    RatchetTree, Welcome, is_strict_base64,
};
use risala_proto::names::{
    BlockTarget, Conv, Domain, Id, Identity, IpPrefix, Name, Room, Seq, ServerBanTarget, Uid,
};
use risala_proto::text::{escape, mentions, unescape};
use risala_proto::time::Timestamp;
use risala_proto::types::{
    Cid, GuestAccess, HistoryMode, HistoryOnly, InfoRole, Presence, PushReason, PushTag, Ref,
    Relation, Role, RoomRetention, RoomSetting, ServerRetention, ServerSetting, parse_u64,
    parse_yes_no,
};

fn round_trip<T>(s: &str)
where
    T: FromStr + Display + PartialEq + Debug,
    T::Err: Display,
{
    let Ok(value) = s.parse::<T>() else {
        return;
    };
    let shown = value.to_string();
    let again: T = shown
        .parse()
        .unwrap_or_else(|e| panic!("{shown:?} from {s:?}: {e}"));
    assert_eq!(again, value, "{s:?}");
    assert_eq!(again.to_string(), shown, "{s:?}");
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let s = s.as_ref();

    round_trip::<Name>(s);
    round_trip::<Domain>(s);
    round_trip::<Uid>(s);
    round_trip::<Identity>(s);
    round_trip::<Room>(s);
    round_trip::<Conv>(s);
    round_trip::<Seq>(s);
    round_trip::<Id>(s);
    round_trip::<BlockTarget>(s);
    round_trip::<IpPrefix>(s);
    round_trip::<ServerBanTarget>(s);
    round_trip::<Timestamp>(s);

    round_trip::<Role>(s);
    round_trip::<InfoRole>(s);
    round_trip::<GuestAccess>(s);
    round_trip::<PushReason>(s);
    round_trip::<Presence>(s);
    round_trip::<RoomRetention>(s);
    round_trip::<ServerRetention>(s);
    round_trip::<Relation>(s);
    round_trip::<Ref>(s);
    round_trip::<Cid>(s);
    round_trip::<PushTag>(s);
    round_trip::<RoomSetting>(s);
    round_trip::<ServerSetting>(s);
    round_trip::<ErrorCode>(s);
    round_trip::<HistoryMode>(s);
    round_trip::<HistoryOnly>(s);

    round_trip::<KeyPackage>(s);
    round_trip::<GroupInfo>(s);
    round_trip::<CommitMessage>(s);
    round_trip::<Welcome>(s);
    round_trip::<RatchetTree>(s);
    round_trip::<Ciphertext>(s);
    round_trip::<Content>(s);
    round_trip::<Frank>(s);
    round_trip::<FrankKey>(s);
    round_trip::<BackupBlob>(s);
    // Strict base64 is exactly what the standard decoder accepts and
    // encodes back unchanged.
    if let Ok(blob) = s.parse::<KeyPackage>() {
        assert!(is_strict_base64(s));
        assert_eq!(KeyPackage::from_bytes(&blob.decode()).as_ref(), Ok(&blob));
    }

    round_trip::<PublicKey>(s);
    round_trip::<Signature>(s);
    round_trip::<Nonce>(s);
    round_trip::<Fingerprint>(s);
    round_trip::<KeyEntry>(s);

    let _ = Seq::parse_or_zero(s);
    let _ = Room::from_bare(s);
    if let Ok(n) = parse_u64(s) {
        assert_eq!(n.to_string(), s);
    }
    let _ = parse_yes_no(s);

    // Text (3.4) and mentions (5.5).
    let escaped = escape(s);
    assert_eq!(check_line(&escaped), Ok(()));
    let unescaped = unescape(s);
    assert!(unescaped.len() <= s.len());
    let folded = unescaped.to_ascii_lowercase();
    let found = mentions(s);
    for (i, uid) in found.iter().enumerate() {
        assert!(!found[..i].contains(uid), "{uid} twice in {s:?}");
        assert!(folded.contains(&format!("@{uid}")), "{uid} not in {s:?}");
    }
});
