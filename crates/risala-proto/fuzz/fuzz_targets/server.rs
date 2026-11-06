//! Lines into `server::ServerMessage::parse` (SPEC 4-11, 12).
//!
//! Whatever parses must serialise with `to_line` into a line that parses
//! back to the same message, both directly and through its wire form.

#![no_main]

use libfuzzer_sys::fuzz_target;
use risala_proto::line::Line;
use risala_proto::server::ServerMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(line) = Line::parse(s) else {
        return;
    };
    let Ok(message) = ServerMessage::parse(&line) else {
        return;
    };
    let out = message.to_line();
    let again = ServerMessage::parse(&out).unwrap_or_else(|e| panic!("{out} from {s:?}: {e}"));
    assert_eq!(again, message, "{s:?}");

    let wire = out.to_string();
    let reparsed = Line::parse(&wire).unwrap_or_else(|e| panic!("{wire:?} from {s:?}: {e}"));
    assert_eq!(
        ServerMessage::parse(&reparsed).as_ref(),
        Ok(&message),
        "{wire:?}"
    );
});
