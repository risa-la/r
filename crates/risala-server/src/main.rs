//! `risalad`, the risala server.
//!
//! Work starts in milestone M2 (see PLAN.md). For now this only proves the
//! workspace builds and links against `risala-proto`.

fn main() {
    println!(
        "risalad {} (protocol version {}): not implemented yet",
        env!("CARGO_PKG_VERSION"),
        risala_proto::PROTOCOL_VERSION
    );
}
