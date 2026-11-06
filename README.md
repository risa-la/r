# risala

risala is a chat protocol for independent servers, made of plain UTF-8
text lines over TLS. Think "modern IRC": rooms, guests and a terminal
you can type into, plus stored history, portable identities, replies,
edits, reactions, file sharing and push notifications.

```
$ openssl s_client -connect chat.example.org:7472 -quiet
RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!
guest sam
OK uid=~sam
join #general
@seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general
SET #general topic General chat. Be kind.
SET #general public yes
SET #general guests write
SET #general retention server
OK id=k3f9q2 head=8812
msg #general hello!
@seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam MSG #general hello!
OK seq=8813
```

- **Usable by hand.** Every feature works from `openssl s_client`.
- **Small.** A complete client or server is realistic to write in Go,
  Rust or C.
- **Independent servers.** No federation, and no server is special.
  Every conversation lives on exactly one server.
- **Portable identity.** `alice@example.org` is whoever holds a key
  listed at `https://example.org/.well-known/risala/alice`. The same
  identity works on any server.
- **History.** Every event has a sequence number, so a client that
  reconnects fetches exactly what it missed.
- **No end-to-end encryption** in this version. The server can read
  everything.

The protocol is defined in [SPEC.md](SPEC.md) (draft-01). Anything in it
may still change.

## This repository

This repository holds the spec and a reference implementation in Rust.
It is at an early stage. [PLAN.md](PLAN.md) describes what will be built
and in what order.

| Part | Language | What it is |
|---|---|---|
| `risalad` | Rust | The server |
| `librisala` | Rust | The shared client library: connection, identity, sync, history cache, rooms, messages, moderation |
| GNOME app | Rust, gtk4-rs, libadwaita | Linux client |
| Apple app | Swift, SwiftUI | macOS and iOS client |
| Android app | Kotlin | Android client |

The apps hold no protocol logic. They show what librisala gives them.
The Apple and Android apps call librisala through generated bindings,
and the GNOME app uses it directly.

There is no browser client, by design.

## Development

The development environment is a Nix flake (using flake-parts):

```
nix develop          # Rust toolchain, SQLite, OpenSSL, GTK 4, libadwaita
nix fmt              # format Nix files
nix build .#risalad  # build the server into ./result
nix flake check      # fmt, clippy, tests, REUSE and Nix formatting, as CI runs them
```

Inside `nix develop`, the usual cargo commands work:

```
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

## Trying a server by hand

[Appendix A of the spec](SPEC.md#appendix-a-using-risala-by-hand) shows
how to connect, check a server's fingerprint, make a key and sign in
with nothing but `openssl`.

## License

Copyright (c) 2026 Risala developers.

The protocol specification ([SPEC.md](SPEC.md)) is licensed under
[CC BY 4.0](LICENSES/CC-BY-4.0.txt). The code and everything else are
licensed under the [Apache License 2.0](LICENSES/Apache-2.0.txt). The
repository follows the [REUSE](https://reuse.software) specification;
see [`REUSE.toml`](REUSE.toml).
