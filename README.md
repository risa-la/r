# risala

risala is a chat protocol for independent servers, made of plain UTF-8
text lines over TLS. Think "modern IRC": rooms, guests and a terminal
you can type into, plus stored history, portable identities, replies,
edits, reactions, file sharing, push notifications and end-to-end
encryption.

```
$ openssl s_client -connect chat.example.org:7472 -quiet
RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!
guest sam
OK uid=~sam token=q7m2x9k4b8n1v5c3z6l0w2e4r7t9y1u3
join #general
@seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general
SET #general topic General chat. Be kind.
SET #general public yes
SET #general guests write
SET #general retention server
SET #general e2ee no
SET #general send all
OK id=k3f9q2 head=8812 role=member
msg #general hello!
@seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam MSG #general hello!
OK seq=8813
```

- **Usable by hand.** Everything outside encrypted conversations works
  from `openssl s_client`.
- **Small where it can be.** A client for public rooms needs only TLS
  and ML-DSA. Encrypted conversations need MLS.
- **Independent servers.** No federation, and no server is special.
  Every conversation lives on exactly one server.
- **Portable identity.** `alice@example.org` is whoever holds a key
  listed at `https://example.org/.well-known/risala/alice`. The same
  identity works on any server.
- **History.** Every event has a sequence number, so a client that
  reconnects fetches exactly what it missed.
- **End-to-end encrypted** direct conversations and private rooms, using
  MLS. Devices keep their history keys, so encrypted history still syncs
  and works offline.
- **Post-quantum.** Hybrid ML-KEM key exchange for TLS and MLS, and
  ML-DSA signatures.

The protocol is defined in [SPEC.md](SPEC.md) (draft-02). Anything in it
may still change.

## This repository

This repository holds the spec and a reference implementation in Rust.
It is at an early stage. [PLAN.md](PLAN.md) describes what will be built
and in what order.

| Part | Language | What it is |
|---|---|---|
| `risala-proto` | Rust | The protocol's lines, names and keys, with no I/O |
| `risalad` | Rust | The server (`crates/risala-server`) |
| `risala-keyfetch` | Rust | Fetches key files over HTTPS for the server (SPEC 4.4) |
| `librisala` | Rust | The shared client library: connection, identity, sync, history cache, rooms, messages, moderation |
| `risala-cli` | Rust | A small terminal client and key tool, built on librisala |
| [`clients/apple`](clients/apple) | Swift, SwiftUI | macOS and iOS client, just started |
| GNOME app | Rust, gtk4-rs, libadwaita | Linux client, planned |
| Android app | Kotlin | Android client, planned |

The apps hold no protocol logic. They show what librisala gives them.
The Apple and Android apps will call librisala through generated
bindings, which do not exist yet. The GNOME app will use it directly.

There is no browser client, by design.

## Development

The development environment is a Nix flake (using flake-parts):

```
nix develop          # Rust toolchain, SQLite, OpenSSL, GTK 4, libadwaita
nix fmt              # format Nix files
nix build .#risalad  # build the server into ./result
nix build .#apple-macos # cacheable Apple Release app, using the declared host Xcode
nix flake check      # fmt, clippy, tests, REUSE and Nix formatting, as CI runs them
```

Inside `nix develop`, the usual cargo commands work:

```
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

### Model checking with Kani

`risala-proto` has [Kani](https://model-checking.github.io/kani/) proofs
in `crates/risala-proto/src/proofs.rs`, plus a few at the end of
`time.rs` and `names.rs` that need private functions. Each proof checks
a property for every input within small bounds: every IP prefix and
address, every day from 1970 to 9999, every name of a few bytes. Only
proofs that finish in under a minute are kept. CI runs them in the
`kani` job.

`risala-pow` has proofs in `crates/risala-pow/src/proofs.rs`. They cover
every seed, not just small ones: every program is well formed, no
instruction can panic, scratchpad reads and writes stay in bounds, and
the puzzle's block arithmetic cannot overflow. Its JITs have more, in
`crates/risala-pow/src/jit/x86_64/proofs.rs` and
`crates/risala-pow/src/jit/aarch64/proofs.rs`, for every program, not
only those a seed can make: the code of each program fits its size
bound, so the encoder never fails or writes past its buffer; its
branches go to its own start and end; every scratchpad access the
encoder emits is masked just before, and the masks keep it in range;
and the loop test decides as the interpreter does. The JITs' encodings
are checked against independent decoders (iced-x86, yaxpeax-arm) in
their unit tests, which also run every compiled function through a
static verifier; both compilers are built and tested on any host, and
the aarch64 tests also evaluate whole compiled functions against the
interpreter. `crates/risala-pow/fuzz` fuzzes the JIT against the
interpreter.

Kani is not in nixpkgs. Its release bundle and the nightly toolchain it
downloads are ordinary Linux binaries, which run on NixOS through
nix-ld. Install them somewhere outside the repository, so nothing global
changes:

```
export CARGO_HOME=~/.cache/risala-kani/cargo
export RUSTUP_HOME=~/.cache/risala-kani/rustup
export KANI_HOME=~/.cache/risala-kani/kani-home
export PATH=$CARGO_HOME/bin:$PATH
nix shell nixpkgs#rustup -c sh -c \
  'rustup toolchain install stable --profile minimal &&
   cargo install --locked kani-verifier &&
   cargo kani setup'
```

Then, with the same variables set, from the repository root:

```
cargo kani -p risala-proto -j 2 --output-format terse -Z unstable-options --harness-timeout 2m
cargo kani -p risala-proto --harness proofs::ip_prefix_v6
cargo kani -p risala-pow -j 2 --output-format terse -Z unstable-options --harness-timeout 2m
```

The full run takes a few minutes (risala-pow's 28 proofs take under five
one at a time; the slowest about 50 seconds). Keep `-j` small: each proof runs
its own solver, which can use several gigabytes of memory, and an
unbounded `-j` can overload a machine.

### risala-pow's aarch64 JIT on x86-64

On an x86-64 machine, the aarch64 JIT runs under qemu-user. With a Rust
toolchain that has the `aarch64-unknown-linux-gnu` target, an aarch64
cross linker (from Nix, `nixpkgs#pkgsCross.aarch64-multiplatform.stdenv.cc`)
and `qemu-aarch64`:

```
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64 \
cargo test -p risala-pow --target aarch64-unknown-linux-gnu
```

The tests check that the JIT, not the interpreter, ran. Timings under
qemu mean nothing; CI runs the tests on aarch64 Linux and on macOS.

## Running a server

With no configuration, `risalad` is a development server. It listens on
port 7472, keeps its database (`risala.db`) and a generated self-signed
certificate (`selfsigned/`) in the current directory, allows guests,
and has one room, `#general`:

```
nix run .#risalad            # or, inside nix develop:
cargo run -p risala-server
```

For anything else, write a configuration file and pass it with
`--config`. Every key is optional, and an empty file gives the
development server's defaults, without `#general`. These are the main
keys:

```toml
hostname = "chat.example.org"    # the greeting's host when a client sends no SNI
listen = ["[::]:7472"]
state_dir = "/var/lib/risala"    # the database, and any generated certificate
rooms = ["#general", "#help"]    # created at startup if missing

# Without [[tls.certs]], risalad generates a self-signed certificate for
# `hostname`. Certificates are reloaded when they change on disk, and on
# SIGHUP, without dropping connections.
[[tls.certs]]
cert = "/var/lib/acme/chat.example.org/fullchain.pem"
key = "/var/lib/acme/chat.example.org/key.pem"

[server]
welcome = "Welcome!"
guests = true
retention = "forever"            # or a number of days

[limits]
sign_in_secs = 120
guest_resume_secs = 300          # how long a guest can resume; at least 120
idle_ping_secs = 120
ping_timeout_secs = 60
```

```
nix run .#risalad -- --config risalad.toml
cargo run -p risala-server -- --config risalad.toml
```

`risalad` logs to standard error. `RUST_LOG` chooses what is logged
(default `info`), for example `RUST_LOG=debug`. SIGINT and SIGTERM shut
it down cleanly: every connection gets `BYE server shutting down`.

**Connecting.** Any TLS 1.3 client with the post-quantum key exchange
X25519MLKEM768 works (Section 2.1 of the spec), such as `openssl` 3.5 or
later:

```
openssl s_client -connect localhost:7472 -quiet
```

Then type `guest sam`, `join #general` and `msg #general hello!`, as in
the session at the top of this file.
[Section 12 of the spec](SPEC.md#12-command-summary) lists every
command.

**Checking the fingerprint.** On start, `risalad` logs the fingerprint
of its certificate, in a line like this:

```
INFO risalad: certificate fingerprint=sha256:51134ecc040df4f143be34b253368e3b4400d9a557868c567a4b19413b8540f2
```

A client that sees a self-signed certificate shows the same value and
asks whether to trust it (Section 2.2 of the spec). To compute it
yourself, from anywhere:

```
openssl s_client -connect localhost:7472 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256
```

The hex digits it prints, after `sha256:`, are the fingerprint.
[Appendix A of the spec](SPEC.md#appendix-a-using-risala-by-hand) also
shows how to make a key and sign in with nothing but `openssl`.

## Contributing and security

Bug reports, questions and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).

## License

Copyright (c) 2026 Risala developers.

The protocol specification ([SPEC.md](SPEC.md)) is licensed under
[CC BY 4.0](LICENSES/CC-BY-4.0.txt). The code and everything else are
licensed under the [Apache License 2.0](LICENSES/Apache-2.0.txt). The
repository follows the [REUSE](https://reuse.software) specification;
see [`REUSE.toml`](REUSE.toml).
