# risala

risala is a modern chat protocol for independent servers. Every
conversation is end-to-end encrypted, public rooms included, and the
server is trusted with as little as possible: it carries encrypted
messages without learning who sent them, and keeps no history.

- **Zero trust in the server.** Devices check membership, roles and
  keys themselves, and never take the server's word for whose keys are
  whose. What a server can still do is listed in the spec.
- **Everything encrypted.** Direct conversations, private rooms and
  public rooms all use MLS, with a new key for every message.
- **Deniable.** A message that leaks does not prove to anyone else who
  wrote it.
- **Little metadata.** Devices post without signing in, so the server
  does not learn who sends a message, or who is in a direct
  conversation or a private room. It still sees network addresses and
  timing, and the members of public rooms.
- **No history on the server.** Encrypted messages wait only until
  devices have had time to fetch them. History moves between your own
  devices, and into an optional backup that only your recovery key
  opens.
- **Portable identity, witnessed keys.** `alice@example.org` is whoever
  controls the key file at `https://example.org/.well-known/risala/alice`.
  Every key is also in a transparency log checked by public witnesses,
  and no operator can reset an identity.
- **Post-quantum.** Hybrid ML-KEM in TLS, X-Wing in MLS, and ML-DSA
  signatures.
- **Independent servers and large rooms.** No federation, and no server
  is special. Private rooms hold up to 1,000 members and public rooms up
  to 10,000, with guests.

The protocol is defined in the spec ([`spec/`](spec/)), now at draft-03.
Anything in it may still change. The code here follows draft-03
(PLAN.md, M5b). Its new constructions, such as deniable leaf
confirmation, epochal signatures and send tokens, have not been
reviewed yet.

## This repository

This repository holds the spec and a reference implementation in Rust.
It is at an early stage. [PLAN.md](PLAN.md) describes what will be built
and in what order.

| Part | Language | What it is |
|---|---|---|
| `risala-proto` | Rust | The protocol's lines, names and keys, with no I/O |
| `risalad` | Rust | The server (`crates/risala-server`) |
| `risala-keyfetch` | Rust | Fetches key files over HTTPS for the server (spec 4.4) |
| `librisala` | Rust | The shared client library: connection, identity, sync, history cache, rooms, messages, moderation |
| `risala-cli` | Rust | A small, scriptable terminal client, built on librisala |
| `risala-dev` | Rust | A local server with its key log and a witness, for the apps, the CLI and tests |
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

### Development server

`risala-dev` runs a local `risalad` named `chat.test` that hosts
identities at `example.org`, keeps their key log, witnesses it, and
serves the log, key files, files and blobs over HTTPS. Run it from the
repository root:

```
nix run .#dev                    # or: cargo run -p risala-dev
nix run .#dev -- --reset         # delete the state and start again
```

State lives in `.dev/`, which git ignores: the database, the test CA and
certificates, and `.dev/cli-args`, the options that point `risala` at
the server (where it listens, its fingerprint, the CAs, the names and the
witness). The chat server listens on `127.0.0.1:7473`, HTTPS on 7474.
For example, two people talking:

```
A=$(cat .dev/cli-args)
risala --state /tmp/alice $A --short-waits create chat.test alice laptop
risala --state /tmp/bob $A --short-waits create chat.test bob laptop
risala --state /tmp/alice $A --short-waits send bob@example.org hello
risala --state /tmp/bob $A --short-waits read alice@example.org --sync
risala --state /tmp/alice $A --short-waits room create garden
risala --state /tmp/alice $A --short-waits room invite '#garden' bob@example.org
risala --state /tmp/alice $A --short-waits send '#garden' welcome
```

A uid names only the direct conversation with that identity, and `send`
starts it if there is none; rooms are named `#name` (quoted, for the
shell) or by their number from `risala list`. `list` prints each
conversation's number, kind, name, unread count and state: `active`,
`joining`, `leaving`, `lost` (posts expired before the device read them)
or `left`.

`--short-waits` cuts the protocol's random waits of up to 10 minutes to a
second. It, `--ca` and `--resolve` weaken what the client checks or
hides, so each run that has them prints a warning.

The witness policy is kept in the state directory. `--witness` from
`.dev/cli-args` saves it when `create`, `pair new` or `recover` sets up a
new state directory; after that the option must match it, and only
`risala witness set` or `risala witness clear` change it (`risala witness
show` prints it). risala-dev's witness key comes from a fixed seed, so
`risala` warns on every run while the policy names it.

Commands that send stay connected until what they sent has reached the
server, for at most `--wait` seconds (20 by default), and exit with 1 if
it has not; it goes out on the next run. A message held by its
conversation is not a failure: while sending in a group is held (12.7),
as when a new device's key check waits up to 2 hours for its key file,
`risala send` exits with 0 and says on standard error that the message
is queued, and why. It goes out on a later run once the hold ends.

M5a's seeded scenarios talked in plain text, which the current protocol
has no commands for; they come back once rebuilt on librisala.

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

**Connecting.** Clients need TLS 1.3 with the post-quantum key exchange
X25519MLKEM768 (Section 2.1 of the spec). Today's `risalad` speaks
draft-03, and `risala-cli` is the client to use with it. To look at a
server from a terminal, `openssl` 3.5 or later works:

```
openssl s_client -connect localhost:7472 -quiet
```

Then type `info`.
[Section 13 of the spec](spec/13-command-summary.md) lists every
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
[Appendix A of the spec](spec/a-checking-a-server-by-hand.md) shows the
same check.

## Contributing and security

Bug reports, questions and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as
described in [SECURITY.md](SECURITY.md).

## License

Copyright (c) 2026 Risala developers.

The protocol specification (the spec, [`spec/`](spec/)) is licensed under
[CC BY 4.0](LICENSES/CC-BY-4.0.txt). The code and everything else are
licensed under the [Apache License 2.0](LICENSES/Apache-2.0.txt). The
repository follows the [REUSE](https://reuse.software) specification;
see [`REUSE.toml`](REUSE.toml).
