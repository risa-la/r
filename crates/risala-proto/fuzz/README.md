# risala-proto fuzz targets

These are [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for
`risala-proto`. Every target that parses something also serialises it,
parses it again and checks that the value is the same.

| Target    | Input                                                        |
|-----------|--------------------------------------------------------------|
| `frame`   | bytes into `LineDecoder`, with and without the long limit of MLS lines and either direction's long verbs, in several chunk splits, then each line into `Line::parse` |
| `keyfile` | text into `KeyFile::parse`. `$` and the byte after it become a real key |
| `names`   | a string into every name, value, key and MLS value `FromStr`, `Timestamp`, and the text functions |
| `client`  | a line into `command::Request::parse`                        |
| `server`  | a line into `server::ServerMessage::parse`                   |

## Running

`cargo-fuzz` is in the dev shell. Run from `crates/risala-proto`:

```sh
nix develop
cargo fuzz run frame
```

cargo-fuzz needs nightly. On a stable toolchain, set `RUSTC_BOOTSTRAP=1`:

```sh
RUSTC_BOOTSTRAP=1 cargo fuzz run frame -- -max_total_time=60
```

The Rust in the Nix dev shell has no AddressSanitizer runtime, so linking
fails with the default sanitizer. Add `--sanitizer none`. The crate has
no unsafe code, so the sanitizer would add little:

```sh
RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none frame -- -max_total_time=60
```

Use the same command for `keyfile`, `names`, `client` and `server`. Use
`cargo fuzz list` to see the targets.

Crashes go to `fuzz/artifacts/<target>/`, and the corpus grows in
`fuzz/corpus/<target>/`. Both are ignored by git. To replay a crash, pass
its file:

```sh
RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none frame fuzz/artifacts/frame/crash-...
```

To shrink it, use `cargo fuzz tmin` with the same arguments.

## Layout

This directory is its own Cargo workspace. The main workspace excludes
it, so `cargo build`, `cargo test` and `cargo clippy` at the repository
root never build it. It has its own `Cargo.lock`, committed here. Update
it from this directory with `cargo update`. It started from the root
lock file, so `risala-proto`'s dependencies are at the same versions.

To check that the targets compile without fuzzing:

```sh
cd crates/risala-proto/fuzz
RUSTC_BOOTSTRAP=1 cargo check --bins
```
