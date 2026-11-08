# risala-pow fuzz targets

These are [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for
`risala-pow`.

| Target | Input                                                          |
|--------|----------------------------------------------------------------|
| `jit`  | a seed and up to 16 nonces: each nonce must hash the same with the JIT as with the interpreter, on a fresh scratchpad and on one reused across nonces, and through a clone of the compiled function |

On a platform without the JIT, both functions are interpreted, and the
target checks nothing useful.

## Running

`cargo-fuzz` is in the dev shell. It needs nightly; on a stable toolchain,
set `RUSTC_BOOTSTRAP=1`. The Rust in the Nix dev shell has no
AddressSanitizer runtime, so add `--sanitizer none`. Run from
`crates/risala-pow`:

```sh
nix develop
RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none jit -- -max_total_time=300
```

Crashes go to `fuzz/artifacts/jit/`, and the corpus grows in
`fuzz/corpus/jit/`. Both are ignored by git. To replay a crash, pass its
file:

```sh
RUSTC_BOOTSTRAP=1 cargo fuzz run --sanitizer none jit fuzz/artifacts/jit/crash-...
```

## Layout

This directory is its own Cargo workspace, like `crates/risala-proto/fuzz`.
The main workspace excludes it, so `cargo build`, `cargo test` and
`cargo clippy` at the repository root never build it. It has its own
`Cargo.lock`, committed here, which started from the root lock file.

To check that the target compiles without fuzzing:

```sh
cd crates/risala-pow/fuzz
RUSTC_BOOTSTRAP=1 cargo check --bins
```
