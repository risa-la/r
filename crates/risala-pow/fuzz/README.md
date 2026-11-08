# risala-pow fuzz targets

These are [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for
`risala-pow`.

| Target | Input                                                          |
|--------|----------------------------------------------------------------|
| `jit`  | a seed and up to 16 nonces: each nonce must hash the same with the JIT as with the interpreter, on a fresh scratchpad and on one reused across nonces, and through a clone of the compiled function |

On a platform without the JIT, both functions are interpreted, and the
target checks nothing useful. The JIT runs on x86-64 and aarch64 Linux,
Android and macOS.

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

### The aarch64 JIT under qemu

On x86-64, the target can be built for aarch64 Linux and run under
qemu-user. It needs a toolchain with the `aarch64-unknown-linux-gnu`
target and an aarch64 cross compiler for libFuzzer's C++ (from Nix,
`nixpkgs#pkgsCross.aarch64-multiplatform.stdenv.cc`):

```sh
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-unknown-linux-gnu-g++
RUSTC_BOOTSTRAP=1 cargo fuzz build --target aarch64-unknown-linux-gnu --sanitizer none jit
qemu-aarch64 fuzz/target/aarch64-unknown-linux-gnu/release/jit fuzz/corpus/jit -max_total_time=600
```

It runs some 150 inputs a second there, against thousands natively.

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
