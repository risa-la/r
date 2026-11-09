# Verification

The tools behind the site's verification page,
[risa.la/verification](https://risa.la/verification). The page lists
every source file of the Rust crates (except the vendored
`openmls` and `openmls-traits`) and of the Apple client. Beside each line it shows
every kind of evidence that reaches it, one narrow column each:

| Column | Evidence |
|---|---|
| unit | the tests in each crate's `src/`, property tests included; for Swift, the Apple client's tests |
| integration | each crate's `tests/`, the spec example and transcript tests included |
| fuzz | the fuzz targets whose corpus runs the line |
| Kani | the Kani proofs that reach the line |
| TLA+ | the line is in a function whose comments cite a spec section a TLA+ model covers |

A line nothing reaches is tinted red. Test code (`tests/`,
`#[cfg(test)]` modules, fuzz targets, Kani proofs) is listed but left
out of the percentages.

The front page leads with one number: the share of code lines that a
unit test, integration test, fuzz input or Kani proof reaches. Below it,
each kind of evidence opens on its tests, targets, proofs or model runs,
and each crate opens on its files.

`/verification/spec` lists each section of the spec with its evidence:
the example lines the tests parse, the TLA+ model, the Kani proofs that
restate its rules, and the code that cites it. Its number is the share of
sections without subsections that a test, example line, proof or model
covers; citations in code alone do not count.

## What each kind of evidence proves

Each one shows less than it may seem to.

- **Tests.** Coverage says a line ran during a test, not that the test
  checked what it did. A covered line can still be wrong. The page also
  shows how many tests passed and failed.
- **Fuzzing.** A fuzz target runs random inputs through the code and
  checks that it does not panic, plus its own checks: what a parser
  parses serialises and parses again to the same value, and the JIT
  agrees with the interpreter. The column shows what
  the corpus found so far reaches. That depends on how long each target
  has been fuzzed, which the page states. The targets run without
  AddressSanitizer.
- **Kani.** A Kani proof checks a property for every input within
  bounds, such as every name of a few bytes. It proves nothing beyond
  those bounds. Kani's source coverage is unstable: where it gives
  nothing, a proof marks the whole of each function it calls, and the
  page labels those marks function-level. Proofs that fail or time out
  mark nothing.
- **TLA+.** The models in [`proofs/`](../proofs/README.md) check the
  spec, not the code, and only within small bounds. They model draft-03,
  the spec in `spec/`. A mark in the TLA+ column only says the function
  cites a section that a model covers. The model `AsWritten.cfg` is
  expected to find a violation: that is how the findings in
  `proofs/README.md` were found.
- **Spec sections.** The spec view shows only the latest spec, in
  `spec/`. A comment in the code that names a section, such as `(7.1)`,
  `(12.10, D.4)`, `(B.1 to B.10)` or `Section 13`, is read as that spec's
  section, and so are the sections in a Kani proof's doc comment. A whole
  number counts only for a section with no subsections, such as `(11)`,
  and a group of whole numbers alone only when nothing else is in its
  parentheses, so `(2 bytes)` cites nothing. A TLA+ model counts, in the
  spec view and in the TLA+ column, only if it models the same draft as
  `spec/`, since drafts number their sections differently. The model of
  draft-02 is kept in `proofs/archive/` and is not listed.
- **Filled lines.** In the source listing, lines inside a function that
  are not code (braces, `} else {`, comments, blank lines) are drawn
  like the code around them, so that a function reads as one block.
  They are never counted, and the details for such a line say so.

## How the data flows

1. `collect.sh` runs one tool and writes its raw output to
   `$VERIFY_RAW` (default `target/verification/raw`), one folder per
   step: `tests/`, `fuzz/`, `kani/`, `tla/`, `swift/`.
2. In CI, the Verification workflow
   ([`verification.yml`](../.github/workflows/verification.yml)) runs
   each step in its own job, on pushes to main and nightly. Its last job
   puts the folders together with `meta.json` (the commit and the run)
   and uploads them as the `verification-raw` artifact.
3. The site build ([`site.yml`](../.github/workflows/site.yml))
   downloads the newest `verification-raw` from a successful run on
   main and checks out that run's commit beside the site, so that line
   numbers match. It never runs the tools.
4. `assemble.ts` turns the raw results into
   `site/public/verification-data/`: `summary.json`, `spec.json`, and
   one JSON file per source file with its text and, per line, what
   reaches it. The site's `prebuild` and `predev` scripts run it, with
   `VERIFY_ROOT` (the verified sources) and `VERIFY_RAW`.
5. The React pages under `/verification` fetch those files and
   highlight the code in the browser.

Any part of the raw results may be missing. That kind of evidence is
then marked as having no results, and with none at all the page says so.

## Running it locally

Each step is heavy. Run one at a time, from the dev shell
(`nix develop`), from the repository root:

The coverage steps (`tests` and `fuzz-cover`) need a Rust whose
coverage runtime matches its LLVM. nixpkgs' rustc does not have one: it
builds code with LLVM 21 but ships a runtime from a newer LLVM, and
every instrumented test binary then crashes on exit, while it writes
its profile. Use a rustup toolchain with its LLVM tools for those two
steps. The dev shell still supplies the native libraries:

```
rustup toolchain install stable --profile minimal --component llvm-tools
export COVERAGE_TOOLCHAIN=$(rustup run stable rustc --print sysroot)
```

```
verification/collect.sh tests            # unit, then integration tests, with coverage
verification/collect.sh fuzz-run 60      # fuzz each target for 60 seconds
verification/collect.sh fuzz-cover       # the coverage of each corpus
verification/collect.sh tla              # TLC, a few minutes (at most 40)
```

The fuzz corpus lives in `crates/<crate>/fuzz/corpus/`, which git
ignores, with `stats.json` beside it: how long each target has been
fuzzed.

Kani is not in nixpkgs. Install it as the
[README](../README.md#model-checking-with-kani) describes, at the
version CI uses:

```
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
```

Then, with `cargo-kani` on `PATH`, run `verification/collect.sh kani`.
`KANI_JOBS` (default 2) and `KANI_TIMEOUT` (default `2m`) set the
parallel proofs and each proof's time limit.

The Apple client's step needs a Mac with Xcode:
`verification/collect.sh swift`.

Then build the page's data and look at it:

```
node verification/assemble.ts
cd site && npm run dev
```

## Testing the assembler

`lib.ts` holds the parts of `assemble.ts` that read each tool's output.
Its tests run on Node 24, which runs TypeScript directly:

```
node --test verification/lib.test.ts
```

## Adding to it

[`config.json`](config.json) tells `assemble.ts` what to list.
`collect.sh` has its own lists of what to run. Change both:

- **A fuzz target:** add `crate:target` to `FUZZ_TARGETS` in
  `collect.sh`, and the target under its crate in `config.json`'s
  `fuzz`. For a crate with no fuzz targets yet, also add its
  `crates/<crate>/fuzz/corpus` to the two cache steps of the `fuzz` job
  in `verification.yml`.
- **A crate with Kani proofs:** add it to `KANI_CRATES` in `collect.sh`
  and to `config.json`'s `kani`.
- **A TLA+ model, or a configuration of one:** add the folder, the
  `.cfg` and a time limit in seconds to `runs` in `collect.sh`'s
  `step_tla`. In `config.json`'s `tla.models`, add the model with the
  spec sections it covers, and each run with what TLC should find
  (`pass` or `violation`) and what the run means. The model's folder
  under `proofs/` is its `id`.
