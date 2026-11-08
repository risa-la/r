#!/usr/bin/env bash
# Runs the verification tools and keeps their raw results for assemble.ts.
#
#   verification/collect.sh tests            unit and integration test coverage
#   verification/collect.sh fuzz-run SECS    fuzz every target for SECS seconds
#   verification/collect.sh fuzz-cover       coverage of each fuzz corpus
#   verification/collect.sh kani             Kani proofs, with their coverage
#   verification/collect.sh tla              the TLA+ models in proofs/
#   verification/collect.sh swift            the Apple client's tests (macOS)
#
# Results go to $VERIFY_RAW (default target/verification/raw), one folder
# per step. Run each step from the dev shell (`nix develop`), except kani,
# which needs cargo-kani on PATH, and swift, which needs Xcode. The steps are
# heavy: run one at a time.
#
# tests and fuzz-cover need a Rust whose coverage runtime matches its LLVM.
# nixpkgs' rustc does not: it builds code with LLVM 21 but ships a runtime
# from a newer LLVM, and every instrumented binary then crashes on exit
# while it writes its profile. Set COVERAGE_TOOLCHAIN to a rustup
# toolchain's folder (with the llvm-tools component), such as
# `$(rustup run stable rustc --print sysroot)`; those steps put its bin/
# first on PATH and use its llvm-cov and llvm-profdata.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RAW=${VERIFY_RAW:-$ROOT/target/verification/raw}
cd "$ROOT"

# The fuzz targets, as crate:target.
FUZZ_TARGETS=(
  risala-proto:frame
  risala-proto:keyfile
  risala-proto:names
  risala-proto:client
  risala-proto:server
  risala-pow:jit
)

# Crates with Kani proofs.
KANI_CRATES=(risala-proto risala-pow)

# Writes "pass" or "fail" and the counts from cargo test's summaries in $1
# (a log) to $2 (JSON).
test_status() {
  local log=$1 out=$2 code=$3
  local passed failed ignored
  passed=$(grep -oE 'test result: [a-zA-Z]+\. [0-9]+ passed' "$log" | awk '{s+=$4} END {print s+0}')
  failed=$(grep -oE '; [0-9]+ failed' "$log" | awk '{s+=$2} END {print s+0}')
  ignored=$(grep -oE '; [0-9]+ ignored' "$log" | awk '{s+=$2} END {print s+0}')
  printf '{"exit":%d,"passed":%d,"failed":%d,"ignored":%d}\n' "$code" "$passed" "$failed" "$ignored" >"$out"
}

# For tests and fuzz-cover: COVERAGE_TOOLCHAIN's Rust and LLVM tools.
use_coverage_toolchain() {
  if [ -n "${COVERAGE_TOOLCHAIN:-}" ]; then
    export PATH=$COVERAGE_TOOLCHAIN/bin:$PATH
    export RUSTC=$COVERAGE_TOOLCHAIN/bin/rustc
  fi
  local tools
  tools="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
  if [ -x "$tools/llvm-cov" ]; then
    export LLVM_COV=$tools/llvm-cov LLVM_PROFDATA=$tools/llvm-profdata
  fi
  echo "coverage with $(rustc -V), $("${LLVM_COV:-llvm-cov}" --version | grep -i 'llvm version')"
}

step_tests() {
  use_coverage_toolchain
  local dir=$RAW/tests
  rm -rf "$dir" && mkdir -p "$dir"
  cargo llvm-cov clean --workspace

  # Unit tests: the tests inside each crate's src/, property tests included.
  local code=0
  cargo llvm-cov --no-report --workspace --lib --bins --no-fail-fast 2>&1 | tee "$dir/unit.log" || code=$?
  test_status "$dir/unit.log" "$dir/unit-status.json" "$code"
  cargo llvm-cov report --json --output-path "$dir/unit.json"

  # Integration tests: each crate's tests/ folder.
  cargo llvm-cov clean --workspace --profraw-only
  code=0
  cargo llvm-cov --no-report --workspace --test '*' --no-fail-fast 2>&1 | tee "$dir/integration.log" || code=$?
  test_status "$dir/integration.log" "$dir/integration-status.json" "$code"
  cargo llvm-cov report --json --output-path "$dir/integration.json"
}

# cargo-fuzz needs nightly; the dev shell's Rust is stable, so allow
# nightly features. The dev shell's Rust has no AddressSanitizer runtime.
fuzz() {
  RUSTC_BOOTSTRAP=1 cargo fuzz "$@"
}

# Seconds each target has been fuzzed in total, kept beside its corpus
# in crates/<crate>/fuzz/corpus/stats.json, so that it lives in the same
# cache as the corpus.
add_fuzz_seconds() {
  local stats=$1 target=$2 secs=$3 crashed=$4
  python3 - "$stats" "$target" "$secs" "$crashed" <<'EOF'
import json, sys, os, time
path, target, secs, crashed = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
stats = json.load(open(path)) if os.path.exists(path) else {}
entry = stats.setdefault(target, {"seconds": 0, "runs": 0})
entry["seconds"] += secs
entry["runs"] += 1
entry["last"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
entry["crashes"] = entry.get("crashes", 0) + (1 if crashed else 0)
entry["lastCrashed"] = crashed
json.dump(stats, open(path, "w"), indent=2, sort_keys=True)
EOF
}

# A crash in one target does not stop the others: each target's time and
# crashes are recorded, and the step fails at the end if any crashed.
step_fuzz_run() {
  local secs=${1:?seconds per target}
  local crashed_targets=()
  for entry in "${FUZZ_TARGETS[@]}"; do
    local crate=${entry%%:*} target=${entry#*:}
    local dir=$ROOT/crates/$crate
    mkdir -p "$dir/fuzz/corpus/$target"
    echo "== fuzzing $crate $target for ${secs}s"
    local start=$SECONDS crashed=0
    (cd "$dir" && fuzz run --sanitizer none "$target" "fuzz/corpus/$target" -- \
      -max_total_time="$secs" -print_final_stats=1) || crashed=1
    add_fuzz_seconds "$dir/fuzz/corpus/stats.json" "$target" $((SECONDS - start)) "$crashed"
    if [ "$crashed" = 1 ]; then crashed_targets+=("$crate:$target"); fi
  done
  if [ ${#crashed_targets[@]} -gt 0 ]; then
    echo "fuzz targets that crashed: ${crashed_targets[*]}" >&2
    return 1
  fi
}

step_fuzz_cover() {
  use_coverage_toolchain
  # libFuzzer is C++. Built by a rustup Rust with the dev shell's C++
  # compiler, the coverage builds need the shell's libstdc++ to run: on a
  # plain Linux runner the loader does not find it.
  if command -v c++ >/dev/null; then
    local cxxlib
    cxxlib=$(dirname "$(c++ -print-file-name=libstdc++.so.6)")
    if [ "$cxxlib" != . ]; then export LD_LIBRARY_PATH=$cxxlib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}; fi
  fi
  local dir=$RAW/fuzz
  rm -rf "$dir" && mkdir -p "$dir"
  local host
  host=$(rustc -vV | sed -n 's/^host: //p')
  for entry in "${FUZZ_TARGETS[@]}"; do
    local crate=${entry%%:*} target=${entry#*:}
    local cdir=$ROOT/crates/$crate
    local corpus=$cdir/fuzz/corpus/$target
    if [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
      echo "== no corpus for $crate $target, skipped"
      continue
    fi
    echo "== coverage of $crate $target"
    (cd "$cdir" && fuzz coverage --sanitizer none "$target" "fuzz/corpus/$target")
    # cargo fuzz puts the coverage build under the crate's target folder,
    # or fuzz/'s, depending on its version: find it.
    local bin
    bin=$(find "$cdir/target" "$cdir/fuzz/target" -path "*/coverage/$host/release/$target" -type f 2>/dev/null | head -1)
    if [ -z "$bin" ]; then
      echo "no coverage build of $crate $target" >&2
      return 1
    fi
    "${LLVM_COV:-llvm-cov}" export -format=text \
      -instr-profile="$cdir/fuzz/coverage/$target/coverage.profdata" \
      -ignore-filename-regex='/(\.cargo|rustc|nix/store)/' \
      "$bin" >"$dir/$crate.$target.json"
    local files
    files=$(find "$corpus" -type f | wc -l)
    printf '{"crate":"%s","target":"%s","inputs":%d}\n' "$crate" "$target" "$files" \
      >"$dir/$crate.$target.meta.json"
  done
  # The time fuzzed so far, from the corpus caches.
  for crate in $(printf '%s\n' "${FUZZ_TARGETS[@]}" | cut -d: -f1 | sort -u); do
    local stats=$ROOT/crates/$crate/fuzz/corpus/stats.json
    if [ -f "$stats" ]; then cp "$stats" "$dir/$crate.stats.json"; fi
  done
}

step_kani() {
  local dir=$RAW/kani
  rm -rf "$dir" && mkdir -p "$dir"
  local target=${CARGO_TARGET_DIR:-$ROOT/target}
  for crate in "${KANI_CRATES[@]}"; do
    echo "== kani $crate"
    rm -rf "$target"/kani/*/kanicov_*
    local code=0
    cargo kani -p "$crate" -j "${KANI_JOBS:-2}" --output-format terse \
      --coverage -Z source-coverage -Z unstable-options \
      --harness-timeout "${KANI_TIMEOUT:-2m}" \
      --export-json "$dir/$crate.json" 2>&1 | tee "$dir/$crate.log" || code=$?
    echo "{\"exit\":$code}" >"$dir/$crate.status.json"
    mkdir -p "$dir/$crate.coverage"
    find "$target/kani" -path '*kanicov_*' -name '*_kaniraw.json' \
      -exec cp {} "$dir/$crate.coverage/" \;
  done
}

step_tla() {
  local dir=$RAW/tla
  rm -rf "$dir" && mkdir -p "$dir"
  # TLC can take most of a machine's memory without a cap.
  export JAVA_TOOL_OPTIONS=${JAVA_TOOL_OPTIONS:--Xmx4g}
  # model folder, config, time limit in seconds
  local runs=(
    "sync AsWritten.cfg 600"
    "sync ProposedOneDevice.cfg 1800"
  )
  for run in "${runs[@]}"; do
    read -r model cfg limit <<<"$run"
    local name=${model}.${cfg%.cfg}
    echo "== tlc $model $cfg"
    local code=0 start=$SECONDS
    # The model's .tla file, the first in the folder.
    (cd "proofs/$model" && specs=(./*.tla) && timeout "$limit" tlc -workers 1 \
      -config "$cfg" "${specs[0]}") >"$dir/$name.log" 2>&1 || code=$?
    printf '{"model":"%s","config":"%s","exit":%d,"seconds":%d,"limit":%d}\n' \
      "$model" "$cfg" "$code" $((SECONDS - start)) "$limit" >"$dir/$name.status.json"
    tail -5 "$dir/$name.log"
  done
}

step_swift() {
  local dir=$RAW/swift
  rm -rf "$dir" && mkdir -p "$dir"
  local bundle=$dir/Tests.xcresult
  local code=0
  xcodebuild test -project clients/apple/Risala.xcodeproj -scheme Risala \
    -destination 'platform=macOS' -enableCodeCoverage YES \
    -resultBundlePath "$bundle" CODE_SIGNING_ALLOWED=NO 2>&1 | tee "$dir/test.log" || code=$?
  # "Executed 12 tests, with 1 failure (0 unexpected)": the last such
  # line is the total for the run.
  local summary passed=0 failed=0
  summary=$(grep -E 'Executed [0-9]+ tests?, with [0-9]+ failures?' "$dir/test.log" | tail -1 || true)
  if [ -n "$summary" ]; then
    local total
    total=$(sed -E 's/.*Executed ([0-9]+) tests?.*/\1/' <<<"$summary")
    failed=$(sed -E 's/.*with ([0-9]+) failures?.*/\1/' <<<"$summary")
    passed=$((total - failed))
  fi
  printf '{"exit":%d,"passed":%d,"failed":%d,"ignored":0}\n' "$code" "$passed" "$failed" >"$dir/status.json"
  if [ ! -d "$bundle" ]; then
    echo "no result bundle, so no coverage" >&2
    return 1
  fi
  xcrun xccov view --archive --json "$bundle" >"$dir/xccov.json"
  # xccov names files by absolute path; keep the checkout's, to strip it.
  echo "$ROOT" >"$dir/root.txt"
}

case ${1:-} in
  tests) step_tests ;;
  fuzz-run) step_fuzz_run "${2:-}" ;;
  fuzz-cover) step_fuzz_cover ;;
  kani) step_kani ;;
  tla) step_tla ;;
  swift) step_swift ;;
  *)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
