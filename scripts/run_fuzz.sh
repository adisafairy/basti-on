#!/usr/bin/env bash
# Runs the real libFuzzer targets via cargo-fuzz. Requires the nightly toolchain
# and cargo-fuzz (see docs/SETUP.md). The raw target is expected to crash fast;
# the guarded target is expected to survive.
#
#   scripts/run_fuzz.sh raw      [seconds]   # expect a crash
#   scripts/run_fuzz.sh guarded  [seconds]   # expect survival
#   scripts/run_fuzz.sh validator [seconds]  # expect survival (no ASan needed)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${1:-raw}
SECONDS_TO_RUN=${2:-60}

case "$TARGET" in
  raw)       NAME=raw_parser;              ASAN=1 ;;
  guarded)   NAME=guarded_parser;          ASAN=1 ;;
  validator) NAME=validator_never_panics;  ASAN=0 ;;
  *) echo "usage: $0 {raw|guarded|validator} [seconds]"; exit 2 ;;
esac

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz not found. Install it: cargo install cargo-fuzz" >&2
  exit 1
fi

echo "Fuzzing '$NAME' for ${SECONDS_TO_RUN}s (ASan=$ASAN) ..."
if [ "$ASAN" = 1 ]; then
  AIRLOCK_ASAN=1 cargo +nightly fuzz run "$NAME" -- -max_total_time="$SECONDS_TO_RUN"
else
  cargo +nightly fuzz run "$NAME" -- -max_total_time="$SECONDS_TO_RUN"
fi
