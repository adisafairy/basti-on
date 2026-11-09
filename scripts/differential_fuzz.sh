#!/usr/bin/env bash
# Runs the differential harness: generate many packets, and for each one compare
# the airlock's verdict against whether the raw C++ parser (under ASan) actually
# over-reads. Prints a contingency table; the "accepted AND crashes" cell must
# be 0. Runs on stable Rust, so it works anywhere cargo + g++ do.
#
#   scripts/differential_fuzz.sh [iterations] [seed]
set -euo pipefail
cd "$(dirname "$0")/.."

ITERS=${1:-3000}
SEED=${2:-$RANDOM}

CXX=${CXX:-g++}
if ! "$CXX" -fsanitize=address -xc++ -std=c++17 - -o /tmp/_asan_probe <<<'int main(){return 0;}' 2>/dev/null; then
  CXX=clang++
fi
rm -f /tmp/_asan_probe

OUT=$(mktemp -d)
echo "Building ASan fuzz_one with $CXX ..."
"$CXX" -std=c++17 -fsanitize=address -g -Icpp/include \
    cpp/src/dns_parser.cpp cpp/src/fuzz_one.cpp -o "$OUT/fuzz_one"

echo "Building differential harness (release) ..."
cargo build --release --quiet --example differential

echo
./target/release/examples/differential "$OUT/fuzz_one" "$ITERS" "$SEED"
rm -rf "$OUT"
