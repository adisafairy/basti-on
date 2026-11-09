#!/usr/bin/env bash
# Proves the C++ parser reads out of bounds, by building it with AddressSanitizer
# and feeding it two crafted packets. Each run ends in an ASan crash report.
#
# Needs a compiler with a working ASan runtime. clang needs the compiler-rt
# runtime installed; g++ ships it. The script prefers g++ for that reason, and
# falls back to clang++.
set -euo pipefail
cd "$(dirname "$0")/.."

CXX=${CXX:-g++}
if ! "$CXX" -fsanitize=address -xc++ -std=c++17 - -o /tmp/_asan_probe <<<'int main(){return 0;}' 2>/dev/null; then
  echo "note: $CXX lacks a working ASan runtime; trying clang++"
  CXX=clang++
fi
rm -f /tmp/_asan_probe

OUT=$(mktemp -d)
echo "Building ASan demo with $CXX ..."
"$CXX" -std=c++17 -fsanitize=address -g -Icpp/include \
    cpp/src/dns_parser.cpp cpp/src/asan_demo.cpp -o "$OUT/asan_demo"

for case in 1 2; do
  label=$([ "$case" = 1 ] && echo "label over-read" || echo "compression-pointer over-read")
  echo
  echo "=================================================================="
  echo " Case $case: $label  (expect an AddressSanitizer crash below)"
  echo "=================================================================="
  ASAN_OPTIONS=detect_leaks=0 "$OUT/asan_demo" "$case" || true
done
rm -rf "$OUT"
