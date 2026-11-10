#!/usr/bin/env bash
# One command that shows whether Basti-on works. Runs each proof and prints
# PASS or FAIL with the evidence:
#   1. unit tests pass
#   2. the C++ bug is real (ASan reports the over-read on both crafted packets)
#   3. the airlock stops every crashing packet (differential fuzz)
#   4. the DNS guard answers real lookups, drops attacks, survives, and doesn't
#      freeze (needs network access to 1.1.1.1; SKIP if it has none)
#
#   scripts/check.sh [fuzz-packets]     (default 2000)
set -uo pipefail
cd "$(dirname "$0")/.."

N=${1:-2000}
pass=0; fail=0; skip=0
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

green=$'\e[32m'; red=$'\e[31m'; yellow=$'\e[33m'; bold=$'\e[1m'; off=$'\e[0m'
result() { # status, title, evidence
  case $1 in
    PASS) pass=$((pass + 1)); printf '%s[PASS]%s %s\n' "$green" "$off" "$2" ;;
    FAIL) fail=$((fail + 1)); printf '%s[FAIL]%s %s\n' "$red" "$off" "$2" ;;
    SKIP) skip=$((skip + 1)); printf '%s[SKIP]%s %s\n' "$yellow" "$off" "$2" ;;
  esac
  printf '       %s\n\n' "$3"
}

echo "${bold}Basti-on self-check${off}"
echo

# 1. Unit tests
echo "Running unit tests..."
if cargo test >"$OUT/test.txt" 2>&1; then
  result PASS "Unit tests" "$(grep -m1 'test result' "$OUT/test.txt")"
else
  result FAIL "Unit tests" "see the output of: cargo test"
fi

# 2. The bug is real
echo "Building the C++ parser with AddressSanitizer and feeding it the two crafted packets..."
scripts/run_asan_demo.sh >"$OUT/asan.txt" 2>&1 || true
hits=$(grep -c 'SUMMARY: AddressSanitizer: heap-buffer-overflow' "$OUT/asan.txt" || true)
if [ "$hits" -ge 2 ]; then
  where=$(grep 'SUMMARY: AddressSanitizer' "$OUT/asan.txt" | grep -o 'dns_parser.cpp:[0-9]*' | sort -u | paste -sd ' ' -)
  result PASS "The C++ bug is real" "ASan reported $hits heap-buffer-overflow reads, at $where"
else
  result FAIL "The C++ bug is real" "expected 2 ASan reports, got $hits (see scripts/run_asan_demo.sh)"
fi

# 3. The airlock stops it
echo "Differential fuzz: $N random packets through the airlock and the ASan-built parser..."
scripts/differential_fuzz.sh "$N" >"$OUT/fuzz.txt" 2>&1 || true
crashed=$(grep -o 'raw parser crashed (ASan) : [0-9]*' "$OUT/fuzz.txt" | grep -o '[0-9]*$')
leaked=$(grep -o 'accepted-by-airlock AND crashes-raw : [0-9]*' "$OUT/fuzz.txt" | grep -o '[0-9]*$')
if grep -q '^PASS' "$OUT/fuzz.txt" && [ "${leaked:-x}" = 0 ]; then
  result PASS "The airlock stops every crashing packet" "$crashed of $N packets crashed the raw parser; $leaked of them got past the airlock"
else
  result FAIL "The airlock stops every crashing packet" "crashed=${crashed:-?}, got past the airlock=${leaked:-?} (see scripts/differential_fuzz.sh)"
fi

# 4. The DNS guard
echo "Running the DNS guard with real lookups, attack packets and a freeze test..."
PORT=${PORT:-5390} scripts/dns_guard_demo.sh >"$OUT/guard.txt" 2>&1 || true
row() { grep -m1 "^$1" "$OUT/guard.txt" | cut -c50-; }
if ! row "real lookup: example.com" | grep -q NOERROR; then
  result SKIP "DNS guard" "no answer for example.com from 1.1.1.1 (no network?). Try again online."
else
  attacks=$(grep -c '^attack:.*FORMERR' "$OUT/guard.txt" || true)
  rules=$(grep -c '^non-standard:.*FORMERR' "$OUT/guard.txt" || true)
  alive=$(grep -c 'Guard still running after all of that: yes' "$OUT/guard.txt" || true)
  freeze=$(grep -o 'all 5 answered after [0-9.]* s' "$OUT/guard.txt" | grep -o '[0-9.]* s' | grep -o '[0-9.]*')
  quick=$(awk -v f="${freeze:-99}" 'BEGIN { print (f < 4) ? 1 : 0 }')
  if [ "$attacks" = 4 ] && [ "$rules" = 2 ] && [ "$alive" = 1 ] && [ "$quick" = 1 ]; then
    result PASS "DNS guard" "example.com -> $(row 'real lookup: example.com' | sed 's/.*answer(s): //'); 4/4 attacks dropped; 2/2 non-standard queries rejected; still running; 5 stuck lookups answered in ${freeze} s"
  else
    result FAIL "DNS guard" "attacks dropped=$attacks/4, non-standard rejected=$rules/2, still running=$alive, freeze test=${freeze:-none} s (see scripts/dns_guard_demo.sh)"
  fi
fi

echo "${bold}Result: $pass passed, $fail failed, $skip skipped${off}"
[ "$fail" = 0 ]
