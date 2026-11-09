# AGENTS.md — context for AI agents working in this repo

This file is read automatically by AI coding agents (e.g. in Orca). It records what
this project is and the rules to keep, so a fresh agent doesn't start from zero.

## What this project is

A demonstration of the **airlock pattern**: a memory-safe Rust validator in front
of a memory-unsafe C++ parser, so the C++ only ever sees input proven
well-formed. The C++ parses DNS messages and has a deliberate out-of-bounds read
(CWE-125) in DNS name decompression — the same bug class as libtins
`DNS::compose_name` (CVE-2026-112273). The Rust `validate()` bounds-checks every
label and compression pointer and rejects malformed packets before C++ runs.

It is a portfolio/interview project. The goal is to *prove*, not assert, three
things: the bug is real, the airlock stops exactly the crashing inputs, and the
overhead is small.

## The three results (keep them reproducible)

- Bug is real: `scripts/run_asan_demo.sh` — C++ built with ASan crashes.
- Airlock works: `scripts/differential_fuzz.sh N` — 0 crashing packets get past.
- Overhead: `cargo run --release --example bench`.

## Rules — do not break these

1. **The C++ parser (`cpp/src/dns_parser.cpp`) is unsafe ON PURPOSE.** Do not
   "fix" its bounds checks. Its over-read is the thing the airlock defends
   against. If you harden it, the whole demo loses its point.
2. **All safety lives in `src/lib.rs::validate`.** Changes to what is accepted or
   rejected go there, with a matching unit test and a note in the write-up.
3. **Only claim numbers you measured.** The counts in README/WRITEUP are sample
   runs; if you change the generator or the parser, regenerate them and say so.
   Never hand-edit a result to look better.
4. **Keep the airlock honest.** The claim is "the bug is unreachable from
   malformed input," not "the C++ is now safe." Don't let the docs drift into
   overclaiming.
5. **Stable Rust must stay enough** for `cargo test`, the examples, and the
   differential fuzzer. Only the `fuzz/` libFuzzer targets may require nightly.
6. **`g++` is the default for ASan** in scripts (its runtime ships); clang is a
   fallback. Don't assume the clang ASan runtime is installed.

## Build notes

- `build.rs` compiles the C++ via `cxx-build`. The bridge definition is the
  `#[cxx::bridge]` mod in `src/lib.rs`; the glue is `cpp/src/dns_parser_bridge.cc`
  (kept as its own `.cc` so the generated `Vec<Question>` specializations are
  defined before use — do not inline it back into a header).
- The hand-written parser lives in namespace `dnscore` to avoid colliding with
  the cxx-generated `dnsparser` types.
- Set `AIRLOCK_ASAN=1` to rebuild the C++ with AddressSanitizer (used for
  fuzzing). The default build has no ASan so `cargo test`/bench link cleanly.

## Good next steps (if asked to extend)

- Wrap a real library (libtins at a pinned vulnerable commit) instead of the
  hand-written parser, so before/after numbers come from production code.
- Extend the airlock + parser to answer/authority/additional records, not just
  questions.
- Add crashing fuzz artifacts as regression tests in CI.
