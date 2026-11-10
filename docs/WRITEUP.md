# Basti-on — project write-up

This is the story to tell about the project, built around the questions an
interviewer tends to ask: what problem you saw, what drove you, the outcome,
scalability, and business value. Every claim here maps to something you can run
in the repo, so you can demo it instead of just describing it.

## The problem

Memory-safety bugs — buffer overflows, out-of-bounds reads, use-after-free — are
the largest single category of serious security vulnerabilities in C and C++
code. Microsoft and the Chrome team have each reported that roughly **70% of
their high-severity vulnerabilities** are memory-safety issues. The obvious fix,
"rewrite it in Rust," collides with reality: the world runs on huge, battle-
tested C++ codebases that are too large, too risky, and too expensive to rewrite
wholesale.

But the bugs are not spread evenly. They cluster at the **boundary** — the code
that parses untrusted input: files, media, and network packets. That is where an
attacker's bytes first meet the program. A parser that trusts its input is where
a crafted packet turns into a crash or worse.

## What drove the project

Two observations.

1. A full rewrite is the wrong unit of work. The right unit is the **boundary**.
   If you make only the parsing layer memory-safe, you remove the part an
   attacker can actually reach with malformed input, while leaving the proven
   core logic alone.

2. People assert that "Rust at the boundary helps" — I wanted to *measure* it on
   a real bug class, with numbers instead of a slogan. So I built the smallest
   honest version: a C++ parser with a genuine, documented bug family (a DNS
   name-decompression over-read, CWE-125, as seen in libtins `compose_name` and
   nmap's DNS code), a Rust airlock in front of it, and a harness that proves the
   airlock stops exactly the inputs that crash the raw parser.

## The outcome

Three results, each reproducible from the repo:

- **The bug is real.** Built with AddressSanitizer, the C++ parser reports a
  `heap-buffer-overflow READ` in `decode_name` on two crafted packets — a label
  that runs off the buffer and a wild compression pointer.
  (`scripts/run_asan_demo.sh`)

- **The airlock stops it, with no false negatives.** A differential harness
  generates thousands of packets and cross-checks the airlock's verdict against
  whether the raw parser actually over-reads under ASan. In a sample run of
  **7,000 packets, 1,997 crashed the raw parser and 0 slipped past the airlock.**
  The dangerous cell — "accepted by the airlock yet crashes the parser" — was
  **0**. (`scripts/differential_fuzz.sh`)

- **The cost is small.** On valid traffic the airlock adds one bounds-checked
  pass over the packet before the C++ runs: roughly **+8%** in a noisy sandbox,
  and typically less on real hardware. On malformed traffic it is *faster* than
  the raw path, because it rejects early and never enters C++.
  (`cargo run --release --example bench`)

The honest framing matters in an interview: the airlock does not make the C++
memory-safe. It makes the bug **unreachable from malformed input**, which is the
property that stops the attack. Saying that out loud is more convincing than
overclaiming.

### Using it in a real service: the DNS guard

`examples/dns_guard.rs` is a small UDP DNS forwarder built on the library, the
way production code would use it: every query goes through `validate()`, bad
ones get a FORMERR reply and never reach C++, good ones are parsed by the C++
parser via `parse_guarded()` (its result drives a blocklist) and forwarded to a
real resolver. `scripts/dns_guard_demo.sh` sends it real lookups, the crafted
packets and two non-standard queries. In one run on 10 Nov 2026 (WSL Ubuntu,
upstream 1.1.1.1):

- Real lookups for `example.com` and `github.com` were answered in about 5 ms,
  and a blocklisted name got NXDOMAIN.
- All five malformed packets were dropped by the airlock, and the guard kept
  serving afterwards.
- With `--no-airlock`, the same packets reached the C++ parser. This build has
  no ASan, so nothing crashed, which is worse: the 14-byte "label runs off the
  end" packet made the parser read on past the packet through leftover heap
  memory and copy at least 500 bytes of it into the logged name, including
  pieces of earlier lookups (`xampl..com`, `hub\3com` from the `github.com`
  request) and what look like heap addresses. That is a Heartbleed-style memory
  disclosure. The pointer loop made the parser follow the same pointer 32,768
  times and build a 65,535-character name, and malformed packets were forwarded
  upstream, where each one tied up a worker for 2 s and ended in SERVFAIL. The
  amount leaked varies from run to run because it depends on what the heap held.

### Trying to break it: a freeze the airlock can't stop

Asked "what makes it fail?", two well-formed but non-standard queries did: a
header with 0 questions, and a query with the QR (reply) bit set. Both pass the
airlock, correctly, since they are memory-safe. But 1.1.1.1 ignores them, and the
first version of the guard handled one query at a time with a 2 s upstream wait.
Measured against that version, each got no reply and froze the guard for 2 s,
so one such packet every 2 s would have kept it nearly unavailable. That is an
availability bug, not a memory-safety one, so the fix lives in the guard rather
than in `validate()`:

- Queries that are not standard (no question or more than one, QR set, or an
  unassigned opcode) get an immediate FORMERR or NOTIMP instead of being
  forwarded. Both packets now get FORMERR in under 1 ms.
- Forwarding runs on 16 worker threads behind a bounded queue (256). A silent
  upstream ties up one worker, a full queue gets SERVFAIL at once, and an
  upstream timeout answers SERVFAIL instead of leaving the client waiting. The
  demo's freeze test points a guard at 192.0.2.1, which never answers, and sends
  5 lookups at once: all 5 got SERVFAIL after 2.0 s, where one-at-a-time would
  take about 10 s.

The lesson: the airlock makes the parser unreachable by malformed input, but a
service built on it still needs its own rules for availability.

### A bug the differential fuzzer could not see

Building the DNS guard turned up a crash outside the parser. A well-formed
packet whose label holds a non-UTF-8 byte (for example `0xff`, which DNS allows)
passes `validate()`, but the C++ → Rust bridge converted each name with
`rust::String(std::string)`, which throws on invalid UTF-8. The exception
crossed the FFI boundary and aborted the process: one 19-byte packet could take
down a server. The differential harness feeds the C++ parser directly through
`fuzz_one`, never through the bridge, so it could not observe this.

The fix is in the bridge (`cpp/src/dns_parser_bridge.cc` now uses
`rust::String::lossy`, replacing bad bytes with U+FFFD), with a regression test
`accepts_non_utf8_label_without_aborting` in `src/lib.rs`. The parser itself and
what the airlock accepts are unchanged. The lesson for the write-up: fuzz the
path production actually takes, including the FFI layer, not just the unsafe
component on its own.

## Is it scalable?

Yes, in two senses.

- **As an engineering pattern.** This is the *strangler fig* approach applied to
  safety: wrap one boundary at a time behind a validated interface, ship it, then
  move to the next, without ever stopping the world for a rewrite. The same shape
  — Rust `validate()` in front, C++ engine behind, `cxx` between — works for an
  image decoder, a file-format parser, or a protocol handler. The DNS parser here
  is just the first boundary.

- **As a running system.** Validation is stateless and per-packet, so it scales
  horizontally: put the airlock in front of N parser workers and add workers as
  load grows. The validation pass is O(packet size) with no allocations on the
  reject path.

## Business value

- **Fewer security incidents at the boundary**, which is where the costly ones
  originate. Each avoided memory-safety CVE is an avoided emergency patch,
  disclosure, and potential breach.
- **No rewrite bill.** You keep the existing C++ investment and its ecosystem
  (here that would be a mature packet library); you add safety only where it pays
  off most. That is a fraction of the cost and risk of a rewrite.
- **A measurable safety claim.** "We fuzzed both paths; malformed input that
  crashes the legacy parser is rejected before it reaches it, at ~8% overhead" is
  the kind of statement that satisfies a security review or a customer
  questionnaire. Assertions without numbers do not.

## Anticipated interview questions

**"Why not just fix the C++ bugs?"** Fuzzing finds bugs one at a time, and a
parser accretes new ones as it grows. The airlock removes an entire *class* of
reachable bugs — including ones nobody has found yet — by construction, because
malformed input never reaches the unsafe code.

**"Isn't the C++ behind it still unsafe?"** Yes, and that's the honest scope. I
shrank the attack surface to the part that only ever receives
already-validated data. The claim is reachability, not purity.

**"Why both languages instead of one?"** C++ has the mature ecosystem and the
existing, proven engine. Rust gives memory safety exactly where untrusted bytes
arrive. Each language is doing the job it is best at; `cxx` keeps the FFI
boundary type-checked rather than a raw `extern "C"` free-for-all.

**"What would you do next?"** Swap the hand-written parser for a real library at
a pinned vulnerable commit (e.g. libtins before the `compose_name` fix), so the
before/after numbers come from production code; widen the airlock to full DNS
(answers, authority, additional records); and add the crashing fuzz artifacts to
CI as regression tests.

## How to demo it live (about 3 minutes)

```bash
cargo run --example airlock_vs_raw   # 3 lines: 2 rejected, 1 accepted
scripts/run_asan_demo.sh             # the raw parser crashes under ASan
scripts/differential_fuzz.sh 5000    # thousands of packets, 0 slip through
cargo run --release --example bench  # the overhead number
```
