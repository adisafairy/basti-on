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
