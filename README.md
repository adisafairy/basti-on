# Basti-on

**Always on, standing guard.** A memory-safe **Rust airlock** in front of a
memory-unsafe **C++** parser.

**Live demo: [basti-on.vercel.app](https://basti-on.vercel.app)**. Packet Lab
shows the airlock under live traffic, takes packets apart byte by byte, replays a
real DNS guard run, and checks itself against 2,000 packets recorded from the
real binaries. Its source is `site/index.html`.

Basti-on is the bastion at the boundary: untrusted packets hit the Rust guard
first, and only the ones it proves well-formed are let through to the C++ engine
behind it.

The C++ side is a small DNS message parser that follows label lengths and
compression pointers **without bounds checks** — a real, documented bug class
(CWE-125 out-of-bounds read, the same family as libtins `DNS::compose_name`,
[CVE-2026-112273](https://www.vulncheck.com/advisories/libtins-through-4.6-heap-out-of-bounds-read-via-dns-compose-name),
and the nmap DNS over-reads found with AFL). On crafted packets it reads past
the end of the buffer.

The Rust side validates every packet first — bounds-checking each label and
compression pointer, rejecting forward/looping pointers, and capping name length
— and only hands the C++ parser input that is already proven well-formed. The
C++ keeps doing the work it is good at; Rust guards the boundary where the
dangerous bugs live.

```
untrusted bytes ──▶ [ Rust airlock: validate() ] ──reject──▶ dropped, C++ never runs
                              │ accept
                              ▼
                     [ C++ dns parser ] ──▶ parsed message
```

## The three results this project demonstrates

Everything below is produced by scripts in this repo, so the numbers are
reproducible rather than asserted.

1. **The bug is real.** `scripts/run_asan_demo.sh` builds the C++ parser with
   AddressSanitizer and crashes it with two crafted packets — a label that runs
   off the end, and a wild compression pointer. ASan reports a
   `heap-buffer-overflow READ` inside `decode_name`.

2. **The airlock stops it.** `scripts/differential_fuzz.sh` generates thousands
   of packets and, for each, compares the airlock's verdict against whether the
   raw parser actually over-reads under ASan. Across a sample run of 7,000
   packets, **1,997 crashed the raw parser and 0 got past the airlock.** The
   "accepted by airlock AND crashes raw parser" cell is 0 — that is the safety
   property.

3. **It is cheap.** `cargo run --release --example bench` parses valid traffic
   both ways and reports the overhead of the validation pass. In a noisy sandbox
   it measured roughly **+8%** on valid packets; on malformed traffic the airlock
   is *faster*, because it rejects early and never enters C++. Run it on your own
   machine for a number you can cite.

## Using it in real code: a DNS guard

`examples/dns_guard.rs` is a small, working DNS forwarder built on the library.
It listens for real DNS lookups, puts the airlock in front of every one, lets the
C++ parser read the good ones (to apply a blocklist), and forwards them to a real
resolver such as 1.1.1.1.

```bash
scripts/dns_guard_demo.sh               # real lookups + attack packets, airlock on
scripts/dns_guard_demo.sh --no-airlock  # same traffic with the airlock off
```

With the airlock on, real lookups are answered and the attack packets get a
FORMERR reply without reaching C++. With it off, the same packets reach the
parser: in a sample run one 14-byte packet made it copy at least 500 bytes of
heap memory into the logged name, including pieces of earlier lookups. The guard
also rejects non-standard queries up front and forwards on a pool of 16 workers,
so a silent upstream can't freeze it. See [docs/WRITEUP.md](docs/WRITEUP.md) for
those runs, and for a crash in the C++ → Rust bridge that building the guard
uncovered and that is now fixed.

## Quick start

To check everything at once, run `scripts/check.sh`. It runs the unit tests,
the ASan demo, a 2,000-packet differential fuzz and the DNS guard demo, and
prints PASS or FAIL for each with the evidence. Or step by step:

```bash
# 1. Build and unit-test (stable Rust + a C++ compiler is all you need)
cargo test

# 2. See the airlock reject the two crash packets and accept a valid one
cargo run --example airlock_vs_raw

# 3. Prove the C++ bug is real (needs a compiler with an ASan runtime; g++ works)
scripts/run_asan_demo.sh

# 4. Run the differential fuzzer (stable Rust; the headline safety result)
scripts/differential_fuzz.sh 5000

# 5. Measure the overhead
cargo run --release --example bench

# 6. Run it as a real DNS service (needs network access to 1.1.1.1)
scripts/dns_guard_demo.sh
```

For the full libFuzzer/`cargo-fuzz` setup (nightly toolchain), see
[docs/SETUP.md](docs/SETUP.md). For the interview-facing story — problem, what
drove it, outcome, scalability, business value — see
[docs/WRITEUP.md](docs/WRITEUP.md).

## Layout

```
cpp/include/dns_parser.h          the unsafe parser's interface
cpp/src/dns_parser.cpp            the unsafe parser (the bug lives here)
cpp/src/dns_parser_bridge.cc      cxx glue: fills the bridged struct
cpp/src/asan_demo.cpp             standalone ASan crash demo
cpp/src/fuzz_one.cpp              reads one packet from stdin (for the harness)
src/lib.rs                        the airlock: validate(), parse_guarded/unguarded
build.rs                          compiles the C++ via cxx-build
examples/airlock_vs_raw.rs        the three-line demonstration
examples/differential.rs          differential harness (airlock vs raw parser)
examples/bench.rs                 throughput benchmark
examples/dns_guard.rs             real DNS forwarder with the airlock in front
fuzz/                             cargo-fuzz targets (raw / guarded / validator)
scripts/                         one-command wrappers
docs/                            SETUP and the interview write-up
```

## Honest limitations

- The C++ parser here is written for this demo, not pulled from a real product,
  so it is small enough to read in one sitting. The *bug class* is real and
  documented; the specific lines are illustrative. Swapping in a real library
  (e.g. wrapping libtins at a pinned vulnerable commit) is the natural next step
  and is described in `docs/WRITEUP.md`.
- The airlock makes the *reachable* surface safe; the C++ behind it is still
  memory-unsafe code. The claim is "attackers can't reach the bug with malformed
  input," not "the C++ is now safe."
- The benchmark and fuzz counts depend on the machine and the run; treat the
  committed numbers as examples and regenerate your own.

## License

MIT. See [LICENSE](LICENSE).
