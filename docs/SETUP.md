# Setup

## What you need

| Tool | Why | Install |
|------|-----|---------|
| Rust (stable) | builds the crate, examples, differential fuzzer | [rustup.rs](https://rustup.rs) |
| A C++ compiler | the parser; `g++` is easiest because it ships an ASan runtime | `sudo apt install build-essential` |
| Rust nightly + cargo-fuzz | only for the real libFuzzer targets | see below |

On **Windows**, do all of this inside **WSL2 (Ubuntu)** — the fuzzing tooling is
most reliable on Linux. `wsl --install -d Ubuntu` from PowerShell, then work
inside the Ubuntu shell.

```bash
sudo apt update
sudo apt install -y build-essential clang cmake git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Running everything without nightly

The stable toolchain is enough for the main story:

```bash
cargo test                          # unit tests
cargo run --example airlock_vs_raw  # the demonstration
scripts/run_asan_demo.sh            # prove the C++ bug (needs g++ ASan)
scripts/differential_fuzz.sh 5000   # the headline safety result
cargo run --release --example bench # overhead
```

`scripts/run_asan_demo.sh` and `scripts/differential_fuzz.sh` need a compiler
whose AddressSanitizer runtime is installed. `g++` has it out of the box. With
clang you also need the runtime: `sudo apt install libclang-rt-dev` (package name
varies by distro).

## Running the real libFuzzer targets (optional, nicer for a demo)

`cargo-fuzz` needs the **nightly** toolchain and the clang ASan runtime.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

# Expected to CRASH within seconds — this is the baseline:
AIRLOCK_ASAN=1 cargo +nightly fuzz run raw_parser -- -max_total_time=60

# Expected to SURVIVE — run it much longer (hours is good):
AIRLOCK_ASAN=1 cargo +nightly fuzz run guarded_parser -- -max_total_time=600

# The validator alone must never panic (no ASan needed):
cargo +nightly fuzz run validator_never_panics -- -max_total_time=120
```

When `raw_parser` crashes, cargo-fuzz writes the offending input to
`fuzz/artifacts/raw_parser/`. Keep it — replaying it against both paths
(`cargo fuzz run guarded_parser fuzz/artifacts/raw_parser/crash-...`) is a clean
way to show the same input crashing one path and being rejected by the other.

There are convenience wrappers: `scripts/run_fuzz.sh raw 60`,
`scripts/run_fuzz.sh guarded 600`, `scripts/run_fuzz.sh validator 120`.

## Troubleshooting

- **`cannot find -lclang_rt.asan`** — clang's ASan runtime isn't installed. Use
  `CXX=g++ scripts/run_asan_demo.sh`, or install the clang runtime package.
- **`cargo fuzz` says nightly is required** — `rustup toolchain install nightly`.
- **cxx build errors after editing `src/lib.rs`** — the bridge header includes
  the generated `lib.rs.h`; run `cargo clean -p basti-on` and rebuild.
