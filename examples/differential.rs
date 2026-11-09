//! Differential harness that runs on STABLE Rust, here in the sandbox.
//!
//! It generates many DNS-shaped packets (some valid, many malformed) and for
//! each one:
//!   * asks the airlock's `validate()` for a verdict (accept / reject), and
//!   * runs the real raw C++ parser under AddressSanitizer in a subprocess
//!     (the `fuzz_one` binary) to see whether it actually reads out of bounds.
//!
//! Then it reports the contingency table. The key property we want to see:
//!   * every packet that CRASHES the raw parser was REJECTED by the airlock
//!     (no crash slips through), and
//!   * the airlock does not reject everything — valid packets are accepted.
//!
//! Usage (wired up by scripts/differential_fuzz.sh):
//!   cargo run --release --example differential -- <fuzz_one_path> <iterations> <seed>

use std::io::Write;
use std::process::{Command, Stdio};

use bastion::validate;

// A tiny xorshift RNG so the run is deterministic from a seed and needs no deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

// Generate a DNS-shaped packet. Mixes three strategies so we hit both valid and
// nasty inputs: fully random, structured-valid, and valid-but-corrupted.
fn gen_packet(rng: &mut Rng) -> Vec<u8> {
    match rng.below(3) {
        0 => {
            // Fully random, random length 0..40.
            let len = rng.below(40);
            (0..len).map(|_| rng.byte()).collect()
        }
        1 => structured(rng, false),
        _ => structured(rng, true),
    }
}

// Build a valid single-question packet; if `corrupt`, poke one byte to break it.
fn structured(rng: &mut Rng, corrupt: bool) -> Vec<u8> {
    let mut p = vec![0u8; 12];
    p[5] = 1; // qdcount = 1
    let labels = 1 + rng.below(3);
    for _ in 0..labels {
        let llen = 1 + rng.below(8);
        p.push(llen as u8);
        for _ in 0..llen {
            p.push(b'a' + (rng.byte() % 26));
        }
    }
    p.push(0); // root label
    p.extend_from_slice(&[0, 1, 0, 1]); // QTYPE, QCLASS
    if corrupt && p.len() > 13 {
        let idx = 12 + rng.below(p.len() - 12);
        // Favour corruptions that matter: oversized label lengths and pointers.
        p[idx] = match rng.below(3) {
            0 => 0xC0, // start of a compression pointer
            1 => 0x3F + rng.byte() % 0x40, // big label length
            _ => rng.byte(),
        };
    }
    p
}

// Run the raw parser (ASan build) on `data` in a subprocess. Returns true if it
// crashed / was killed (i.e. ASan caught an over-read).
fn raw_crashes(fuzz_one: &str, data: &[u8]) -> bool {
    let mut child = Command::new(fuzz_one)
        .env("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1:exitcode=99")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fuzz_one");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(data)
        .ok();
    let status = child.wait().expect("wait");
    // Success exit is 0; any crash/abort/ASan exit is non-zero.
    !status.success()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fuzz_one = args.get(1).cloned().unwrap_or_else(|| "fuzz_one".into());
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let seed: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0xD1CE);

    let mut rng = Rng(seed | 1);

    let (mut accepted, mut rejected) = (0usize, 0usize);
    let (mut raw_crash, mut raw_ok) = (0usize, 0usize);
    // The dangerous cell: accepted by airlock AND crashes raw parser. Must be 0.
    let mut accepted_and_crash = 0usize;
    // Sanity: rejected by airlock but raw parser happened not to crash (fine).
    let mut rejected_but_raw_ok = 0usize;
    let mut accepted_examples: Vec<String> = Vec::new();

    for _ in 0..iters {
        let pkt = gen_packet(&mut rng);
        let verdict = validate(&pkt);
        let crashes = raw_crashes(&fuzz_one, &pkt);

        match &verdict {
            Ok(()) => accepted += 1,
            Err(_) => rejected += 1,
        }
        if crashes {
            raw_crash += 1;
        } else {
            raw_ok += 1;
        }
        match (verdict.is_ok(), crashes) {
            (true, true) => accepted_and_crash += 1,
            (false, false) => rejected_but_raw_ok += 1,
            _ => {}
        }
        if verdict.is_ok() && accepted_examples.len() < 3 {
            accepted_examples.push(format!("{:02x?}", pkt));
        }
    }

    println!("Differential fuzz: {iters} packets, seed {seed:#x}");
    println!("  airlock accepted : {accepted}");
    println!("  airlock rejected : {rejected}");
    println!("  raw parser crashed (ASan) : {raw_crash}");
    println!("  raw parser survived       : {raw_ok}");
    println!();
    println!("  >>> accepted-by-airlock AND crashes-raw : {accepted_and_crash}  (MUST be 0)");
    println!("      rejected-by-airlock but raw survived : {rejected_but_raw_ok}  (expected; not every malformed packet over-reads)");
    if !accepted_examples.is_empty() {
        println!("  sample accepted packets:");
        for e in &accepted_examples {
            println!("    {e}");
        }
    }

    if accepted_and_crash != 0 {
        eprintln!("\nFAIL: the airlock let through a packet that crashes the raw parser.");
        std::process::exit(1);
    }
    println!("\nPASS: no packet that crashes the raw parser got past the airlock.");
}
