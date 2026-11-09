//! Throughput benchmark: how much does the airlock cost on good traffic?
//!
//!   cargo run --release --example bench
//!
//! It parses a batch of *valid* DNS queries many times over, once through the
//! raw path (C++ only) and once through the guarded path (Rust validate + C++),
//! and reports packets/sec for each plus the overhead. Valid traffic is the
//! fair comparison: that is the common case, and it is where the airlock adds
//! work without saving a crash. (On malformed traffic the airlock is *faster*,
//! because it rejects early and never enters C++.)
//!
//! Note: this build links C++ WITHOUT AddressSanitizer (the default), so the
//! numbers reflect production-style speed, not instrumented speed.

use std::time::Instant;

use airlock::{parse_guarded, parse_unguarded};

fn valid_packets() -> Vec<Vec<u8>> {
    let names: &[&[&str]] = &[
        &["example", "com"],
        &["www", "google", "com"],
        &["a", "b", "c", "d", "e"],
        &["mail", "protonmail", "ch"],
        &["very", "long", "subdomain", "name", "here", "org"],
    ];
    names
        .iter()
        .map(|labels| {
            let mut p = vec![0u8; 12];
            p[5] = 1; // qdcount
            for l in *labels {
                p.push(l.len() as u8);
                p.extend_from_slice(l.as_bytes());
            }
            p.push(0);
            p.extend_from_slice(&[0, 1, 0, 1]);
            p
        })
        .collect()
}

fn main() {
    let packets = valid_packets();
    let rounds: usize = 200_000;
    let total = rounds * packets.len();

    // Warm up both paths.
    for p in &packets {
        let _ = parse_unguarded(p);
        let _ = parse_guarded(p);
    }

    let t0 = Instant::now();
    let mut sink = 0u64;
    for _ in 0..rounds {
        for p in &packets {
            let m = parse_unguarded(p);
            sink = sink.wrapping_add(m.qdcount as u64);
        }
    }
    let raw = t0.elapsed();

    let t1 = Instant::now();
    for _ in 0..rounds {
        for p in &packets {
            if let Ok(m) = parse_guarded(p) {
                sink = sink.wrapping_add(m.qdcount as u64);
            }
        }
    }
    let guarded = t1.elapsed();

    let raw_pps = total as f64 / raw.as_secs_f64();
    let guarded_pps = total as f64 / guarded.as_secs_f64();
    let overhead = (guarded.as_secs_f64() / raw.as_secs_f64() - 1.0) * 100.0;

    println!("Benchmark: {total} valid packets per path (checksum {sink})");
    println!("  raw (C++ only)          : {raw_pps:>12.0} packets/sec  [{raw:?}]");
    println!("  guarded (Rust + C++)    : {guarded_pps:>12.0} packets/sec  [{guarded:?}]");
    println!("  airlock overhead        : {overhead:+.1}%");
    println!();
    println!("  Note: run on your own machine for numbers you can cite; a shared");
    println!("  sandbox is noisy. Overhead is dominated by one bounds-checked");
    println!("  pass over the packet, which is cheap next to building the result.");
}
