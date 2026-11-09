//! Side-by-side: the same crafted packets that make the raw C++ parser read out
//! of bounds are rejected by the airlock before C++ is ever called.
//!
//!   cargo run --example airlock_vs_raw
//!
//! This binary only exercises the *guarded* path, so it is safe to run with no
//! sanitizer. The matching crashes on the unguarded path are shown by the ASan
//! demo (`scripts/run_asan_demo.sh`).

use airlock::{parse_guarded, validate};

fn header(qdcount: u16) -> Vec<u8> {
    let mut h = vec![0u8; 12];
    h[4..6].copy_from_slice(&qdcount.to_be_bytes());
    h
}

fn main() {
    // The two packets that crash the raw C++ parser under ASan.
    let mut label_overread = header(1);
    label_overread.extend_from_slice(&[40, b'x']); // label claims 40 bytes; 1 present

    let mut pointer_overread = header(1);
    pointer_overread.extend_from_slice(&[0xC0, 0xFF]); // pointer to 0x3FFF, off the end

    // A genuinely valid query, to show the airlock lets good traffic through.
    let mut valid = header(1);
    valid.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    valid.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    for (name, pkt) in [
        ("label over-read", &label_overread),
        ("compression-pointer over-read", &pointer_overread),
        ("valid example.com query", &valid),
    ] {
        print!("{name:32} -> ");
        match parse_guarded(pkt) {
            Ok(msg) => {
                let q = msg
                    .questions
                    .first()
                    .map(|q| q.qname.clone())
                    .unwrap_or_else(|| "<none>".into());
                println!("ACCEPTED, parsed qname = {q:?}");
            }
            Err(reason) => {
                // The airlock caught it. C++ was never called. No crash.
                println!("REJECTED by airlock ({reason:?}) — C++ never ran");
                debug_assert!(validate(pkt).is_err());
            }
        }
    }
}
