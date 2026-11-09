#![no_main]
//! Fuzzes the GUARDED path: every input goes through the Rust airlock first,
//! and the C++ parser only runs on inputs the airlock accepted.
//!
//!     AIRLOCK_ASAN=1 cargo +nightly fuzz run guarded_parser
//!
//! This target is EXPECTED TO SURVIVE. Run it for as long as you ran
//! `raw_parser` (ideally much longer — hours). If the airlock is correct, the
//! C++ parser never sees a malformed packet, so ASan never fires. A crash here
//! would mean the validator has a gap, which is itself a useful finding.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only well-formed packets reach C++. If this ever crashes, the airlock
    // accepted something it should have rejected.
    let _ = bastion::parse_guarded(data);
});
