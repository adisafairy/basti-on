#![no_main]
//! Fuzzes the UNGUARDED path: raw bytes straight into the unsafe C++ parser.
//!
//! Build the C++ with AddressSanitizer so the over-reads are caught:
//!     AIRLOCK_ASAN=1 cargo +nightly fuzz run raw_parser
//!
//! This target is EXPECTED TO CRASH, usually within seconds. The crash it finds
//! is the baseline: it is what the airlock exists to prevent. Keep the crashing
//! input (cargo-fuzz saves it under fuzz/artifacts/) for the write-up.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bastion::parse_unguarded(data);
});
