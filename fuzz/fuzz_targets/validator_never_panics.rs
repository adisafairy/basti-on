#![no_main]
//! Fuzzes the validator alone (pure safe Rust, no C++). It must never panic and
//! never read out of bounds on ANY input — it either returns Ok or a
//! RejectReason. This proves the airlock itself is robust.
//!
//!     cargo +nightly fuzz run validator_never_panics
//!
//! No ASan needed: safe Rust can't have the C++ bug. This guards against logic
//! panics (e.g. an arithmetic overflow in an index calculation).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = airlock::validate(data);
});
