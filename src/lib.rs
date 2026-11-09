//! # Basti-on
//!
//! A small, self-contained demonstration of the **airlock pattern**: put a
//! memory-safe Rust validator in front of a memory-unsafe C++ parser, so the
//! C++ only ever sees input that has already been proven well-formed.
//!
//! The C++ side (`cpp/`) is a DNS message parser that follows label lengths and
//! compression pointers with no bounds checks — a real, documented bug class
//! (CWE-125, as in libtins `DNS::compose_name`). On its own it reads out of
//! bounds on crafted packets.
//!
//! This crate exposes two entry points so the difference can be measured:
//!
//! * [`parse_unguarded`] — hands bytes straight to C++. **Unsafe**; crashes on
//!   bad input. This is the "before" baseline.
//! * [`parse_guarded`] — runs [`validate`] first and only calls C++ if the
//!   packet is well-formed. This is the "after": the airlock.
//!
//! The validator ([`validate`]) is pure safe Rust. It walks the exact same
//! structure the C++ walks, but every read is bounds-checked, every compression
//! pointer must point backwards and in-bounds, and total name length is capped.

use std::collections::HashSet;

#[cxx::bridge(namespace = "dnsparser")]
mod ffi {
    struct Question {
        qname: String,
        qtype: u16,
        qclass: u16,
    }

    struct Message {
        id: u16,
        flags: u16,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
        questions: Vec<Question>,
    }

    unsafe extern "C++" {
        include!("basti-on/cpp/include/dns_parser_bridge.h");

        // Calls into the unsafe C++ parser. `data` is a DNS message.
        fn parse_message_ffi(data: &[u8]) -> Message;
    }
}

pub use ffi::{Message, Question};

/// Why a packet was rejected by the airlock. Useful in tests and reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    TooShort,
    TruncatedName,
    LabelTooLong,
    NameTooLong,
    BadPointer,
    PointerLoop,
    TruncatedQuestion,
    TrailingGarbage,
}

const MAX_NAME_LEN: usize = 255; // RFC 1035 hard limit
const MAX_LABEL_LEN: usize = 63; // top two bits are reserved for the pointer marker

/// Validate a raw DNS message *without copying it into C++*.
///
/// Returns `Ok(())` if every label length and compression pointer stays inside
/// the buffer, names respect the RFC length limits, and there are no pointer
/// loops. Otherwise returns the first problem found. Pure safe Rust: it can
/// never itself read out of bounds, because every index goes through a checked
/// slice access.
pub fn validate(data: &[u8]) -> Result<(), RejectReason> {
    if data.len() < 12 {
        return Err(RejectReason::TooShort);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = validate_name(data, pos)?;
        // QTYPE (2) + QCLASS (2) must fit.
        if pos + 4 > data.len() {
            return Err(RejectReason::TruncatedQuestion);
        }
        pos += 4;
    }

    Ok(())
}

/// Validate one (possibly compressed) name starting at `start`. Returns the
/// offset in the linear stream just past the name.
fn validate_name(data: &[u8], start: usize) -> Result<usize, RejectReason> {
    let mut cursor = start;
    let mut linear_end: Option<usize> = None; // where the name ends in the flat stream
    let mut name_len = 0usize;
    let mut seen_pointers: HashSet<usize> = HashSet::new();

    loop {
        let len_byte = *data.get(cursor).ok_or(RejectReason::TruncatedName)?;

        if len_byte == 0 {
            let end = linear_end.unwrap_or(cursor + 1);
            return Ok(end);
        }

        if (len_byte & 0xC0) == 0xC0 {
            // Compression pointer. Need the second byte too.
            let b2 = *data.get(cursor + 1).ok_or(RejectReason::TruncatedName)?;
            let ptr = (((len_byte & 0x3F) as usize) << 8) | b2 as usize;

            if linear_end.is_none() {
                linear_end = Some(cursor + 2);
            }
            // Pointer must land inside the buffer...
            if ptr >= data.len() {
                return Err(RejectReason::BadPointer);
            }
            // ...and must point strictly backwards, which makes loops impossible.
            if ptr >= cursor {
                return Err(RejectReason::BadPointer);
            }
            if !seen_pointers.insert(ptr) {
                return Err(RejectReason::PointerLoop);
            }
            cursor = ptr;
            continue;
        }

        // A normal label.
        let label_len = len_byte as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(RejectReason::LabelTooLong);
        }
        let label_end = cursor + 1 + label_len;
        if label_end > data.len() {
            return Err(RejectReason::TruncatedName);
        }
        name_len += label_len + 1;
        if name_len > MAX_NAME_LEN {
            return Err(RejectReason::NameTooLong);
        }
        cursor = label_end;
    }
}

/// **Unsafe path (baseline).** Hand the bytes straight to the C++ parser with no
/// validation. Returns the parsed message. Will read out of bounds — and, under
/// AddressSanitizer, crash — on a crafted packet.
pub fn parse_unguarded(data: &[u8]) -> Message {
    ffi::parse_message_ffi(data)
}

/// **Guarded path (the airlock).** Validate first; only call C++ if the packet
/// is well-formed. On rejection, return the reason and never touch the C++.
pub fn parse_guarded(data: &[u8]) -> Result<Message, RejectReason> {
    validate(data)?;
    Ok(ffi::parse_message_ffi(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal valid query for "a.bc": header + labels + QTYPE/QCLASS.
    fn valid_query() -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
        ];
        m.extend_from_slice(&[1, b'a', 2, b'b', b'c', 0]); // name a.bc
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        m
    }

    #[test]
    fn accepts_valid() {
        let m = valid_query();
        assert!(validate(&m).is_ok());
        let parsed = parse_guarded(&m).expect("should parse");
        assert_eq!(parsed.qdcount, 1);
        assert_eq!(parsed.questions[0].qname, "a.bc");
    }

    #[test]
    fn rejects_short() {
        assert_eq!(validate(&[0u8; 5]), Err(RejectReason::TooShort));
    }

    #[test]
    fn rejects_label_running_off_end() {
        // header says 1 question; label claims 10 bytes but only 2 follow.
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[10, b'a', b'b']); // label_len 10, truncated
        assert_eq!(validate(&m), Err(RejectReason::TruncatedName));
    }

    #[test]
    fn rejects_forward_pointer() {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0xFF]); // pointer to offset 255, past the end
        assert_eq!(validate(&m), Err(RejectReason::BadPointer));
    }

    #[test]
    fn rejects_self_pointer_loop() {
        // pointer at offset 12 that points to 12 is not strictly backwards.
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0x0C]); // -> offset 12 (itself)
        assert_eq!(validate(&m), Err(RejectReason::BadPointer));
    }
}
