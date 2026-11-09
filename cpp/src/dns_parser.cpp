// dns_parser.cpp — unsafe-by-design DNS parser. See dns_parser.h.
//
// The vulnerability: decode_name() follows DNS label-length bytes and 0xC0
// compression pointers with no check that the cursor stays within [data, data+len).
// A label whose length runs off the end of the buffer, or a compression pointer
// that aims past the end (or loops), causes an out-of-bounds read. Compiled with
// -fsanitize=address this is reported as a heap-buffer-overflow READ.

#include "dns_parser.h"

#include <cstring>

namespace dnscore {

namespace {

uint16_t read_u16(const uint8_t* p) {
    // Big-endian, as DNS is on the wire.
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// Decode a (possibly compressed) DNS name starting at offset `pos`.
// Advances `pos` past the name in the *linear* stream (for the question that
// contained it) and returns the decoded dotted string.
//
// BUG: none of the reads below are bounds-checked against `len`.
std::string decode_name(const uint8_t* data, size_t len, size_t& pos) {
    std::string name;
    size_t cursor = pos;
    bool jumped = false;
    size_t safety = 0;  // only guards against a totally infinite loop at ASan's mercy

    while (true) {
        // UNCHECKED read of the length byte. If cursor >= len, this is OOB.
        uint8_t label_len = data[cursor];

        if (label_len == 0) {
            cursor += 1;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            // Compression pointer: next byte completes the 14-bit offset.
            // UNCHECKED read of the second pointer byte.
            uint16_t ptr = static_cast<uint16_t>(((label_len & 0x3F) << 8) | data[cursor + 1]);
            if (!jumped) {
                pos = cursor + 2;  // the name in the linear stream ends after the pointer
                jumped = true;
            }
            // BUG: ptr is attacker-controlled and never checked against len.
            cursor = ptr;
            if (++safety > 65535) break;  // avoid a truly unbounded loop
            continue;
        }

        // A normal label: copy `label_len` bytes.
        if (!name.empty()) name.push_back('.');
        // UNCHECKED: copies label_len bytes starting at cursor+1, no check that
        // cursor + 1 + label_len <= len. This is the compose_name-style over-read.
        for (uint8_t i = 0; i < label_len; ++i) {
            name.push_back(static_cast<char>(data[cursor + 1 + i]));
        }
        cursor += 1 + label_len;
        if (++safety > 65535) break;
    }

    if (!jumped) pos = cursor;
    return name;
}

}  // namespace

bool parse_message(const uint8_t* data, size_t len, Message& out) {
    // The only bounds check in the whole parser: the fixed 12-byte header.
    if (len < 12) return false;

    out.id = read_u16(data + 0);
    out.flags = read_u16(data + 2);
    out.qdcount = read_u16(data + 4);
    out.ancount = read_u16(data + 6);
    out.nscount = read_u16(data + 8);
    out.arcount = read_u16(data + 10);

    size_t pos = 12;
    out.questions.clear();

    // Walk qdcount questions. qdcount is attacker-controlled; the loop trusts it.
    for (uint16_t q = 0; q < out.qdcount; ++q) {
        Question question;
        question.qname = decode_name(data, len, pos);
        // UNCHECKED reads of QTYPE and QCLASS.
        question.qtype = read_u16(data + pos);
        question.qclass = read_u16(data + pos + 2);
        pos += 4;
        out.questions.push_back(std::move(question));
    }

    return true;
}

bool parse_message_bytes(const std::vector<uint8_t>& data, Message& out) {
    return parse_message(data.data(), data.size(), out);
}

}  // namespace dnscore
