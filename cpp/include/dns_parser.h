// dns_parser.h — a deliberately memory-UNSAFE DNS message parser.
//
// This is the "legacy C++ engine" in the airlock demo. It models a real,
// documented class of bug: an out-of-bounds read while decompressing a DNS
// name, the same family as libtins CVE-2026-112273 (DNS::compose_name) and the
// nmap DNS over-reads found by AFL. The parser trusts its input: it walks
// length-prefixed labels and follows compression pointers without ever checking
// that it stays inside the packet buffer.
//
// It exists to be fuzzed and crashed, so the Rust airlock in front of it has
// something real to protect. Do NOT copy this into production code.

#ifndef AIRLOCK_DNS_PARSER_H
#define AIRLOCK_DNS_PARSER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dnscore {

struct Question {
    std::string qname;   // decoded, dot-joined domain name
    uint16_t qtype = 0;
    uint16_t qclass = 0;
};

struct Message {
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t qdcount = 0;
    uint16_t ancount = 0;
    uint16_t nscount = 0;
    uint16_t arcount = 0;
    std::vector<Question> questions;
};

// Parse a raw DNS message. Returns true on "success". This function performs
// NO bounds checking on label lengths or compression pointers — feeding it a
// crafted packet can read past the end of `data`. That is the whole point.
bool parse_message(const uint8_t* data, size_t len, Message& out);

// Convenience wrapper over a byte vector (used by the cxx bridge).
bool parse_message_bytes(const std::vector<uint8_t>& data, Message& out);

}  // namespace dnscore

#endif  // AIRLOCK_DNS_PARSER_H
