// dns_parser_bridge.cc — fills the cxx-generated Message out of the unsafe
// hand-written parser. Compiled as its own translation unit.

#include "dns_parser_bridge.h"
#include "dns_parser.h"

#include <utility>
#include <vector>

namespace dnsparser {

Message parse_message_ffi(rust::Slice<const uint8_t> data) {
    std::vector<uint8_t> bytes(data.begin(), data.end());

    ::dnscore::Message native;
    ::dnscore::parse_message(bytes.data(), bytes.size(), native);

    Message out;
    out.id = native.id;
    out.flags = native.flags;
    out.qdcount = native.qdcount;
    out.ancount = native.ancount;
    out.nscount = native.nscount;
    out.arcount = native.arcount;
    for (const auto& q : native.questions) {
        Question bq;
        bq.qname = rust::String(q.qname);
        bq.qtype = q.qtype;
        bq.qclass = q.qclass;
        out.questions.push_back(std::move(bq));
    }
    return out;
}

}  // namespace dnsparser
