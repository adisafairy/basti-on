// dns_parser_bridge.h — declaration of the cxx entry point. The definition is
// in cpp/src/dns_parser_bridge.cc, which is compiled separately so the
// cxx-generated Vec<Question> specializations are fully defined before use.

#pragma once

#include "basti-on/src/lib.rs.h"  // cxx-generated: dnsparser::Message, Question

#include <cstdint>

#include "rust/cxx.h"

namespace dnsparser {

// Entry point the Rust side calls. Copies the slice and runs the unsafe parser.
Message parse_message_ffi(rust::Slice<const uint8_t> data);

}  // namespace dnsparser
