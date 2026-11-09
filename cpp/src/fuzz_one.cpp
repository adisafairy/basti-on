// fuzz_one.cpp — reads a single DNS packet from stdin and feeds it to the raw
// (unguarded) C++ parser. Built with ASan. Exit codes:
//   0  parsed without a memory error
//   non-zero / ASan abort  -> the packet triggered an out-of-bounds access
//
// Used by scripts/differential_fuzz.sh to classify random packets. Running each
// packet in its own process is what makes a crash observable instead of fatal
// to the whole run.

#include "dns_parser.h"

#include <cstdint>
#include <cstdio>
#include <vector>

int main() {
    std::vector<uint8_t> data;
    int c;
    while ((c = getchar()) != EOF) {
        data.push_back(static_cast<uint8_t>(c));
    }
    dnscore::Message msg;
    dnscore::parse_message(data.data(), data.size(), msg);
    return 0;
}
