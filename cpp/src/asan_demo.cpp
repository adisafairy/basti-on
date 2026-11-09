// asan_demo.cpp — standalone proof that the C++ parser reads out of bounds.
//
// Build with AddressSanitizer and run; it feeds the parser a crafted DNS
// packet whose single label claims more bytes than the packet contains, then
// a second packet with a wild compression pointer. Either triggers an ASan
// heap-buffer-overflow READ. This is the "before" the airlock protects against.
//
//   clang++ -std=c++17 -fsanitize=address -g -Icpp/include \
//       cpp/src/dns_parser.cpp cpp/src/asan_demo.cpp -o asan_demo
//   ./asan_demo 1   # label over-read
//   ./asan_demo 2   # compression-pointer over-read

#include "dns_parser.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static std::vector<uint8_t> header(uint16_t qd) {
    std::vector<uint8_t> h = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    h[4] = qd >> 8;
    h[5] = qd & 0xFF;
    return h;
}

int main(int argc, char** argv) {
    int which = argc > 1 ? atoi(argv[1]) : 1;

    std::vector<uint8_t> packet = header(1);
    if (which == 1) {
        // Label says 40 bytes follow, but the buffer ends right after.
        packet.push_back(40);
        packet.push_back('x');  // only 1 of the 40 bytes is present
    } else {
        // Compression pointer to offset 0x3FFF — far past the buffer end.
        packet.push_back(0xC0);
        packet.push_back(0xFF);
    }

    // Heap-allocate the exact size so ASan has a tight redzone right after it.
    uint8_t* heap = static_cast<uint8_t*>(malloc(packet.size()));
    memcpy(heap, packet.data(), packet.size());

    printf("Feeding %zu-byte crafted packet to the unguarded C++ parser...\n",
           packet.size());
    fflush(stdout);

    dnscore::Message msg;
    dnscore::parse_message(heap, packet.size(), msg);  // <-- over-reads here

    // If ASan is off we may reach this line with garbage; with ASan we never do.
    printf("parsed id=%u qname=%s (no crash — ASan likely disabled)\n", msg.id,
           msg.questions.empty() ? "<none>" : msg.questions[0].qname.c_str());
    free(heap);
    return 0;
}
