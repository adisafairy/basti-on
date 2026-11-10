#!/usr/bin/env bash
# Starts examples/dns_guard on 127.0.0.1, sends it real lookups, the crafted
# attack packets and non-standard queries, and prints what came back for each
# and how long it took, then the guard's own log. The real lookups need network
# access to the upstream resolver (default 1.1.1.1).
#
# With the airlock on it also runs a freeze test: a second guard points at
# 192.0.2.1 (a documentation address that never answers) and gets 5 lookups at
# once. With the worker pool they should all fail together after about 2 s.
#
#   scripts/dns_guard_demo.sh [--no-airlock]
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-5353}
UPSTREAM=${UPSTREAM:-1.1.1.1:53}
LOG=$(mktemp)
LOG2=$(mktemp)
GUARD2=""

cargo build --release --quiet --example dns_guard
./target/release/examples/dns_guard --listen "127.0.0.1:$PORT" --upstream "$UPSTREAM" \
    --block ads.example.com "$@" >"$LOG" 2>&1 &
GUARD=$!
trap 'kill $GUARD $GUARD2 2>/dev/null || true; rm -f "$LOG" "$LOG2"' EXIT
sleep 0.5

python3 - "$PORT" <<'PY'
import socket, struct, sys, time

port = int(sys.argv[1])

def header(qd=1, ident=0x1234, flags=0x0100):
    return struct.pack(">HHHHHH", ident, flags, qd, 0, 0, 0)

def name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"

def query(n, qtype=1, flags=0x0100):
    return header(flags=flags) + name(n) + struct.pack(">HH", qtype, 1)

def skip_name(r, i):
    while True:
        l = r[i]
        if l == 0:
            return i + 1
        if l & 0xC0 == 0xC0:
            return i + 2
        i += 1 + l

def summarize(r):
    rcode = r[3] & 0x0F
    an = struct.unpack(">H", r[6:8])[0]
    names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
    out = f"{names.get(rcode, rcode)}, {an} answer(s)"
    try:
        i = 12
        for _ in range(struct.unpack(">H", r[4:6])[0]):
            i = skip_name(r, i) + 4
        ips = []
        for _ in range(an):
            i = skip_name(r, i)
            t, _, _, rdlen = struct.unpack(">HHIH", r[i:i + 10])
            i += 10
            if t == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(r[i:i + 4]))
            i += rdlen
        if ips:
            out += ": " + ", ".join(ips[:3])
    except Exception:
        pass
    return out

cases = [
    ("real lookup: example.com", query("example.com")),
    ("real lookup: github.com", query("github.com")),
    ("blocklisted: ads.example.com", query("ads.example.com")),
    ("attack: label runs off the end", header() + bytes([40, 0x78])),
    ("attack: pointer past the end", header() + bytes([0xC0, 0xFF])),
    ("attack: pointer loop", header() + bytes([1, 0x61, 0xC0, 0x0C])),
    ("attack: question count lies", header(qd=5) + name("example.com") + struct.pack(">HH", 1, 1)),
    ("odd but valid: non-UTF-8 byte in name", header() + bytes([1, 0xFF, 0]) + struct.pack(">HH", 1, 1)),
    ("non-standard: header only, 0 questions", header(qd=0)),
    ("non-standard: a reply sent as a query", query("example.com", flags=0x8100)),
    ("junk: 5 random bytes", bytes([0x9B, 0x58, 0xA0, 0x9B, 0x3C])),
    ("still alive? example.com again", query("example.com")),
]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
print(f"{'what we sent':40} {'time':>7}  what came back")
print(f"{'-' * 40} {'-' * 7}  {'-' * 36}")
for label, pkt in cases:
    t = time.time()
    s.sendto(pkt, ("127.0.0.1", port))
    try:
        r, _ = s.recvfrom(4096)
        print(f"{label:40} {1000 * (time.time() - t):5.0f}ms  {summarize(r)}")
    except socket.timeout:
        print(f"{label:40} {1000 * (time.time() - t):5.0f}ms  no reply")
PY

echo
echo "Guard log:"
cat "$LOG"
if kill -0 "$GUARD" 2>/dev/null; then echo; echo "Guard still running after all of that: yes"; else echo; echo "Guard still running after all of that: NO (it crashed)"; fi

case " $* " in *" --no-airlock "*) exit 0 ;; esac

echo
echo "Freeze test: 5 lookups at once to a guard whose upstream (192.0.2.1) never answers"
PORT2=$((PORT + 1))
./target/release/examples/dns_guard --listen "127.0.0.1:$PORT2" --upstream 192.0.2.1:53 >"$LOG2" 2>&1 &
GUARD2=$!
sleep 0.5
python3 - "$PORT2" <<'PY'
import socket, struct, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(12)
t = time.time()
for i in range(5):
    q = struct.pack(">HHHHHH", 0x5000 + i, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    s.sendto(q, ("127.0.0.1", port))
got = []
for _ in range(5):
    r, _ = s.recvfrom(512)
    got.append(r[3] & 15)
names = {2: "SERVFAIL"}
print(f"  all 5 answered after {time.time() - t:.1f} s: " + ", ".join(names.get(c, str(c)) for c in got))
print("  (one at a time with a 2 s wait each would take about 10 s)")
PY
