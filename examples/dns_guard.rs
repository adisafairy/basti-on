//! A real DNS forwarder with the Basti-on airlock in front of the C++ parser.
//!
//!   cargo run --release --example dns_guard -- \
//!       [--listen 127.0.0.1:5353] [--upstream 1.1.1.1:53] [--block NAME]... [--no-airlock]
//!
//! Every query that arrives on `--listen` goes through `validate()` first.
//! Malformed queries are answered with FORMERR (or dropped when they are too
//! short to answer) and never reach the C++ parser. Well-formed queries are
//! parsed by the C++ parser through `parse_guarded()`, checked against the
//! blocklist, and forwarded to the upstream resolver by a pool of worker
//! threads; the upstream reply is relayed back unchanged.
//!
//! Two guard-level rules keep it available, separate from the airlock's
//! memory-safety job:
//!   * queries that are well-formed but not standard (no question, more than
//!     one, the QR "reply" bit set, or an unassigned opcode) get an immediate
//!     error reply instead of being forwarded, because resolvers ignore them and
//!     the guard would sit waiting;
//!   * forwarding runs on `WORKERS` threads behind a bounded queue, so a slow or
//!     silent upstream ties up one worker, not the whole guard. If the queue is
//!     full the client gets SERVFAIL straight away, and an upstream timeout also
//!     answers SERVFAIL rather than leaving the client hanging.
//!
//! `--no-airlock` skips `validate()` and hands every query straight to the C++
//! parser, to show what the airlock prevents: malformed queries make it read
//! past the end of the packet. Never expose that mode to a network.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bastion::{parse_guarded, parse_unguarded, validate, Message};

const WORKERS: usize = 16;
const QUEUE: usize = 256;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

const FORMERR: u8 = 1;
const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;

struct Config {
    listen: SocketAddr,
    upstream: SocketAddr,
    blocklist: Vec<String>,
    airlock: bool,
}

fn parse_args() -> Config {
    let mut cfg = Config {
        listen: "127.0.0.1:5353".parse().unwrap(),
        upstream: "1.1.1.1:53".parse().unwrap(),
        blocklist: Vec::new(),
        airlock: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().unwrap_or_else(|| panic!("{name} needs a value"));
        match a.as_str() {
            "--listen" => cfg.listen = value("--listen").parse().expect("--listen: use IP:PORT"),
            "--upstream" => cfg.upstream = value("--upstream").parse().expect("--upstream: use IP:PORT"),
            "--block" => cfg.blocklist.push(value("--block").trim_end_matches('.').to_ascii_lowercase()),
            "--no-airlock" => cfg.airlock = false,
            other => panic!("unknown argument: {other}"),
        }
    }
    cfg
}

#[derive(Default)]
struct Totals {
    forwarded: AtomicU64,
    blocked: AtomicU64,
    rejected: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
}

impl Totals {
    fn line(&self) -> String {
        format!(
            "         totals: {} forwarded, {} blocked, {} rejected, {} upstream failures, {} dropped by the airlock",
            self.forwarded.load(Relaxed),
            self.blocked.load(Relaxed),
            self.rejected.load(Relaxed),
            self.failed.load(Relaxed),
            self.dropped.load(Relaxed)
        )
    }
}

/// Print an event and the running totals as one write, so lines from worker
/// threads never interleave.
fn log(event: String, totals: &Totals) {
    println!("{event}\n{}", totals.line());
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// Error reply for a query whose header we can read: same ID and opcode, QR
/// and RA set, the given RCODE, no sections.
fn error_reply(q: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if q.len() < 12 {
        return None;
    }
    Some(vec![q[0], q[1], 0x80 | (q[2] & 0x79), 0x80 | rcode, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// Offset just past the first question. Only called on validated packets, but
/// it still uses checked reads.
fn first_question_end(q: &[u8]) -> Option<usize> {
    let mut pos = 12;
    loop {
        let len = *q.get(pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len as usize;
    }
    (pos + 4 <= q.len()).then_some(pos + 4)
}

/// NXDOMAIN reply that echoes the first question, used for blocked names.
fn nxdomain(q: &[u8]) -> Option<Vec<u8>> {
    let end = first_question_end(q)?;
    let mut r = vec![q[0], q[1], 0x80 | (q[2] & 0x79), 0x80 | NXDOMAIN, 0, 1, 0, 0, 0, 0, 0, 0];
    r.extend_from_slice(&q[12..end]);
    Some(r)
}

/// Guard rule: only forward standard queries with exactly one question.
/// Resolvers ignore the rest, which would leave a worker waiting on them.
fn not_standard(q: &[u8]) -> Option<(String, u8)> {
    if q.len() < 12 {
        return Some(("shorter than a DNS header".into(), FORMERR));
    }
    if q[2] & 0x80 != 0 {
        return Some(("QR bit set, so it is a reply, not a query".into(), FORMERR));
    }
    let opcode = (q[2] >> 3) & 0x0F;
    if opcode != 0 {
        return Some((format!("opcode {opcode} is not a standard query"), NOTIMP));
    }
    let qdcount = u16::from_be_bytes([q[4], q[5]]);
    if qdcount != 1 {
        return Some((format!("{qdcount} questions, resolvers expect exactly 1"), FORMERR));
    }
    None
}

fn is_blocked(name: &str, blocklist: &[String]) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    blocklist.iter().any(|b| name == *b || name.ends_with(&format!(".{b}")))
}

fn describe(m: &Message) -> String {
    match m.questions.first() {
        Some(q) => format!("{} {}", q.qname.escape_debug(), qtype_name(q.qtype)),
        None => "(no question)".into(),
    }
}

struct Job {
    query: Vec<u8>,
    client: SocketAddr,
    what: String,
    started: Instant,
}

/// Send the query upstream and wait, up to the timeout, for the reply with
/// the same ID.
fn forward(upstream: &UdpSocket, to: SocketAddr, q: &[u8]) -> std::io::Result<Vec<u8>> {
    upstream.send_to(q, to)?;
    let deadline = Instant::now() + UPSTREAM_TIMEOUT;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        upstream.set_read_timeout(Some(left))?;
        let (n, from) = upstream.recv_from(&mut buf)?;
        if from == to && n >= 2 && buf[..2] == q[..2] {
            return Ok(buf[..n].to_vec());
        }
    }
}

fn worker(jobs: Arc<Mutex<Receiver<Job>>>, server: UdpSocket, to: SocketAddr, totals: Arc<Totals>) {
    let upstream = UdpSocket::bind("0.0.0.0:0").expect("bind upstream socket");
    loop {
        let job = match jobs.lock().unwrap().recv() {
            Ok(j) => j,
            Err(_) => return,
        };
        match forward(&upstream, to, &job.query) {
            Ok(reply) => {
                totals.forwarded.fetch_add(1, Relaxed);
                let _ = server.send_to(&reply, job.client);
                log(
                    format!("OK       {} -> {to}, {} bytes back in {} ms", job.what, reply.len(), job.started.elapsed().as_millis()),
                    &totals,
                );
            }
            Err(e) => {
                totals.failed.fetch_add(1, Relaxed);
                if let Some(r) = error_reply(&job.query, SERVFAIL) {
                    let _ = server.send_to(&r, job.client);
                }
                log(format!("UPSTREAM {} -> no answer from {to} ({e}), replied SERVFAIL", job.what), &totals);
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let cfg = parse_args();
    let server = UdpSocket::bind(cfg.listen)?;
    let totals = Arc::new(Totals::default());

    let (tx, rx) = sync_channel::<Job>(QUEUE);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let (rx, server, totals) = (rx.clone(), server.try_clone()?, totals.clone());
        let to = cfg.upstream;
        thread::spawn(move || worker(rx, server, to, totals));
    }

    println!(
        "dns_guard listening on {}  upstream {}  airlock {}  {WORKERS} workers{}",
        cfg.listen,
        cfg.upstream,
        if cfg.airlock { "ON" } else { "OFF (unsafe)" },
        if cfg.blocklist.is_empty() { String::new() } else { format!("  blocking {}", cfg.blocklist.join(", ")) }
    );

    let mut buf = [0u8; 4096];
    loop {
        let (n, client) = server.recv_from(&mut buf)?;
        let q = &buf[..n];
        let started = Instant::now();

        // The airlock: malformed queries stop here and never reach C++.
        let parsed = if cfg.airlock {
            if let Err(reason) = validate(q) {
                totals.dropped.fetch_add(1, Relaxed);
                let reply = error_reply(q, FORMERR);
                if let Some(r) = &reply {
                    server.send_to(r, client)?;
                }
                log(
                    format!(
                        "DROP     {n:>3} bytes from {client}  {reason:?}, C++ never ran -> {}",
                        if reply.is_some() { "FORMERR" } else { "no reply" }
                    ),
                    &totals,
                );
                continue;
            }
            parse_guarded(q).expect("validated above")
        } else {
            parse_unguarded(q)
        };
        let what = describe(&parsed);

        // Guard rule: answer non-standard queries now instead of forwarding them.
        if let Some((why, rcode)) = not_standard(q) {
            totals.rejected.fetch_add(1, Relaxed);
            let reply = error_reply(q, rcode);
            if let Some(r) = &reply {
                server.send_to(r, client)?;
            }
            let code = match (reply.is_some(), rcode) {
                (false, _) => "no reply",
                (true, NOTIMP) => "NOTIMP",
                _ => "FORMERR",
            };
            log(format!("REJECT   {what} -> {code} ({why})"), &totals);
            continue;
        }

        if parsed.questions.iter().any(|qq| is_blocked(&qq.qname, &cfg.blocklist)) {
            totals.blocked.fetch_add(1, Relaxed);
            if let Some(r) = nxdomain(q).or_else(|| error_reply(q, FORMERR)) {
                server.send_to(&r, client)?;
            }
            log(format!("BLOCK    {what} -> NXDOMAIN (blocklist)"), &totals);
            continue;
        }

        // Hand forwarding to the worker pool; if it is saturated, fail fast.
        let job = Job { query: q.to_vec(), client, what, started };
        if let Err(TrySendError::Full(job)) = tx.try_send(job) {
            totals.failed.fetch_add(1, Relaxed);
            if let Some(r) = error_reply(&job.query, SERVFAIL) {
                server.send_to(&r, client)?;
            }
            log(format!("BUSY     {} -> SERVFAIL (all {WORKERS} workers busy, queue full)", job.what), &totals);
        }
    }
}
