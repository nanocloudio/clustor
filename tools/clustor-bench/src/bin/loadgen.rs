//! `clustor-loadgen` — off-DUT open-loop load generator (RFC §5.2/§5.3).
//!
//! Drives the DUT over the real client path (`POST /propose` by default; any
//! POST path via `--path`) at a fixed offered rate using a Poisson-free fixed
//! interval arrival process, sharded across worker threads, each with its own
//! latency histogram merged at the end. Latency is **coordinated-omission
//! corrected**: each request's latency is measured from its *intended* send
//! time, so a stalled server shows up as a growing tail instead of stopping
//! the clock.
//!
//! It also self-reports the RFC §2.4 harness-headroom verdict — achieved vs
//! offered rate — so a run that the generator (not the DUT) bottlenecked is
//! flagged `HARNESS_BOUND` rather than silently reported as a DUT ceiling.
//!
//! Usage:
//!   clustor-loadgen --host 192.168.1.9:9090 --rate 2000 --duration 10 \
//!       --conns 4 --path /propose --body 64
//!
//! std-only: one OS thread per shard, raw `http_post`. Fine for a Pi-class
//! driver at the rates a 1 GbE link admits; for >~10k conns move to mio/tokio.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use clustor_bench::{http_post, JsonObj, LatencyHist};

struct Args {
    host: String,
    path: String,
    rate: u64,
    duration_secs: u64,
    conns: u64,
    body_size: usize,
}

fn usage() -> ! {
    eprintln!(
        "clustor-loadgen --host <addr:port> --rate <req/s> [--duration N]\n\
         \x20  [--conns N] [--path /propose] [--body <bytes>]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args {
        host: String::new(),
        path: "/propose".to_string(),
        rate: 1000,
        duration_secs: 10,
        conns: 4,
        body_size: 64,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut next = || it.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--host" => a.host = next(),
            "--path" => a.path = next(),
            "--rate" => a.rate = next().parse().unwrap_or_else(|_| usage()),
            "--duration" => a.duration_secs = next().parse().unwrap_or_else(|_| usage()),
            "--conns" => a.conns = next().parse().unwrap_or_else(|_| usage()),
            "--body" => a.body_size = next().parse().unwrap_or_else(|_| usage()),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown flag: {other}");
                usage();
            }
        }
    }
    if a.host.is_empty() || a.rate == 0 || a.conns == 0 {
        usage();
    }
    a
}

struct ShardResult {
    hist: LatencyHist,
    sent: u64,
    ok: u64,
    errors: u64,
}

fn run_shard(
    host: String,
    path: String,
    per_shard_rate: f64,
    duration: Duration,
    body: Vec<u8>,
) -> ShardResult {
    let mut hist = LatencyHist::new();
    let mut sent = 0u64;
    let mut ok = 0u64;
    let mut errors = 0u64;
    let interval = Duration::from_secs_f64(1.0 / per_shard_rate);
    let start = Instant::now();
    let mut i: u64 = 0;
    loop {
        let intended = start + interval * (i as u32);
        let now = Instant::now();
        if now >= start + duration {
            break;
        }
        if intended > now {
            std::thread::sleep(intended - now);
        }
        // Coordinated-omission correction: latency measured from the INTENDED
        // arrival, not the actual send — a slow server inflates the tail
        // rather than pacing our loop.
        let send_instant = Instant::now();
        match http_post(&host, &path, &body, Duration::from_secs(5)) {
            Ok((status, _)) => {
                if (200..400).contains(&status) {
                    ok += 1;
                } else {
                    errors += 1;
                }
            }
            Err(_) => errors += 1,
        }
        let done = Instant::now();
        let latency = done.saturating_duration_since(intended.min(send_instant));
        hist.record(latency.as_micros() as u64);
        sent += 1;
        i += 1;
    }
    ShardResult {
        hist,
        sent,
        ok,
        errors,
    }
}

fn main() {
    let a = parse_args();
    let per_shard = a.rate as f64 / a.conns as f64;
    let duration = Duration::from_secs(a.duration_secs);
    let body = vec![b'x'; a.body_size];

    eprintln!(
        "[loadgen] host={} path={} offered={}/s conns={} dur={}s body={}B",
        a.host, a.path, a.rate, a.conns, a.duration_secs, a.body_size
    );

    let (tx, rx) = mpsc::channel();
    let wall = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..a.conns {
        let (host, path, body, tx) = (a.host.clone(), a.path.clone(), body.clone(), tx.clone());
        handles.push(std::thread::spawn(move || {
            let r = run_shard(host, path, per_shard, duration, body);
            let _ = tx.send(r);
        }));
    }
    drop(tx);

    let mut merged = LatencyHist::new();
    let (mut sent, mut ok, mut errors) = (0u64, 0u64, 0u64);
    for r in rx {
        merged.merge(&r.hist);
        sent += r.sent;
        ok += r.ok;
        errors += r.errors;
    }
    for h in handles {
        let _ = h.join();
    }
    let elapsed = wall.elapsed().as_secs_f64().max(0.001);
    let achieved = sent as f64 / elapsed;

    // RFC §2.4 headroom verdict: if the generator couldn't offer ≥ the target
    // rate, the run is harness-bound and excluded from DUT-ceiling baselines.
    let ratio = achieved / a.rate as f64;
    let verdict = if ratio < 0.9 {
        "HARNESS_BOUND"
    } else {
        "DUT_ATTRIBUTABLE"
    };

    let report = JsonObj::new()
        .str("schema", "clustor-loadgen/1")
        .str("host", &a.host)
        .str("path", &a.path)
        .num("offered_rate", a.rate)
        .num("achieved_rate", format!("{achieved:.1}"))
        .num("conns", a.conns)
        .num("sent", sent)
        .num("ok", ok)
        .num("errors", errors)
        .num("p50_us", merged.percentile(50.0))
        .num("p99_us", merged.percentile(99.0))
        .num("p999_us", merged.percentile(99.9))
        .num("max_us", merged.max())
        .num("mean_us", merged.mean())
        .str("headroom_verdict", verdict)
        .render();
    println!("{report}");
    eprintln!(
        "[loadgen] sent={sent} ok={ok} err={errors} achieved={achieved:.0}/s verdict={verdict}"
    );
}
