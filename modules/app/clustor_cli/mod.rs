//! The clustor operator CLI as a fluxor cli-applet fmod
//! (rfc_cli_execution.md): ONE PIC module dispatches clustor subcommands over
//! the cli host surface. The `cli` stack injects cli_in/cli_out; this module
//! reads argv (NUL-separated, from `args`), routes on the subcommand, writes
//! output to `stdout` (→ cli_out.bytes_in), latches an exit code on `exit`
//! (→ cli_out.exit_in), and returns Done so the run-to-completion CLI exits.
//!
//!   clustor crc <hex>                  crc32c of the decoded bytes
//!   clustor wal-frame <payload_hex>    frame an entry as [len][crc32c][payload]
//!   clustor wal-scan <segment_hex>     walk a WAL segment image, replay-exact
//!   clustor help
//!
//! `wal-frame` and `wal-scan` run the IDENTICAL include!'d Crc32c core the
//! durability module runs, and `wal-scan` applies the same frame validation
//! as WAL replay (durability/wal.rs): a length of 0, > 2048, or past the end
//! of the image is a torn header; a CRC mismatch is a corrupt payload; either
//! way the scan stops and everything before it is the durable prefix — exactly
//! the log a replica would recover from that segment. A truncated scan exits
//! non-zero so scripts fail closed on a damaged segment.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");

// The repo's single CRC32C owner — identical source to the WAL's.
#[path = "../../common/collections.rs"]
mod collections;
use collections::Crc32c;
// The WAL frame contract itself — the same file durability's replay
// compiles, so wal-scan's verdict is replay's by construction.
#[path = "../../common/wal_frame.rs"]
mod wal_frame;
use wal_frame::{FRAME_HDR, MAX_ENTRY_LEN};

const PORT_INPUT: u8 = 0;
const PORT_OUTPUT: u8 = 1;
const STEP_DONE: i32 = 1;

const ARGV_BUF: usize = 8192;
const BIN_BUF: usize = 4096;
const OUT_BUF: usize = 8192;
/// Steps to wait for the argv record before defaulting to `help` (cli_in emits
/// it early; an empty argv — no `--` — never arrives, so we fall through).
const ARGV_WAIT: u32 = 2000;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// argv channel (input port 0 ← cli_in.args_out).
    args_chan: i32,
    /// stdout channel (output port 0 → cli_out.bytes_in).
    out_chan: i32,
    /// exit-code channel (output port 1 → cli_out.exit_in).
    exit_chan: i32,
    waited: u32,
    done: u8,
    // Large work buffers live in module state; `module_step` copies
    // argv to a stack scratch only to avoid aliasing `&mut State`.
    arec: [u8; ARGV_BUF],
    bin: [u8; BIN_BUF],
    framed: [u8; BIN_BUF],
    out: [u8; OUT_BUF],
}

fn append(dst: &mut [u8], at: usize, src: &[u8]) -> usize {
    let n = src.len().min(dst.len().saturating_sub(at));
    dst[at..at + n].copy_from_slice(&src[..n]);
    at + n
}

fn append_u64(dst: &mut [u8], at: usize, mut n: u64) -> usize {
    if at >= dst.len() {
        return at;
    }
    if n == 0 {
        dst[at] = b'0';
        return at + 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 && i < tmp.len() {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut p = at;
    while i > 0 && p < dst.len() {
        i -= 1;
        dst[p] = tmp[i];
        p += 1;
    }
    p
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.len() < bytes.len() * 2 {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
    }
    Some(bytes.len() * 2)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(hex: &[u8], out: &mut [u8]) -> Option<usize> {
    if hex.len() % 2 != 0 || out.len() < hex.len() / 2 {
        return None;
    }
    for i in 0..hex.len() / 2 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(hex.len() / 2)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut c = Crc32c::new();
    c.update(bytes);
    c.finalize()
}

/// Split the NUL-separated argv record into (start, end) spans.
fn split_argv(rec: &[u8], out: &mut [(usize, usize); 8]) -> usize {
    let mut n = 0;
    let mut start = 0;
    let mut i = 0;
    while i <= rec.len() && n < out.len() {
        if i == rec.len() || rec[i] == 0 {
            if i > start {
                out[n] = (start, i);
                n += 1;
            }
            start = i + 1;
        }
        i += 1;
    }
    n
}

fn cmd_help(out: &mut [u8]) -> usize {
    append(
        out,
        0,
        b"clustor - the replicated-log operator applet\n\
          \x20 clustor crc <hex>                  crc32c of the decoded bytes\n\
          \x20 clustor wal-frame <payload_hex>    frame an entry as [len][crc32c][payload]\n\
          \x20 clustor wal-scan <segment_hex>     walk a WAL segment image, replay-exact\n\
          \x20 clustor help\n\
          wal-scan applies the durability module's replay validation: it stops\n\
          at the first torn or corrupt frame and exits non-zero, so everything\n\
          it reports is exactly the durable prefix a replica would recover.\n",
    )
}

/// `crc <hex>`: CRC32C of the decoded bytes — the same Castagnoli core the
/// WAL uses for frame integrity.
fn cmd_crc(s: &mut State, hex: &[u8]) -> (usize, i32) {
    let Some(blen) = hex_decode(hex, &mut s.bin) else {
        return (append(&mut s.out, 0, b"error: not valid hex\n"), 1);
    };
    let crc = crc32c(&s.bin[..blen]);
    let mut hexed = [0u8; 8];
    let Some(hl) = hex_encode(&crc.to_be_bytes(), &mut hexed) else {
        return (append(&mut s.out, 0, b"error: encode\n"), 1);
    };
    let mut p = append(&mut s.out, 0, &hexed[..hl]);
    p = append(&mut s.out, p, b"\n");
    (p, 0)
}

/// `wal-frame <payload_hex>`: emit the framed entry
/// `[entry_len: u32 LE][crc32c: u32 LE][payload]` — byte-identical to what the
/// WAL appends to a segment, so the output feeds straight into `wal-scan`.
fn cmd_wal_frame(s: &mut State, payload_hex: &[u8]) -> (usize, i32) {
    let Some(plen) = hex_decode(payload_hex, &mut s.bin) else {
        return (
            append(&mut s.out, 0, b"error: payload is not valid hex\n"),
            1,
        );
    };
    if plen == 0 || plen > MAX_ENTRY_LEN {
        return (
            append(&mut s.out, 0, b"error: payload must be 1..2048 bytes\n"),
            1,
        );
    }
    let crc = crc32c(&s.bin[..plen]);
    s.framed[0..4].copy_from_slice(&(plen as u32).to_le_bytes());
    s.framed[4..8].copy_from_slice(&crc.to_le_bytes());
    s.framed[FRAME_HDR..FRAME_HDR + plen].copy_from_slice(&s.bin[..plen]);
    let mut hexed = [0u8; 2 * BIN_BUF];
    let Some(hl) = hex_encode(&s.framed[..FRAME_HDR + plen], &mut hexed) else {
        return (
            append(&mut s.out, 0, b"error: frame too large to print\n"),
            1,
        );
    };
    let mut p = append(&mut s.out, 0, &hexed[..hl]);
    p = append(&mut s.out, p, b"\n");
    (p, 0)
}

/// `wal-scan <segment_hex>`: walk framed entries with replay's exact
/// validation (durability/wal.rs). Reports term/index per entry (payloads of
/// >= 16 bytes carry term(8 LE) + index(8 LE) first, wire::decode_term_index's
/// layout), then either the clean-segment summary (exit 0) or the truncation
/// point (exit 1 — the durable prefix ends there).
fn cmd_wal_scan(s: &mut State, seg_hex: &[u8]) -> (usize, i32) {
    let Some(slen) = hex_decode(seg_hex, &mut s.bin) else {
        return (
            append(&mut s.out, 0, b"error: segment is not valid hex\n"),
            1,
        );
    };
    let mut pos = 0usize;
    let mut entries = 0u64;
    let mut p = 0usize;
    while slen - pos >= FRAME_HDR {
        let hdr_at = pos;
        let mut hdr = [0u8; FRAME_HDR];
        hdr.copy_from_slice(&s.bin[pos..pos + FRAME_HDR]);
        let (entry_len32, stored_crc) = wal_frame::parse_header(&hdr);
        let entry_len = entry_len32 as usize;
        if wal_frame::len_invalid(entry_len32, (slen - pos - FRAME_HDR) as u64) {
            p = append(&mut s.out, p, b"torn header at offset ");
            p = append_u64(&mut s.out, p, hdr_at as u64);
            p = append(&mut s.out, p, b" after ");
            p = append_u64(&mut s.out, p, entries);
            p = append(&mut s.out, p, b" entry(s) - durable prefix ends here\n");
            return (p, 1);
        }
        pos += FRAME_HDR;
        let payload = &s.bin[pos..pos + entry_len];
        if crc32c(payload) != stored_crc {
            p = append(&mut s.out, p, b"corrupt payload at offset ");
            p = append_u64(&mut s.out, p, hdr_at as u64);
            p = append(&mut s.out, p, b" after ");
            p = append_u64(&mut s.out, p, entries);
            p = append(&mut s.out, p, b" entry(s) - durable prefix ends here\n");
            return (p, 1);
        }
        p = append(&mut s.out, p, b"  entry ");
        p = append_u64(&mut s.out, p, entries);
        if entry_len >= 16 {
            let term = u64::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
                payload[7],
            ]);
            let index = u64::from_le_bytes([
                payload[8],
                payload[9],
                payload[10],
                payload[11],
                payload[12],
                payload[13],
                payload[14],
                payload[15],
            ]);
            p = append(&mut s.out, p, b": term=");
            p = append_u64(&mut s.out, p, term);
            p = append(&mut s.out, p, b" index=");
            p = append_u64(&mut s.out, p, index);
        } else {
            p = append(&mut s.out, p, b": (short payload, no term/index)");
        }
        p = append(&mut s.out, p, b" len=");
        p = append_u64(&mut s.out, p, entry_len as u64);
        p = append(&mut s.out, p, b"\n");
        pos += entry_len;
        entries += 1;
    }
    let mut q = append(&mut s.out, p, b"ok: ");
    q = append_u64(&mut s.out, q, entries);
    q = append(&mut s.out, q, b" entry(s), ");
    q = append_u64(&mut s.out, q, pos as u64);
    q = append(&mut s.out, q, b" byte(s) durable");
    if slen - pos > 0 {
        q = append(&mut s.out, q, b" (");
        q = append_u64(&mut s.out, q, (slen - pos) as u64);
        q = append(&mut s.out, q, b" trailing byte(s) below a frame header)");
    }
    q = append(&mut s.out, q, b"\n");
    (q, 0)
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.args_chan = in_chan; // input port 0 ← cli_in.args_out
        s.out_chan = out_chan; // output port 0 → cli_out.bytes_in
        s.exit_chan = -1; // output port 1 → cli_out.exit_in (resolved lazily)
        s.waited = 0;
        s.done = 0;
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return STEP_DONE;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return STEP_DONE;
        }
        let sys = &*s.syscalls;
        if s.done != 0 {
            return STEP_DONE;
        }
        if s.exit_chan < 0 {
            s.exit_chan = dev_channel_port(sys, PORT_OUTPUT, 1);
        }

        // Read the argv record (one NUL-separated record from cli_in). Retry a
        // bounded number of steps; an empty argv (no `--`) never arrives, so we
        // fall through to `help`.
        let an = if s.args_chan >= 0 {
            (sys.channel_read)(s.args_chan, s.arec.as_mut_ptr(), s.arec.len())
        } else {
            0
        };
        if an <= 0 {
            s.waited += 1;
            if s.waited < ARGV_WAIT {
                return 0; // keep waiting for argv
            }
        }
        let alen = if an > 0 { an as usize } else { 0 };

        let mut argv = [(0usize, 0usize); 8];
        let mut arec = [0u8; ARGV_BUF];
        arec[..alen].copy_from_slice(&s.arec[..alen]);
        let argc = split_argv(&arec[..alen], &mut argv);

        let (olen, code): (usize, i32) = if argc == 0 {
            (cmd_help(&mut s.out), 0)
        } else {
            let (s0, e0) = argv[0];
            let sub = &arec[s0..e0];
            if sub == b"crc" {
                if argc >= 2 {
                    let (a, b) = argv[1];
                    cmd_crc(s, &arec[a..b])
                } else {
                    (append(&mut s.out, 0, b"error: crc needs <hex>\n"), 1)
                }
            } else if sub == b"wal-frame" {
                if argc >= 2 {
                    let (a, b) = argv[1];
                    cmd_wal_frame(s, &arec[a..b])
                } else {
                    (
                        append(&mut s.out, 0, b"error: wal-frame needs <payload_hex>\n"),
                        1,
                    )
                }
            } else if sub == b"wal-scan" {
                if argc >= 2 {
                    let (a, b) = argv[1];
                    cmd_wal_scan(s, &arec[a..b])
                } else {
                    (
                        append(&mut s.out, 0, b"error: wal-scan needs <segment_hex>\n"),
                        1,
                    )
                }
            } else if sub == b"help" {
                (cmd_help(&mut s.out), 0)
            } else {
                let mut p = append(&mut s.out, 0, b"error: unknown command '");
                p = append(&mut s.out, p, sub);
                p = append(&mut s.out, p, b"' (try `help`)\n");
                (p, 1)
            }
        };

        if s.out_chan >= 0 && olen > 0 {
            let _ = (sys.channel_write)(s.out_chan, s.out.as_ptr(), olen);
        }
        if s.exit_chan >= 0 {
            let c = code.to_le_bytes();
            let _ = (sys.channel_write)(s.exit_chan, c.as_ptr(), c.len());
        }
        s.done = 1;
        STEP_DONE
    }
}

include!("../../../target/fluxor/fluxor-abi/sdk/runtime/wasm_entry.rs");
