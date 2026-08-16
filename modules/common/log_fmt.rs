//! Bounded `dev_log` line formatters: `tag` + decimal-value appenders
//! for composing parseable log lines in a module-owned line buffer.
//!
//! Every write is bounds-checked against the destination slice: a
//! field whose rendered bytes would not fit is dropped whole, so an
//! undersized line buffer truncates the line instead of writing past
//! its end into adjacent `ModuleState` fields.
//!
//! `#[path]`-mounted alongside `wire.rs`; the parent must `include!`
//! the SDK runtime, which supplies `fmt_u32_raw`.

#![allow(
    dead_code,
    reason = "shared #[path]-mounted helper surface; each consumer uses a subset"
)]

/// Append `tag` + decimal `val` into `buf` at `pos`; returns the new
/// position. A field that would overrun `buf` (worst case
/// `tag.len() + 10` bytes) is dropped and `pos` returned unchanged.
pub fn log_field(buf: &mut [u8], pos: usize, tag: &[u8], val: u32) -> usize {
    let mut digits = [0u8; 10];
    // SAFETY: `digits` is 10 bytes — the maximum decimal width of u32.
    let n = unsafe { super::fmt_u32_raw(digits.as_mut_ptr(), val) };
    append(buf, pos, tag, &digits[..n])
}

/// Like `log_field` but for a possibly-negative `i32` (e.g. an
/// errno-style FS return code): writes `tag`, a leading `-` when
/// negative, then the magnitude (worst case `tag.len() + 11` bytes).
/// `FS_OPEN_CREATE` returns a tagged fd (positive) or `-errno`.
pub fn log_field_i32(buf: &mut [u8], pos: usize, tag: &[u8], val: i32) -> usize {
    let mut digits = [0u8; 11];
    let mut n = 0usize;
    let mag = if val < 0 {
        digits[0] = b'-';
        n = 1;
        (val as i64).unsigned_abs() as u32
    } else {
        val as u32
    };
    // SAFETY: 11 bytes hold a sign plus the 10-digit u32 maximum.
    n += unsafe { super::fmt_u32_raw(digits.as_mut_ptr().add(n), mag) };
    append(buf, pos, tag, &digits[..n])
}

/// Bounds-checked append of `tag` + `rendered` at `pos`; drops the
/// whole field (returning `pos`) when it would not fit.
fn append(buf: &mut [u8], pos: usize, tag: &[u8], rendered: &[u8]) -> usize {
    let need = tag.len() + rendered.len();
    if pos > buf.len() || buf.len() - pos < need {
        return pos;
    }
    buf[pos..pos + tag.len()].copy_from_slice(tag);
    buf[pos + tag.len()..pos + need].copy_from_slice(rendered);
    pos + need
}
