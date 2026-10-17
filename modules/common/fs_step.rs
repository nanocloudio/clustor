//! The caller's half of the non-blocking `fs` contract
//! (`target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs`).
//!
//! No fs call waits on the device. A call answers a result, `EAGAIN`
//! ("nothing moved, ask again later, with any arguments") or, for the
//! multi-step operations (FSYNC, FSYNC_NAME, RENAME, MKDIR, RMDIR, UNLINK,
//! LINK, TRUNCATE, PREALLOCATE, OPEN_CREATE), `EINPROGRESS` ("taken, not
//! decided: re-ask the byte-identical request on a later step"). READ,
//! WRITE and WRITE_ASYNC may move fewer bytes than asked. The device only
//! progresses between steps, so a sequence of calls is a step machine that
//! keeps its in-flight request and resumes it where it stopped — it never
//! loops "until done" inside one step and never restarts from the top.
//!
//! The helpers here are the pieces every such machine shares. They are
//! panic-free (PIC modules carry no panic path) and loop only while the
//! provider is still moving bytes, so a step's work stays bounded by the
//! request it was given.

#![allow(
    dead_code,
    reason = "shared via #[path] into several modules; each consumer uses a subset of the surface"
)]

/// `EAGAIN`: nothing moved — no cursor, no offset, no directory change.
pub const E_AGAIN: i32 = -11;
/// `EINPROGRESS`: taken, not yet decided. Re-ask with the same
/// (opcode, handle, arg bytes); a later answer is the decision.
pub const E_INPROGRESS: i32 = -36;
/// `ENOENT`, the answer a re-asked `UNLINK` gives once the removal it
/// started has already happened and its decision was dropped.
pub const E_NOENT: i32 = -2;

pub const OP_READ: u32 = 0x0901;
pub const OP_FSYNC: u32 = 0x0905;

/// `provider_call`'s shape.
pub type Call = unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32;

/// True when `rc` is not an answer yet: the caller keeps its request and
/// asks again on a later step. Never a failure, an end of data, or an
/// absence.
#[inline]
pub const fn later(rc: i32) -> bool {
    rc == E_AGAIN || rc == E_INPROGRESS
}

/// The state of a transfer that moves `len` bytes in as many asks, and
/// steps, as the provider needs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Io {
    /// Every byte moved.
    Done,
    /// The provider moved what it could; the rest moves on a later step.
    Later,
    /// READ answered 0 before `len` bytes: the file ends here.
    End,
    /// A real failure of the call.
    Fail(i32),
}

/// Read into `buf[*done..len]` from `fd`'s current offset, advancing
/// `*done` by what moved. Asks again only while bytes keep moving, so the
/// loop is bounded by `len`.
///
/// # Safety
/// `buf` must be writable for `len` bytes; `call` must be the module's
/// `provider_call`.
#[inline(never)]
pub unsafe fn read_into(call: Call, fd: i32, buf: *mut u8, len: usize, done: &mut usize) -> Io {
    while *done < len {
        let want = len - *done;
        let rc = call(fd, OP_READ, buf.add(*done), want);
        if later(rc) {
            return Io::Later;
        }
        if rc < 0 {
            return Io::Fail(rc);
        }
        if rc == 0 {
            return Io::End;
        }
        let n = rc as usize;
        *done += if n > want { want } else { n };
    }
    Io::Done
}

/// Write `buf[*done..len]` through `fd` with `op` (WRITE or WRITE_ASYNC),
/// advancing `*done` by what the provider accepted. A written prefix
/// belongs to the provider from then on; the caller resumes after it.
/// A zero count is backpressure, like `EAGAIN`.
///
/// # Safety
/// `buf` must be readable for `len` bytes; `call` must be the module's
/// `provider_call`.
#[inline(never)]
pub unsafe fn write_from(
    call: Call,
    op: u32,
    fd: i32,
    buf: *const u8,
    len: usize,
    done: &mut usize,
) -> Io {
    while *done < len {
        let want = len - *done;
        let rc = call(fd, op, buf.add(*done) as *mut u8, want);
        if later(rc) || rc == 0 {
            return Io::Later;
        }
        if rc < 0 {
            return Io::Fail(rc);
        }
        let n = rc as usize;
        *done += if n > want { want } else { n };
    }
    Io::Done
}

/// One ask of a single-call operation. `Some(rc)` is the decision (a
/// result or a real errno); `None` means ask again later — the request
/// stays exactly as it was asked.
///
/// # Safety
/// `arg` must be valid for `len` bytes as the opcode requires.
#[inline]
pub unsafe fn ask(call: Call, handle: i32, op: u32, arg: *mut u8, len: usize) -> Option<i32> {
    let rc = call(handle, op, arg, len);
    if later(rc) {
        None
    } else {
        Some(rc)
    }
}
