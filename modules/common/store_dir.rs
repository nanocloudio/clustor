//! A module's on-disk directory, named by a param.
//!
//! `durability` keeps its WAL segments, floor sidecar, seal state and
//! snapshots under one directory (`wal_dir`, default `wal`), and
//! `consensus` keeps its Raft metadata slots under another (`meta_dir`,
//! default `raft`). Each is a path the FS provider resolves: relative to
//! the process working directory (a workload's owner root), or absolute —
//! which is how a workload puts its state on a volume lent at an absolute
//! path. The module creates the LAST component at first open (`FS_MKDIR`,
//! once, then fences its name); every parent must already exist.
//!
//! The value is validated once, at construction, and a bad one refuses the
//! module rather than writing somewhere unintended:
//!
//!   - 1..=`STORE_DIR_MAX` bytes once trailing `/` are dropped (so `/`
//!     alone, which would name the FS root, is refused — the root layout
//!     is `root_path = 1`'s);
//!   - no NUL byte;
//!   - no `..` component, so a relative value cannot climb out of the
//!     working directory and an absolute one names exactly what it says.
//!
//! An explicit value alongside `root_path = 1` is refused too: the 8.3
//! root layout has no directory to place.

/// Longest directory a `wal_dir` / `meta_dir` param names. Every path a
/// module builds is this plus its own short file name, and the platform
/// fs contract takes paths up to 255 bytes, so 128 leaves each name its
/// room with margin.
pub const STORE_DIR_MAX: usize = 128;

/// A validated directory, held inline (module state has no heap).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StoreDir {
    bytes: [u8; STORE_DIR_MAX],
    len: u8,
    /// The param named a value (not the default).
    explicit: bool,
    /// The param named a value `set` refused; construction fails on it.
    refused: bool,
}

impl StoreDir {
    /// The default directory `name` (a module constant, assumed valid).
    pub const fn named(name: &[u8]) -> Self {
        let mut bytes = [0u8; STORE_DIR_MAX];
        let mut i = 0;
        while i < name.len() && i < STORE_DIR_MAX {
            bytes[i] = name[i];
            i += 1;
        }
        Self {
            bytes,
            len: i as u8,
            explicit: false,
            refused: false,
        }
    }

    /// Apply a param value. Empty restores `default` (what the param
    /// defaults pass); anything else is validated and, if refused,
    /// remembered so construction fails (`refused`).
    pub fn set(&mut self, raw: &[u8], default: &[u8]) {
        if raw.is_empty() {
            *self = Self::named(default);
            return;
        }
        let mut end = raw.len();
        while end > 0 && raw[end - 1] == b'/' {
            end -= 1;
        }
        let v = &raw[..end];
        if !valid(v) {
            *self = Self::named(default);
            self.refused = true;
            return;
        }
        *self = Self::named(v);
        self.explicit = true;
    }

    /// The directory, without a trailing `/`.
    pub fn get(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The param named a value of its own rather than the default.
    pub fn explicit(&self) -> bool {
        self.explicit
    }

    /// The param named a value construction must refuse.
    pub fn refused(&self) -> bool {
        self.refused
    }

    /// Write `<dir>/` at the start of `out` and return its length, or
    /// `None` when `out` cannot hold it.
    pub fn put_prefix(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.len as usize;
        if out.len() < n + 1 {
            return None;
        }
        out[..n].copy_from_slice(self.get());
        out[n] = b'/';
        Some(n + 1)
    }

    /// Write `<dir>` (no trailing `/`) at the start of `out` — what
    /// `FS_MKDIR` and the directory's name fence take — and return its
    /// length, or `None` when `out` cannot hold it.
    pub fn put(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.len as usize;
        if out.len() < n {
            return None;
        }
        out[..n].copy_from_slice(self.get());
        Some(n)
    }
}

/// Whether `v` (trailing `/` already dropped) is a directory a module may
/// keep its state in: 1..=`STORE_DIR_MAX` bytes, no NUL, no `..`
/// component.
pub fn valid(v: &[u8]) -> bool {
    if v.is_empty() || v.len() > STORE_DIR_MAX {
        return false;
    }
    // Byte loops, not `contains`/`split`: those reach `memchr`, which a
    // PIC module build does not link.
    let mut start = 0;
    let mut i = 0;
    while i <= v.len() {
        if i < v.len() && v[i] == 0 {
            return false;
        }
        if i == v.len() || v[i] == b'/' {
            if i - start == 2 && v[start] == b'.' && v[start + 1] == b'.' {
                return false;
            }
            start = i + 1;
        }
        i += 1;
    }
    true
}
