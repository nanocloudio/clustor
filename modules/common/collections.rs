//! Fixed-size collections for no_std modules.

#![allow(dead_code)]

/// Fixed-capacity ring buffer. `N` must be a power of 2 for efficient wrapping.
///
/// Stores items inline — no heap allocation. Suitable for entry queues,
/// pending-fsync batches, and idempotency ledgers.
#[repr(C)]
pub struct RingBuf<T: Copy + Default, const N: usize> {
    buf: [T; N],
    head: u16,  // index of oldest item
    len: u16,   // number of items in buffer
}

impl<T: Copy + Default, const N: usize> RingBuf<T, N> {
    /// Create an empty ring buffer (all slots zeroed).
    pub const fn new() -> Self {
        Self {
            buf: [unsafe { core::mem::zeroed() }; N],
            head: 0,
            len: 0,
        }
    }

    /// Number of items in the buffer.
    #[inline]
    pub fn len(&self) -> u16 { self.len }

    /// Whether the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Whether the buffer is full.
    #[inline]
    pub fn is_full(&self) -> bool { self.len as usize >= N }

    /// Capacity.
    #[inline]
    pub fn capacity(&self) -> usize { N }

    /// Push an item to the back. Returns false if full.
    #[inline]
    pub fn push(&mut self, item: T) -> bool {
        if self.is_full() { return false; }
        let idx = (self.head as usize + self.len as usize) % N;
        self.buf[idx] = item;
        self.len += 1;
        true
    }

    /// Pop an item from the front. Returns None if empty.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() { return None; }
        let item = self.buf[self.head as usize];
        self.head = ((self.head as usize + 1) % N) as u16;
        self.len -= 1;
        Some(item)
    }

    /// Peek at the front item without removing.
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() { return None; }
        Some(&self.buf[self.head as usize])
    }

    /// Clear all items.
    #[inline]
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Access item at logical index (0 = front). Returns None if out of range.
    #[inline]
    pub fn get(&self, logical_idx: u16) -> Option<&T> {
        if logical_idx >= self.len { return None; }
        let actual = (self.head as usize + logical_idx as usize) % N;
        Some(&self.buf[actual])
    }
}

/// Simple CRC32C implementation (Castagnoli polynomial).
/// Used by the WAL for frame integrity. Not hardware-accelerated;
/// sufficient for module-level validation.
pub struct Crc32c {
    state: u32,
}

impl Crc32c {
    pub const fn new() -> Self { Self { state: 0xFFFF_FFFF } }

    pub fn reset(&mut self) { self.state = 0xFFFF_FFFF; }

    /// Update CRC with `data`. Uses the nibble-table approach (32-entry table)
    /// for compact code size.
    pub fn update(&mut self, data: &[u8]) {
        // Castagnoli CRC32C nibble table.
        const TABLE: [u32; 16] = [
            0x0000_0000, 0x105E_C76F, 0x20BD_8EDE, 0x30E3_49B1,
            0x417B_1DBC, 0x5125_DAD3, 0x61C6_9362, 0x7198_540D,
            0x82F6_3B78, 0x92A8_FC17, 0xA24B_B5A6, 0xB215_72C9,
            0xC38D_26C4, 0xD3D3_E1AB, 0xE330_A81A, 0xF36E_6F75,
        ];
        let mut crc = self.state;
        for &b in data {
            crc = (crc >> 4) ^ TABLE[((crc ^ b as u32) & 0x0F) as usize];
            crc = (crc >> 4) ^ TABLE[((crc ^ (b as u32 >> 4)) & 0x0F) as usize];
        }
        self.state = crc;
    }

    pub fn finalize(&self) -> u32 { self.state ^ 0xFFFF_FFFF }
}
