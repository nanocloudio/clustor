use crate::storage::entry::EntryFrame;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct SegmentManager {
    capacity: usize,
    buffer: Vec<u8>,
    cursor: usize,
    flush_order: VecDeque<Vec<u8>>,
}

impl SegmentManager {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: Vec::with_capacity(capacity),
            cursor: 0,
            flush_order: VecDeque::new(),
        }
    }

    pub fn append(&mut self, frame: &EntryFrame) -> SegmentPosition {
        let bytes = frame.encode();
        if self.cursor + bytes.len() > self.capacity {
            self.flush();
        }
        let offset = self.cursor;
        self.buffer.extend_from_slice(&bytes);
        self.cursor += bytes.len();
        SegmentPosition {
            offset,
            len: bytes.len(),
        }
    }

    pub fn flush(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.flush_order.push_back(self.buffer.clone());
        self.buffer.clear();
        self.cursor = 0;
    }

    pub fn drain_flushes(&mut self) -> Vec<Vec<u8>> {
        self.flush_order.drain(..).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentPosition {
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct SegmentHandle {
    pub position: SegmentPosition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::entry::EntryFrameBuilder;

    #[test]
    fn flushes_in_order() {
        let mut manager = SegmentManager::with_capacity(32);
        manager.append(&EntryFrameBuilder::new(1, 1).payload(vec![0; 16]).build());
        manager.append(&EntryFrameBuilder::new(1, 2).payload(vec![0; 20]).build());
        manager.flush();
        let flushes = manager.drain_flushes();
        assert_eq!(flushes.len(), 2);
    }
}
