#[derive(Debug, Clone)]
pub struct ReplayGuard {
    target_index: u64,
    applied_index: u64,
}

impl ReplayGuard {
    pub fn new(target_index: u64) -> Self {
        Self {
            target_index,
            applied_index: 0,
        }
    }

    pub fn record_apply(&mut self, index: u64) {
        if index > self.applied_index {
            self.applied_index = index;
        }
    }

    pub fn is_replay_complete(&self) -> bool {
        self.applied_index >= self.target_index
    }
}
