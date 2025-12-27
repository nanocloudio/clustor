use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceState {
    pub fence_epoch: u64,
    pub manifest_id: String,
    pub participants: HashSet<String>,
    pub acked: HashSet<String>,
    pub aborted: bool,
}

#[derive(Debug)]
pub struct DrFenceManager {
    state: Option<FenceState>,
}

impl Default for DrFenceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DrFenceManager {
    pub fn new() -> Self {
        Self { state: None }
    }

    pub fn begin(
        &mut self,
        fence_epoch: u64,
        manifest_id: impl Into<String>,
        participants: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<(), DrFenceError> {
        if let Some(state) = &self.state {
            if state.fence_epoch >= fence_epoch && !state.aborted {
                return Err(DrFenceError::FenceInProgress {
                    current_epoch: state.fence_epoch,
                });
            }
        }
        let set = participants
            .into_iter()
            .map(Into::into)
            .collect::<HashSet<_>>();
        if set.is_empty() {
            return Err(DrFenceError::NoParticipants);
        }
        self.state = Some(FenceState {
            fence_epoch,
            manifest_id: manifest_id.into(),
            participants: set,
            acked: HashSet::new(),
            aborted: false,
        });
        Ok(())
    }

    pub fn ack(
        &mut self,
        fence_epoch: u64,
        participant: impl Into<String>,
    ) -> Result<(), DrFenceError> {
        let participant = participant.into();
        let state = self
            .state
            .as_mut()
            .ok_or(DrFenceError::NoFence)?
            .ensure_epoch(fence_epoch)?;
        if !state.participants.contains(&participant) {
            return Err(DrFenceError::UnknownParticipant { participant });
        }
        state.acked.insert(participant);
        Ok(())
    }

    pub fn abort(&mut self, fence_epoch: u64) -> Result<(), DrFenceError> {
        let state = self.state.as_mut().ok_or(DrFenceError::NoFence)?;
        state.ensure_epoch(fence_epoch)?;
        state.aborted = true;
        Ok(())
    }

    pub fn is_committed(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| !state.aborted && state.acked.len() == state.participants.len())
    }

    pub fn state(&self) -> Option<&FenceState> {
        self.state.as_ref()
    }
}

impl FenceState {
    fn ensure_epoch(&mut self, epoch: u64) -> Result<&mut Self, DrFenceError> {
        if self.fence_epoch != epoch {
            return Err(DrFenceError::EpochMismatch {
                expected: self.fence_epoch,
                observed: epoch,
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DrFenceError {
    #[error("fence already in progress at epoch {current_epoch}")]
    FenceInProgress { current_epoch: u64 },
    #[error("no active fence")]
    NoFence,
    #[error("unknown fence epoch: expected {expected}, observed {observed}")]
    EpochMismatch { expected: u64, observed: u64 },
    #[error("no participants supplied")]
    NoParticipants,
    #[error("participant {participant} not part of fence set")]
    UnknownParticipant { participant: String },
}
