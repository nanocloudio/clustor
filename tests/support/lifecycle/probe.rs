use clustor::lifecycle::bootstrap::{
    FsyncProbeTelemetry, ProbeIoError, ProbeTarget, ProbeTelemetrySink, TelemetryError,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::Duration;

pub struct MockProbeTarget {
    samples: Vec<Duration>,
    cursor: usize,
    finalized: bool,
}

impl MockProbeTarget {
    pub fn new(samples: Vec<Duration>) -> Self {
        Self {
            samples,
            cursor: 0,
            finalized: false,
        }
    }

    pub fn finalized(&self) -> bool {
        self.finalized
    }
}

impl ProbeTarget for MockProbeTarget {
    fn run_sample(
        &mut self,
        _sample_idx: usize,
        _total_samples: usize,
    ) -> Result<Duration, ProbeIoError> {
        let duration = self
            .samples
            .get(self.cursor)
            .copied()
            .unwrap_or(Duration::from_millis(1));
        self.cursor += 1;
        Ok(duration)
    }

    fn finalize(&mut self) -> Result<(), ProbeIoError> {
        self.finalized = true;
        Ok(())
    }
}

pub struct RecordingSink {
    payloads: Mutex<Vec<FsyncProbeTelemetry>>,
    publish_calls: AtomicUsize,
}

impl RecordingSink {
    pub fn new() -> Self {
        Self {
            payloads: Mutex::new(Vec::new()),
            publish_calls: AtomicUsize::new(0),
        }
    }

    pub fn publish_calls(&self) -> usize {
        self.publish_calls.load(Ordering::Relaxed)
    }
}

impl ProbeTelemetrySink for RecordingSink {
    fn publish(&self, payload: &FsyncProbeTelemetry) -> Result<(), TelemetryError> {
        self.publish_calls.fetch_add(1, Ordering::Relaxed);
        self.payloads.lock().unwrap().push(payload.clone());
        Ok(())
    }
}
