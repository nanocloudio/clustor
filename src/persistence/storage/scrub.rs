use crate::storage::crypto::NonceReservationLedger;
use crate::storage::layout::NonceReservationAbandon;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct StartupScrubReport {
    pub scrubbed: bool,
    pub gap_bytes_before: u64,
    pub gap_bytes_after: u64,
    pub telemetry: ScrubTelemetry,
    pub abandon_record: Option<NonceReservationAbandon>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScrubTelemetry {
    pub gap_bytes: u64,
    pub warn_gap: bool,
    pub needs_scrub: bool,
}

impl ScrubTelemetry {
    fn from_ledger(ledger: &NonceReservationLedger) -> Self {
        Self {
            gap_bytes: ledger.gap_bytes(),
            warn_gap: ledger.warn_gap(),
            needs_scrub: ledger.needs_scrub(),
        }
    }
}

pub struct StartupScrubEngine;

impl StartupScrubEngine {
    pub fn run(ledger: &mut NonceReservationLedger, now: SystemTime) -> StartupScrubReport {
        let before = ledger.gap_bytes();
        if ledger.needs_scrub() {
            let abandon = ledger.abandon("startup scrub", system_time_to_ms(now));
            let telemetry = ScrubTelemetry::from_ledger(ledger);
            StartupScrubReport {
                scrubbed: true,
                gap_bytes_before: before,
                gap_bytes_after: telemetry.gap_bytes,
                telemetry,
                abandon_record: Some(abandon),
            }
        } else {
            StartupScrubReport {
                scrubbed: false,
                gap_bytes_before: before,
                gap_bytes_after: before,
                telemetry: ScrubTelemetry::from_ledger(ledger),
                abandon_record: None,
            }
        }
    }
}

fn system_time_to_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
