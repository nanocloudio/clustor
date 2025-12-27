use clustor::persistence::storage::{
    NonceLedgerConfig, NonceReservationLedger, StartupScrubEngine, MAX_RESERVATION_BLOCKS,
    WAL_CRYPTO_BLOCK_BYTES,
};
use std::time::{Duration, UNIX_EPOCH};

fn new_ledger() -> NonceReservationLedger {
    NonceReservationLedger::with_config(
        1,
        NonceLedgerConfig {
            warn_gap_bytes: 4 * WAL_CRYPTO_BLOCK_BYTES as u64,
            abandon_gap_bytes: 8 * WAL_CRYPTO_BLOCK_BYTES as u64,
        },
    )
}

#[test]
fn startup_scrub_engine_abandons_when_gap_exceeds_threshold() {
    let mut ledger = new_ledger();
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    assert!(ledger.needs_scrub());
    let now = UNIX_EPOCH + Duration::from_millis(10);
    let report = StartupScrubEngine::run(&mut ledger, now);
    assert!(report.scrubbed);
    assert_eq!(report.gap_bytes_after, 0);
    assert!(report.abandon_record.is_some());
    assert!(!ledger.needs_scrub());
}

#[test]
fn startup_scrub_engine_reports_gap_without_scrub() {
    let mut ledger = new_ledger();
    ledger.reserve(1, 0).unwrap();
    let now = UNIX_EPOCH;
    let report = StartupScrubEngine::run(&mut ledger, now);
    assert!(!report.scrubbed);
    assert_eq!(report.gap_bytes_before, report.gap_bytes_after);
    assert!(report.abandon_record.is_none());
    assert_eq!(report.telemetry.gap_bytes, ledger.gap_bytes());
}
