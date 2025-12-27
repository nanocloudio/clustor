use clustor::persistence::storage::crypto::{
    DataEncryptionKey, KeyEpoch, KeyEpochError, KeyEpochTracker, NonceLedgerConfig,
    NonceReservationLedger, SegmentHeader, WalAead, WAL_CRYPTO_BLOCK_BYTES,
};

#[test]
fn key_epoch_tracker_rejects_replay() {
    let mut tracker = KeyEpochTracker::default();
    tracker
        .observe(KeyEpoch {
            kek_version: 1,
            dek_epoch: 2,
            integrity_mac_epoch: 3,
        })
        .unwrap();
    let err = tracker
        .observe(KeyEpoch {
            kek_version: 1,
            dek_epoch: 1,
            integrity_mac_epoch: 3,
        })
        .unwrap_err();
    assert!(matches!(err, KeyEpochError::Replay { .. }));
}

#[test]
fn aead_round_trip() {
    let key = DataEncryptionKey::new(7, [42u8; 32]);
    let pipeline = WalAead::new(&key, "partition-1");
    let plaintext = vec![5u8; WAL_CRYPTO_BLOCK_BYTES as usize];
    let ciphertext = pipeline
        .encrypt_block(key.epoch, 18, 0, &plaintext)
        .unwrap();
    assert_ne!(ciphertext[..plaintext.len()], plaintext[..]);
    let recovered = pipeline
        .decrypt_block(key.epoch, 18, 0, &ciphertext)
        .unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn segment_header_encode_decode() {
    let header = SegmentHeader::new(1, 99, 4);
    let bytes = header.encode();
    let decoded = SegmentHeader::decode(&bytes).unwrap();
    assert_eq!(decoded.segment_seq, 99);
    assert!(decoded.validate(WAL_CRYPTO_BLOCK_BYTES).is_ok());
}

#[test]
fn segment_header_seal_round_trip() {
    let key = DataEncryptionKey::new(3, [1u8; 32]);
    let aead = WalAead::new(&key, "partition-z");
    let header = SegmentHeader::new(1, 42, key.epoch);
    let sealed = header.seal_block(&aead, key.epoch).unwrap();
    let opened = SegmentHeader::open_block(&aead, key.epoch, header.segment_seq, &sealed).unwrap();
    assert_eq!(opened.segment_seq, header.segment_seq);
    assert_eq!(opened.dek_epoch, key.epoch);
}

#[test]
fn nonce_ledger_enforces_reservations() {
    let mut ledger = NonceReservationLedger::new(5);
    let range = ledger.reserve(4, 0).unwrap();
    assert_eq!(range.start_block, 0);
    ledger.record_completion(0).unwrap();
    ledger.record_completion(2).unwrap();
    ledger.record_completion(1).unwrap();
    ledger.record_completion(3).unwrap();
    assert!(!ledger.has_outstanding_reservations());
    let abandon = ledger.abandon("rewrite", 10);
    assert_eq!(abandon.segment_seq, 5);
}

#[test]
fn nonce_ledger_reports_gap_telemetry() {
    let config = NonceLedgerConfig {
        warn_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64 * 2,
        abandon_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64 * 5,
    };
    let mut ledger = NonceReservationLedger::with_config(7, config);
    ledger.reserve(4, 0).unwrap();
    assert!(ledger.warn_gap());
    assert!(!ledger.needs_scrub());
    let telemetry = ledger.telemetry();
    assert_eq!(telemetry.reserved_blocks, 4);
    assert!(telemetry.gap_bytes >= WAL_CRYPTO_BLOCK_BYTES as u64 * 4);
}
