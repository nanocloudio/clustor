//! Storage subsystem scaffolding: WAL entry encoding, segment management, and guard rails.

pub mod compaction;
pub mod crypto;
pub mod definitions;
pub mod entry;
pub mod guard;
pub mod layout;
pub mod replay;
pub mod segment;

pub use compaction::{
    CompactionBlockReason, CompactionDecision, CompactionGate, CompactionPlanRequest,
    CompactionState, ManifestAuthorizationLog, ManifestGate, ManifestLogError, SegmentHealth,
    SegmentSkipReason, SnapshotAuthorizationRecord,
};
pub use crypto::{
    CryptoError, DataEncryptionKey, KeyEpoch, KeyEpochError, KeyEpochTracker, NonceLedgerConfig,
    NonceLedgerError, NonceReservationLedger, NonceReservationRange, NonceReservationTelemetry,
    SegmentHeader, SegmentHeaderError, WalAead, MAX_RESERVATION_BLOCKS, WAL_CRYPTO_BLOCK_BYTES,
};
pub use definitions::{DefinitionBundle, DefinitionBundleError, DefinitionBundleStore};
pub use entry::{EntryFrame, EntryFrameBuilder, EntryFrameError, FrameHeader, MerkleDigest};
pub use guard::{FsyncMode, GroupFsyncPolicy, GroupFsyncPolicyTelemetry};
pub use layout::{
    CompactionAuthAck, CompactionMetadata, NonceReservationAbandon, StorageLayout,
    StorageLayoutError, StorageMetadata, StorageMetadataError, StorageMetadataStore, StoragePaths,
    StorageState,
};
pub use replay::{WalReplayError, WalReplayResult, WalReplayScanner, WalTruncation};
pub use segment::{SegmentHandle, SegmentManager, SegmentPosition};
