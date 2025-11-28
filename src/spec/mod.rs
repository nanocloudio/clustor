//! Specification helpers: fixtures, coverage matrix, self-test harness, and runtime terminology.

pub mod fixtures;
pub mod matrix;
pub mod self_test;
pub mod terminology;

pub use fixtures::{
    ChunkedListSchemaArtifact, ClauseCoverageReport, FixtureBundle, FixtureBundleGenerator,
    FixtureEntry, FixtureError, SpecLint, TermDefinition, TermRegistry, WireCatalogArtifact,
};
pub use matrix::{MatrixOutcome, MatrixReport, MatrixRunner, MatrixScenario};
pub use self_test::{SpecSelfTestError, SpecSelfTestHarness, SpecSelfTestResult, SpecTestOutcome};
pub use terminology::{
    runtime_terms, RuntimeTerm, TERM_DURABILITY_RECORD, TERM_FOLLOWER_READ_SNAPSHOT,
    TERM_GROUP_FSYNC, TERM_LEASE_ENABLE, TERM_SNAPSHOT_DELTA, TERM_STRICT,
};
