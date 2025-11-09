use clustor::{
    FixtureBundleGenerator, FixtureEntry, MetricsRegistry, SpecLint, SpecSelfTestHarness,
};
use std::time::SystemTime;
use tempfile::tempdir;

#[test]
fn spec_self_test_checkpoint_runs_and_persists() {
    let tmp = tempdir().unwrap();
    let output = tmp.path().join("spec_self_test.json");
    let mut registry = MetricsRegistry::new("clustor");
    let harness = SpecSelfTestHarness::new().with_test(
        "routing-epoch-monotone",
        "Spec §2.3",
        Box::new(|| true),
    );
    let result = harness
        .run(&output, &mut registry, SystemTime::now())
        .expect("self test succeeds");
    assert_eq!(result.total, 1);
    assert!(output.exists());
}

#[test]
fn spec_fixture_checkpoint_validates_bundle() {
    let tmp = tempdir().unwrap();
    let bundle_path = tmp.path().join("fixtures.json");
    let entries = vec![FixtureEntry {
        name: "appendix-d".into(),
        description: "Durability entry".into(),
        payload: serde_json::json!({"mode": "Strict"}),
    }];
    let bundle = FixtureBundleGenerator::generate(entries, &bundle_path).expect("bundle generated");
    SpecLint::validate_bundle(&bundle, "docs/specification.md").unwrap();
}
