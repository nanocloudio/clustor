use clustor::spec::matrix::MatrixRunner;

#[test]
fn matrix_runner_records_outcomes() {
    let runner = MatrixRunner::new()
        .add_scenario(
            "appendix-c-fixture",
            "Appendix C",
            vec!["manifest".into()],
            true,
        )
        .add_scenario(
            "appendix-d-durability",
            "Appendix D",
            vec!["durability".into()],
            false,
        );
    let report = runner.run();
    assert_eq!(report.outcomes.len(), 2);
}
