use clustor::replication::membership::{
    evaluate_survivability, SurvivabilityInputs, SurvivabilityResult,
};

#[test]
fn fails_when_quorum_not_met() {
    let report = evaluate_survivability(SurvivabilityInputs {
        voters: 5,
        healthy: 3,
        planned_outages: 2,
        fault_domains: 3,
        tolerated_faults: 1,
    });
    assert_eq!(report.quorum_result, SurvivabilityResult::Fail);
}

#[test]
fn passes_when_all_metrics_satisfied() {
    let report = evaluate_survivability(SurvivabilityInputs {
        voters: 5,
        healthy: 5,
        planned_outages: 1,
        fault_domains: 3,
        tolerated_faults: 2,
    });
    assert_eq!(report.quorum_result, SurvivabilityResult::Pass);
    assert_eq!(report.fault_result, SurvivabilityResult::Pass);
}
