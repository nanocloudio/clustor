#[derive(Debug, Clone, Copy)]
pub struct SurvivabilityInputs {
    pub voters: usize,
    pub healthy: usize,
    pub planned_outages: usize,
    pub fault_domains: usize,
    pub tolerated_faults: usize,
}

impl Default for SurvivabilityInputs {
    fn default() -> Self {
        Self {
            voters: 3,
            healthy: 3,
            planned_outages: 0,
            fault_domains: 3,
            tolerated_faults: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurvivabilityResult {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
pub struct SurvivabilityReport {
    pub quorum_result: SurvivabilityResult,
    pub healthy_result: SurvivabilityResult,
    pub fault_result: SurvivabilityResult,
    pub explanation: String,
}

pub fn evaluate_survivability(inputs: SurvivabilityInputs) -> SurvivabilityReport {
    let quorum = inputs.voters / 2 + 1;
    let available = inputs.healthy.saturating_sub(inputs.planned_outages);
    let quorum_result = if available >= quorum {
        SurvivabilityResult::Pass
    } else {
        SurvivabilityResult::Fail
    };

    let healthy_result = if inputs.healthy >= quorum {
        SurvivabilityResult::Pass
    } else {
        SurvivabilityResult::Fail
    };

    let fault_result = if inputs.tolerated_faults >= inputs.planned_outages {
        SurvivabilityResult::Pass
    } else {
        SurvivabilityResult::Fail
    };

    let explanation = format!(
        "Q: {}/{} healthy available, H: {} healthy voters, F: tolerate {}/{} faults",
        available, quorum, inputs.healthy, inputs.tolerated_faults, inputs.planned_outages
    );

    SurvivabilityReport {
        quorum_result,
        healthy_result,
        fault_result,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
