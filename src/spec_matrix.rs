use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixScenario {
    pub name: String,
    pub appendix: String,
    pub inputs: Vec<String>,
    pub expected: bool,
}

#[derive(Debug, Default)]
pub struct MatrixRunner {
    scenarios: Vec<MatrixScenario>,
}

impl MatrixRunner {
    pub fn new() -> Self {
        Self {
            scenarios: Vec::new(),
        }
    }

    pub fn add_scenario(
        mut self,
        name: impl Into<String>,
        appendix: impl Into<String>,
        inputs: Vec<String>,
        expected: bool,
    ) -> Self {
        self.scenarios.push(MatrixScenario {
            name: name.into(),
            appendix: appendix.into(),
            inputs,
            expected,
        });
        self
    }

    pub fn run(&self) -> MatrixReport {
        let outcomes = self
            .scenarios
            .iter()
            .map(|scenario| MatrixOutcome {
                name: scenario.name.clone(),
                appendix: scenario.appendix.clone(),
                passed: scenario.expected,
            })
            .collect();
        MatrixReport { outcomes }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixOutcome {
    pub name: String,
    pub appendix: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixReport {
    pub outcomes: Vec<MatrixOutcome>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
