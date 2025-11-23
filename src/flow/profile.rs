use crate::profile::PartitionProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FlowProfile {
    #[default]
    Latency,
    Throughput,
    Wan,
}

impl FlowProfile {
    pub(crate) fn params(&self) -> super::pid::PidParams {
        match self {
            FlowProfile::Latency => super::pid::PidParams {
                kp: 0.60,
                ki: 0.20,
                kd: 0.10,
                derivative_tau_ms: 300.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
            },
            FlowProfile::Throughput => super::pid::PidParams {
                kp: 0.50,
                ki: 0.15,
                kd: 0.08,
                derivative_tau_ms: 300.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
            },
            FlowProfile::Wan => super::pid::PidParams {
                kp: 0.40,
                ki: 0.10,
                kd: 0.05,
                derivative_tau_ms: 450.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
            },
        }
    }

    pub fn partition_profile(&self) -> PartitionProfile {
        match self {
            FlowProfile::Latency => PartitionProfile::Latency,
            FlowProfile::Throughput => PartitionProfile::Throughput,
            FlowProfile::Wan => PartitionProfile::Wan,
        }
    }

    pub fn ingest_ops_target(&self) -> Option<f64> {
        self.partition_profile()
            .config()
            .ingest_ops_target
            .map(|value| value as f64)
    }

    pub fn alert_floor_ops_per_sec(&self) -> Option<f64> {
        self.partition_profile()
            .config()
            .throughput_alert_floor
            .map(|value| value as f64)
    }

    pub fn metric_label(&self) -> &'static str {
        match self {
            FlowProfile::Latency => "latency",
            FlowProfile::Throughput => "throughput",
            FlowProfile::Wan => "wan",
        }
    }
}
