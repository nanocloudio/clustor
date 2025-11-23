use clap::Parser;
use env_logger::Env;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
pub struct Cli {
    /// Path to cluster configuration YAML
    #[arg(long)]
    pub config: PathBuf,

    /// Node ID to run (e.g. node-a)
    #[arg(long)]
    pub node: String,

    /// Directory for persisted Raft state (per-node subdirectories are created automatically)
    #[arg(long, default_value = "state")]
    pub state_dir: PathBuf,

    /// env_logger-style filter string (e.g. "info,clustor=debug"); overrides RUST_LOG/defaults
    #[arg(long)]
    pub log_filter: Option<String>,
}

pub const DEFAULT_LOG_FILTER: &str = "info,clustor=info,clustor::net::raft=info";

pub fn init_logging(cli_filter: Option<&str>) {
    let env = Env::default().default_filter_or(DEFAULT_LOG_FILTER);
    let mut builder = env_logger::Builder::from_env(env);
    builder.parse_filters("clustor::net::raft=info");
    if let Some(filter) = cli_filter {
        builder.parse_filters(filter);
    }
    builder.format_timestamp_secs();
    builder.format(|buf, record| {
        let ts = buf.timestamp();
        writeln!(
            buf,
            "[{} {:<5} {}] {}",
            ts,
            record.level(),
            record.target(),
            record.args()
        )
    });
    builder.init();
}
