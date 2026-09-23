use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[command(version, about = "Patchwork bootstrap server (health endpoints only)")]
pub struct ServerConfig {
    /// Explicit directory for the new-format database. Use a fresh directory.
    #[arg(long)]
    pub data_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    #[arg(long, default_value = "info")]
    pub log_filter: String,
}

pub fn init_tracing(filter: &str) -> crate::Result<()> {
    let filter =
        tracing_subscriber::EnvFilter::try_new(filter).map_err(|_| crate::Error::TracingFilter)?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_writer(std::io::stderr)
        .init();
    Ok(())
}
