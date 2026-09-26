use crate::{Error, Result};
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Patchwork CLI (bootstrap)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-time local administrator bootstrap. The data directory is private.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Sign a one-time challenge with ssh-keygen (private key or agent-backed public key).
    Login {
        #[arg(long)]
        url: String,
        #[arg(long)]
        ssh_key: std::path::PathBuf,
        #[arg(long)]
        ssh_public_key: std::path::PathBuf,
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Create, inspect, resolve or delete streams.
    Stream {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[command(subcommand)]
        command: StreamCommand,
    },
    /// Append exact bytes from stdin and print the receipt as JSON.
    Append {
        #[command(flatten)]
        connection: ConnectionArgs,
        stream_id: String,
    },
    /// Read a bounded JSON/base64 replay page.
    Read {
        #[command(flatten)]
        connection: ConnectionArgs,
        stream_id: String,
        #[arg(long, default_value = "0")]
        from: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Write one record as exact bytes to stdout.
    Get {
        #[command(flatten)]
        connection: ConnectionArgs,
        stream_id: String,
        position: String,
    },
    /// Mint a scoped API credential or revoke one using a fresh SSH session.
    Token {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Check liveness AND readiness. This bootstrap client supports HTTP only.
    Health {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
    },
}

pub async fn check_health(base: &str) -> Result<()> {
    let base = reqwest::Url::parse(base).map_err(|_| Error::Invalid("server URL"))?;
    if base.scheme() != "http"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        return Err(Error::Invalid("server URL (expected an HTTP origin)"));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Error::HealthRequest)?;
    for path in ["healthz", "readyz"] {
        let response = client
            .get(base.join(path).map_err(|_| Error::Invalid("server URL"))?)
            .send()
            .await
            .map_err(Error::HealthRequest)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Unhealthy(response.status()));
        }
    }
    Ok(())
}

#[derive(clap::Args)]
pub struct ConnectionArgs {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    pub url: String,
    #[arg(long)]
    pub token_file: std::path::PathBuf,
}
#[derive(Subcommand)]
pub enum AdminCommand {
    Bootstrap {
        #[arg(long)]
        data_dir: std::path::PathBuf,
        #[arg(long)]
        ssh_public_key: std::path::PathBuf,
        #[arg(long)]
        origin: String,
    },
}
#[derive(Subcommand)]
pub enum StreamCommand {
    Create {
        name: String,
    },
    Show {
        id: String,
    },
    Resolve {
        name: String,
    },
    Delete {
        id: String,
        #[arg(long)]
        config_revision: String,
    },
}
#[derive(Subcommand)]
pub enum TokenCommand {
    Mint {
        #[arg(long)]
        scope_file: std::path::PathBuf,
        #[arg(long, default_value_t = 3600)]
        lifetime_seconds: i64,
        #[arg(long)]
        output: std::path::PathBuf,
    },
    Revoke {
        id: String,
    },
}

mod commands;
pub use commands::run;
