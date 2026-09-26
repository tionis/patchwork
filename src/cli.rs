use crate::{Error, Result};
use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Patchwork authenticated stream CLI")]
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
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
    },
    AppendNamed {
        #[command(flatten)]
        connection: ConnectionArgs,
        name: String,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,
    },
    Follow {
        #[command(flatten)]
        connection: ConnectionArgs,
        stream_id: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        last_event_id: Option<String>,
    },
    Live {
        #[command(flatten)]
        connection: ConnectionArgs,
        stream_id: String,
    },
    Watch {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long, conflicts_with = "stream_ids")]
        prefix: Option<String>,
        #[arg(long = "stream", required_unless_present = "prefix")]
        stream_ids: Vec<String>,
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
    /// Check liveness and readiness.
    Health {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        url: String,
    },
}

pub async fn check_health(base: &str) -> Result<()> {
    let base = reqwest::Url::parse(base).map_err(|_| Error::Invalid("server URL"))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        return Err(Error::Invalid(
            "server URL (expected an HTTP or HTTPS origin)",
        ));
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
    Principals {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[command(subcommand)]
        command: PrincipalCommand,
    },
    Policy {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, requires = "file")]
        revision: Option<String>,
    },
    CreationRules {
        #[command(flatten)]
        connection: ConnectionArgs,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, requires = "file")]
        revision: Option<String>,
    },
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
        #[arg(long)]
        config_file: Option<std::path::PathBuf>,
        #[arg(long)]
        metadata_file: Option<std::path::PathBuf>,
    },
    List {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Config {
        id: String,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, requires = "file")]
        revision: Option<String>,
    },
    Metadata {
        id: String,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, requires = "file")]
        revision: Option<String>,
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
    List,
    Whoami,
    Inspect,
    Attenuate {
        #[arg(long)]
        read_only: bool,
        #[arg(long)]
        stream: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        output: std::path::PathBuf,
    },
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

#[derive(Subcommand)]
pub enum PrincipalCommand {
    List,
    Create {
        #[arg(long)]
        file: std::path::PathBuf,
    },
    Update {
        id: String,
        #[arg(long)]
        file: std::path::PathBuf,
        #[arg(long)]
        revision: String,
    },
}
