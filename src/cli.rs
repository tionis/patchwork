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
