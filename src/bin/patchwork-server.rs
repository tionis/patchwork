use clap::Parser;
use patchwork::{
    config::{ServerConfig, init_tracing},
    http::{Readiness, router},
    store::Store,
};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> patchwork::Result<()> {
    let config = ServerConfig::parse();
    init_tracing(&config.log_filter)?;
    // Fail closed before binding if initialization or migration fails.
    let store = Store::open(&config.data_dir)?;
    let readiness = Readiness::default();
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    readiness.set(true);
    tracing::info!(address = %listener.local_addr()?, "server ready; data API unavailable");
    let shutdown_state = readiness.clone();
    axum::serve(listener, router(readiness))
        .with_graceful_shutdown(async move {
            #[cfg(unix)]
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
            shutdown_state.set(false);
            tracing::info!("shutdown requested");
        })
        .await?;
    drop(store);
    tracing::info!("shutdown complete");
    Ok(())
}
