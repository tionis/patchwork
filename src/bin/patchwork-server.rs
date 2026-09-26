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
    let data_api = config.data_api;
    if data_api && !config.listen.ip().is_loopback() {
        return Err(patchwork::Error::Invalid(
            "prototype data API requires loopback listener",
        ));
    }
    if data_api {
        store.configured_origin()?;
    }
    let readiness = Readiness::default();
    let service = if data_api {
        Some(patchwork::http::data::DataService::new(store))
    } else {
        drop(store);
        None
    };
    let app = if let Some(service) = &service {
        let data = patchwork::http::data::router(service.clone());
        router(readiness.clone())
            .nest("/v1", data.clone())
            .merge(data)
    } else {
        router(readiness.clone())
    };
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    readiness.set(true);
    tracing::info!(address = %listener.local_addr()?, data_api, "server ready");
    let shutdown_state = readiness.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        #[cfg(unix)]
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        shutdown_state.set(false);
        if let Some(service) = service {
            service.shutdown();
        }
        let _ = shutdown_tx.send(());
        tracing::info!("shutdown requested");
    })
    .into_future();
    use std::future::IntoFuture;
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result?,
        _ = shutdown_rx => {
            // SSE peers may stop reading; shutdown must not wait forever.
            if let Ok(result) = tokio::time::timeout(std::time::Duration::from_secs(5), &mut server).await { result?; }
        }
    }
    tracing::info!("shutdown complete");
    Ok(())
}
