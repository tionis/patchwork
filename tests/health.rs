use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use patchwork::http::{Readiness, router};
use tower::ServiceExt;

#[tokio::test]
async fn readiness_transitions_and_data_routes_absent() {
    let state = Readiness::default();
    let app = router(state.clone());
    for (ready, path, expected) in [
        (false, "/healthz", StatusCode::OK),
        (false, "/readyz", StatusCode::SERVICE_UNAVAILABLE),
        (true, "/readyz", StatusCode::OK),
        (false, "/readyz", StatusCode::SERVICE_UNAVAILABLE),
        (true, "/v1/streams", StatusCode::NOT_FOUND),
        (true, "/auth/exchange", StatusCode::NOT_FOUND),
    ] {
        state.set(ready);
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn cli_checks_both_health_endpoints() {
    let state = Readiness::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(state.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    assert!(patchwork::cli::check_health(&url).await.is_err());
    state.set(true);
    assert!(patchwork::cli::check_health(&url).await.is_ok());
    assert!(
        patchwork::cli::check_health("http://user:secret@localhost")
            .await
            .is_err()
    );
    stop.send(()).unwrap();
    server.await.unwrap();
}
