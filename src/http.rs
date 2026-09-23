use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// False until migrations and the storage probe complete; false on shutdown.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);
impl Readiness {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

pub fn router(readiness: Readiness) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { Json(Health { status: "live" }) }),
        )
        .route("/readyz", get(ready))
        .with_state(readiness)
}

async fn ready(State(state): State<Readiness>) -> (StatusCode, Json<Health>) {
    if state.0.load(Ordering::Acquire) {
        (StatusCode::OK, Json(Health { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(Health {
                status: "not_ready",
            }),
        )
    }
}
