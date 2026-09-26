use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use patchwork::{
    auth::ssh,
    http::data::{self, DataService},
    store::Store,
};
use serde_json::{Value, json};
use tower::ServiceExt;
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    etag: Option<&str>,
    body: Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(etag) = etag {
        req = req.header("if-match", etag);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, value)
}
#[tokio::test]
async fn data_routes_require_auth_and_enforce_cas_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key");
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .unwrap()
            .success()
    );
    let key =
        ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(&key_path).unwrap()).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    store
        .bootstrap(
            &key.public_key().to_openssh().unwrap(),
            "http://127.0.0.1:8080",
        )
        .unwrap();
    let app = data::router(DataService::new(store));
    assert_eq!(
        call(
            &app,
            "POST",
            "/streams",
            None,
            None,
            json!({"name":"events/a"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let challenge = call(
        &app,
        "POST",
        "/auth/challenges",
        None,
        None,
        json!({"ssh_public_key":key.public_key().to_openssh().unwrap()}),
    )
    .await
    .2;
    let signature = key
        .sign(
            ssh::NAMESPACE,
            ssh_key::HashAlg::Sha512,
            &STANDARD
                .decode(challenge["payload_base64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap();
    let exchange = json!({"challenge_id":challenge["challenge_id"],"signature":signature});
    let session = call(&app, "POST", "/auth/exchange", None, None, exchange.clone())
        .await
        .2;
    let token = session["token"].as_str().unwrap();
    assert_eq!(
        call(&app, "POST", "/auth/exchange", None, None, exchange)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, stream) = call(
        &app,
        "POST",
        "/streams",
        Some(token),
        None,
        json!({"name":"events/a"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = stream["id"].as_str().unwrap();
    let config_path = format!("/streams/{id}/config");
    let metadata_path = format!("/streams/{id}/metadata");
    let (_, headers, config) =
        call(&app, "GET", &config_path, Some(token), None, Value::Null).await;
    let etag = headers["etag"].to_str().unwrap();
    assert_eq!(
        call(&app, "PUT", &config_path, Some(token), None, config.clone())
            .await
            .0,
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &config_path,
            Some(token),
            Some(etag),
            config.clone()
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "PUT", &config_path, Some(token), Some(etag), config)
            .await
            .0,
        StatusCode::PRECONDITION_FAILED
    );
    let (_, metadata_headers, _) =
        call(&app, "GET", &metadata_path, Some(token), None, Value::Null).await;
    let metadata_etag = metadata_headers["etag"].to_str().unwrap();
    assert_eq!(
        call(
            &app,
            "PUT",
            &metadata_path,
            Some(token),
            Some(metadata_etag),
            json!({"value":{"title":"hello"},"object_refs":[]})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &metadata_path,
            Some(token),
            Some(metadata_etag),
            json!({"value":{}})
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    let (_, headers, problem) = call(
        &app,
        "POST",
        "/streams",
        Some(token),
        None,
        json!({"name":"bad","unexpected":true}),
    )
    .await;
    assert_eq!(headers["content-type"], "application/problem+json");
    assert!(problem["request_id"].is_string());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/streams/{id}/records"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(vec![0; 1024 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/streams/{id}/records"),
            Some("invalid"),
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}
