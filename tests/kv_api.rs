mod common;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use patchwork::{
    auth::{Action, Grant, Selector},
    http::data::{DataService, router},
};
use serde_json::json;
use tower::ServiceExt;
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    bytes: &[u8],
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::from(bytes.to_vec())).unwrap())
        .await
        .unwrap()
}
#[tokio::test]
async fn http_kv_conditions_bytes_retry_headers_and_scoped_authority() {
    let (_dir, mut store, key) = common::fixture();
    let admin = common::login(&mut store, &key);
    let st = store.create_stream(&"kv/http".parse().unwrap()).unwrap();
    let writer = store
        .mint(
            &admin,
            &[Grant {
                actions: vec![Action::KvWrite, Action::KvRead],
                selector: Selector::Stream(st.id.as_str().into()),
            }],
            600,
        )
        .unwrap();
    let app = router(DataService::new(store));
    let root = format!("/streams/{}", st.id.as_str());
    let install = json!({"type":"patchwork/kv/v1"}).to_string();
    let response = call(
        &app,
        "POST",
        &format!("{root}/attachments"),
        &admin,
        &[
            ("content-type", "application/json"),
            ("if-match", &format!("\"{}:config:0\"", st.id.as_str())),
        ],
        install.as_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let a: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let aid = a["id"].as_str().unwrap();
    let path = format!("{root}/kv/{aid}/items/{}", URL_SAFE_NO_PAD.encode("a/日本"));
    let response = call(
        &app,
        "PUT",
        &path,
        &writer.token,
        &[("if-none-match", "*"), ("idempotency-key", "first")],
        b"\0\xffbytes",
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(response.headers()["patchwork-applied-position"], "1");
    let retry = call(
        &app,
        "PUT",
        &path,
        &writer.token,
        &[("if-none-match", "*"), ("idempotency-key", "first")],
        b"\0\xffbytes",
    )
    .await;
    assert_eq!(retry.headers()["patchwork-deduplicated"], "true");
    assert_eq!(
        call(
            &app,
            "PUT",
            &path,
            &writer.token,
            &[("if-none-match", "*")],
            b"duplicate"
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );
    let response = call(&app, "GET", &path, &writer.token, &[], b"").await;
    assert_eq!(response.headers()["etag"], etag);
    assert_eq!(
        to_bytes(response.into_body(), 100).await.unwrap(),
        b"\0\xffbytes".as_slice()
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{root}/records?from=0"),
            &writer.token,
            &[],
            b""
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let response = call(
        &app,
        "DELETE",
        &path,
        &writer.token,
        &[("if-match", &etag)],
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()["patchwork-position"], "1");
    let response = call(
        &app,
        "DELETE",
        &path,
        &writer.token,
        &[("idempotency-key", "no-op")],
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!response.headers().contains_key("patchwork-position"));
    assert_eq!(response.headers()["patchwork-applied-position"], "2");
    assert_eq!(
        call(&app, "GET", &path, &writer.token, &[], b"")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}
