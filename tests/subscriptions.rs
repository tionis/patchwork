use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use patchwork::{
    auth::{Action, Grant, Selector, ssh},
    http::data::{DataService, router},
    model::{Retention, StreamConfig},
    store::Store,
};
use serde_json::{Value, json};
use std::time::Duration;
use tower::ServiceExt;
fn fixture() -> (tempfile::TempDir, Store, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let key = ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(path).unwrap()).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    store.bootstrap(&public, "http://127.0.0.1:8080").unwrap();
    let challenge = store.challenge(&public).unwrap();
    let signature = key
        .sign(
            ssh::NAMESPACE,
            ssh_key::HashAlg::Sha512,
            &STANDARD.decode(challenge.payload_base64).unwrap(),
        )
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap();
    let token = store
        .exchange(&challenge.challenge_id, &signature)
        .unwrap()
        .token;
    (dir, store, token)
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Vec<u8>,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}
async fn chunk(
    stream: &mut (
             impl futures_util::Stream<Item = std::result::Result<axum::body::Bytes, axum::Error>>
             + Unpin
         ),
) -> String {
    String::from_utf8(
        tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
#[tokio::test]
async fn follow_replays_concurrent_appends_and_closes_after_revocation() {
    let (_dir, mut store, admin) = fixture();
    let st = store
        .create_stream(&"events/follow".parse().unwrap())
        .unwrap();
    let reader = store
        .mint(
            &admin,
            &[Grant {
                actions: vec![Action::RecordRead],
                selector: Selector::Stream(st.id.as_str().into()),
            }],
            600,
        )
        .unwrap();
    let app = router(DataService::new(store));
    let path = format!("/streams/{}/follow?from=0", st.id.as_str());
    let response = call(&app, "GET", &path, &reader.token, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut events = response.into_body().into_data_stream();
    assert!(chunk(&mut events).await.contains("event: ready"));
    let response = call(
        &app,
        "POST",
        &format!("/streams/{}/records", st.id.as_str()),
        &admin,
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let record = chunk(&mut events).await;
    assert!(record.contains("event: record"));
    assert!(record.contains(&format!("id: {}:1", st.id.as_str())));
    assert_eq!(
        call(
            &app,
            "DELETE",
            &format!("/credentials/{}", reader.credential_id),
            &admin,
            vec![]
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(chunk(&mut events).await.contains("event: unauthorized"));
    assert!(events.next().await.is_none());
}
#[tokio::test]
async fn live_is_ephemeral_bounded_and_watch_only_receives_hints() {
    let (_dir, mut store, admin) = fixture();
    let st = store
        .create_stream_with(
            &"events/live".parse().unwrap(),
            &StreamConfig {
                retention: Retention::None,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
    let watcher = store
        .mint(
            &admin,
            &[Grant {
                actions: vec![Action::StreamWatch],
                selector: Selector::Prefix("events/".into()),
            }],
            600,
        )
        .unwrap();
    let app = router(DataService::new(store));
    let response = call(
        &app,
        "POST",
        "/watch",
        &watcher.token,
        json!({"prefix":"events/"}).to_string().into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut watch = response.into_body().into_data_stream();
    assert!(chunk(&mut watch).await.contains("ready"));
    let response = call(
        &app,
        "GET",
        &format!("/streams/{}/live", st.id.as_str()),
        &admin,
        vec![],
    )
    .await;
    let mut live = response.into_body().into_data_stream();
    assert!(chunk(&mut live).await.contains("epoch"));
    let records = format!("/streams/{}/records", st.id.as_str());
    assert_eq!(
        call(&app, "GET", &records, &watcher.token, vec![])
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    for n in 0..10 {
        let response = call(
            &app,
            "POST",
            &records,
            &admin,
            format!("secret-{n}").into_bytes(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    let hint = chunk(&mut watch).await;
    assert!(hint.contains("changed"));
    assert!(!hint.contains("secret"));
    assert!(!hint.contains("payload"));
    assert!(chunk(&mut live).await.contains("lagged"));
    assert!(live.next().await.is_none());
    let response = call(&app, "GET", &records, &admin, vec![]).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn explicit_watch_is_all_or_nothing_and_listing_rechecks_items() {
    let (_dir, mut store, admin) = fixture();
    let a = store.create_stream(&"events/a".parse().unwrap()).unwrap();
    let b = store.create_stream(&"private/b".parse().unwrap()).unwrap();
    let user = store
        .mint(
            &admin,
            &[Grant {
                actions: vec![
                    Action::StreamWatch,
                    Action::StreamList,
                    Action::StreamInspect,
                ],
                selector: Selector::Prefix("events/".into()),
            }],
            600,
        )
        .unwrap();
    let app = router(DataService::new(store));
    assert_eq!(
        call(
            &app,
            "POST",
            "/watch",
            &user.token,
            json!({"stream_ids":[a.id.as_str(),b.id.as_str()]})
                .to_string()
                .into_bytes()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let response = call(&app, "GET", "/streams?limit=1", &user.token, vec![]).await;
    let page: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["id"], a.id.as_str());
}
