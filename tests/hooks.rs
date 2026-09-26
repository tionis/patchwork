mod common;
use hmac::{Hmac, Mac};
use patchwork::{
    Error,
    model::{Position, Revision, StreamConfig},
    store::hooks::{self, Config, Input, Transform},
};
const SECRET: &str = "It's a Secret to Everybody";
fn sign(body: &[u8], secret: &str) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!(
        "sha256={}",
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn config(stream_id: String) -> Input {
    Input {
        config: Config {
            stream_id,
            enabled: true,
            git_ref: Some("refs/heads/main".into()),
            transform: Transform::Wakeup,
            success_status: 204,
        },
        secret: Some(SECRET.into()),
    }
}
fn body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"ref":"refs/heads/main","after":"abcd","repository":{"full_name":"owner/repo"},"private_signed_field":"not retained"})).unwrap()
}
#[test]
fn github_published_signature_vector_and_original_byte_tampering() {
    let signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
    hooks::verify_signature(SECRET.as_bytes(), b"Hello, World!", signature).unwrap();
    assert!(hooks::verify_signature(SECRET.as_bytes(), b"Hello, World!\n", signature).is_err());
    assert!(hooks::verify_signature(b"wrong", b"Hello, World!", signature).is_err());
    for bad in ["", "sha1=00", "sha256=00"] {
        assert!(hooks::verify_signature(SECRET.as_bytes(), b"Hello, World!", bad).is_err());
    }
}
#[test]
fn authenticated_receipts_rotation_current_authority_and_safe_transform() {
    let (dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let st = store
        .create_stream(&"hooks/github".parse().unwrap())
        .unwrap();
    let input = config(st.id.as_str().into());
    let h = store.put_hook(&token, None, None, &input).unwrap();
    assert!(!serde_json::to_string(&h).unwrap().contains(SECRET));
    let bytes = body();
    let signature = sign(&bytes, SECRET);
    let delivery = uuid::Uuid::new_v4().to_string();
    let first = store
        .ingest_hook(&h.id, "push", &delivery, &signature, &bytes)
        .unwrap();
    assert_eq!(first.receipt.position.as_deref(), Some("0"));
    let stored = store.read(&st.id, Position::ZERO, 10, 65536).unwrap();
    assert!(!String::from_utf8_lossy(&stored.records[0].payload).contains("private_signed_field"));
    assert!(matches!(
        store.ingest_hook(&h.id, "push", &delivery, "sha256=00", &bytes),
        Err(Error::Unauthorized)
    ));
    let retry = store
        .ingest_hook(&h.id, "push", &delivery, &signature, &bytes)
        .unwrap();
    assert_eq!(retry.receipt.deduplicated, Some(true));
    let mut changed = body();
    changed.push(b' ');
    assert!(matches!(
        store.ingest_hook(&h.id, "push", &delivery, &sign(&changed, SECRET), &changed),
        Err(Error::Conflict)
    ));
    let mut rotated = config(st.id.as_str().into());
    rotated.secret = Some("new-secret-with-entropy-12345".into());
    store
        .put_hook(&token, Some(&h.id), Some(Revision::ZERO), &rotated)
        .unwrap();
    assert!(
        store
            .ingest_hook(&h.id, "push", &delivery, &signature, &bytes)
            .is_err()
    );
    assert_eq!(
        store
            .ingest_hook(
                &h.id,
                "push",
                &delivery,
                &sign(&bytes, rotated.secret.as_ref().unwrap()),
                &bytes
            )
            .unwrap()
            .receipt
            .deduplicated,
        Some(true)
    );
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    db.execute("UPDATE principals SET enabled=0", []).unwrap();
    assert!(matches!(
        store.ingest_hook(
            &h.id,
            "push",
            &delivery,
            &sign(&bytes, rotated.secret.as_ref().unwrap()),
            &bytes
        ),
        Err(Error::Forbidden)
    ));
    assert_eq!(store.stream(&st.id).unwrap().tail.get(), 1);
}
#[test]
fn drops_are_durable_but_validators_and_storage_failures_remain_errors() {
    let (dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let st = store.create_stream(&"hooks/drop".parse().unwrap()).unwrap();
    let input = config(st.id.as_str().into());
    let hook = store.put_hook(&token, None, None, &input).unwrap();
    let bytes = body();
    let signature = sign(&bytes, SECRET);
    let delivery = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        store
            .ingest_hook(&hook.id, "ping", &delivery, &signature, &bytes)
            .unwrap()
            .receipt
            .outcome,
        "dropped"
    );
    assert_eq!(
        store
            .ingest_hook(&hook.id, "ping", &delivery, &signature, &bytes)
            .unwrap()
            .receipt
            .deduplicated,
        Some(true)
    );
    assert_eq!(store.stream(&st.id).unwrap().tail, Position::ZERO);
    let blocked = StreamConfig {
        validators: vec![patchwork::pipeline::Validator::ContentType {
            value: "other/type".into(),
        }],
        ..Default::default()
    };
    store
        .replace_config(&st.id, Revision::ZERO, &blocked)
        .unwrap();
    let delivery = uuid::Uuid::new_v4().to_string();
    assert!(matches!(
        store.ingest_hook(&hook.id, "push", &delivery, &signature, &bytes),
        Err(Error::Rejected)
    ));
    store
        .replace_config(&st.id, Revision::new(1).unwrap(), &StreamConfig::default())
        .unwrap();
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'fault'); END;").unwrap();
    assert!(
        store
            .ingest_hook(&hook.id, "push", &delivery, &signature, &bytes)
            .is_err()
    );
    assert_eq!(store.stream(&st.id).unwrap().tail, Position::ZERO);
    let info = store.hook(&token, &hook.id).unwrap();
    assert_eq!(info.counters["dropped"], "1");
    assert_eq!(info.counters["rejected"], "1");
    assert_eq!(info.counters["errors"], "1");
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM receipts WHERE key=?1",
            [delivery],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn attenuated_tokens_cannot_launder_restrictions_into_service_grants() {
    let (_dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let st = store
        .create_stream(&"hooks/authority".parse().unwrap())
        .unwrap();
    let child =
        patchwork::auth::token::attenuate(&token, false, Some(st.id.as_str()), None, None).unwrap();
    assert!(matches!(
        store.put_hook(&child, None, None, &config(st.id.as_str().into())),
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn http_provider_ingress_returns_only_fixed_safe_responses() {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (_dir, mut store, key) = common::fixture();
    let admin = common::login(&mut store, &key);
    let st = store.create_stream(&"hooks/http".parse().unwrap()).unwrap();
    let mut input = config(st.id.as_str().into());
    input.config.success_status = 200;
    let hook = store.put_hook(&admin, None, None, &input).unwrap();
    let app = patchwork::http::data::router(patchwork::http::data::DataService::new(store));
    let bytes = body();
    let delivery = uuid::Uuid::new_v4().to_string();
    for valid in [true, true, false] {
        let signature = if valid {
            sign(&bytes, SECRET)
        } else {
            "sha256=00".into()
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/hooks/{}", hook.id))
                    .header("x-hub-signature-256", signature)
                    .header("x-github-event", "push")
                    .header("x-github-delivery", &delivery)
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if valid {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        let output = to_bytes(response.into_body(), 65536).await.unwrap();
        if valid {
            assert_eq!(output, b"ok\n".as_slice());
        }
        assert!(!String::from_utf8_lossy(&output).contains("private_signed_field"));
    }
}
