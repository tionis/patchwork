mod common;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use patchwork::{
    auth::{Action, Grant, Selector},
    http::data::{DataService, router},
};
use serde_json::Value;
use tower::ServiceExt;

fn grant(actions: &[Action], selector: Selector) -> Grant {
    Grant {
        actions: actions.to_vec(),
        selector,
    }
}
async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: &[u8],
) -> axum::response::Response {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap()
}
async fn json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
}

#[test]
fn url_credentials_must_be_narrow_single_purpose_and_long_lived_only_when_flagged() {
    let (_dir, mut store, key) = common::fixture();
    let admin = common::login(&mut store, &key);
    let st = store.create_stream(&"hooks/wake".parse().unwrap()).unwrap();
    let id = Selector::Stream(st.id.as_str().into());
    let append = [Action::RecordAppend];
    let read = [Action::RecordRead, Action::RecordSubscribe];

    for bad in [
        vec![],
        vec![grant(
            &[Action::RecordAppend, Action::RecordRead],
            id.clone(),
        )],
        vec![grant(&append, id.clone()), grant(&read, id.clone())],
        vec![grant(&[Action::AdminRead], id.clone())],
        vec![grant(&[Action::CredentialMint], id.clone())],
        vec![grant(&[Action::StreamCreate], id.clone())],
        vec![grant(&read, Selector::Prefix(String::new()))],
        vec![grant(
            &read,
            Selector::Instance(uuid::Uuid::new_v4().to_string()),
        )],
    ] {
        assert!(store.mint_with(&admin, &bad, 600, true).is_err(), "{bad:?}");
    }
    // A prefix that names a subtree, or an exact stream, is acceptable.
    store
        .mint_with(
            &admin,
            &[grant(&read, Selector::Prefix("hooks/".into()))],
            600,
            true,
        )
        .unwrap();
    store
        .mint_with(&admin, &[grant(&append, id.clone())], 600, true)
        .unwrap();

    // Only URL credentials get the long lifetime.
    let year = 365 * 24 * 3600;
    assert!(
        store
            .mint_with(&admin, &[grant(&read, id.clone())], year, true)
            .is_ok()
    );
    assert!(
        store
            .mint_with(&admin, &[grant(&read, id.clone())], year, false)
            .is_err()
    );
    assert!(
        store
            .mint_with(&admin, &[grant(&read, id.clone())], 315_360_001, true)
            .is_err()
    );

    // A URL credential can never mint, even though it is an API credential.
    let url = store
        .mint_with(&admin, &[grant(&read, id)], 600, true)
        .unwrap();
    assert!(store.mint(&url.token, &[], 60).is_err());
}

#[tokio::test]
async fn query_tokens_work_only_for_url_credentials_and_leak_nothing() {
    let (_dir, mut store, key) = common::fixture();
    let admin = common::login(&mut store, &key);
    let st = store.create_stream(&"hooks/wake".parse().unwrap()).unwrap();
    let id = Selector::Stream(st.id.as_str().into());
    let publish = store
        .mint_with(
            &admin,
            &[grant(&[Action::RecordAppend], id.clone())],
            3600,
            true,
        )
        .unwrap();
    let subscribe = store
        .mint_with(
            &admin,
            &[grant(
                &[Action::RecordRead, Action::RecordSubscribe],
                id.clone(),
            )],
            3600,
            true,
        )
        .unwrap();
    let plain = store
        .mint(
            &admin,
            &[grant(&[Action::RecordAppend, Action::RecordRead], id)],
            3600,
        )
        .unwrap();
    let app = router(DataService::new(store));
    let records = format!("/streams/{}/records", st.id.as_str());

    // Publish through the URL: no Authorization header at all.
    let response = call(
        &app,
        "POST",
        &format!("{records}?token={}", publish.token),
        None,
        b"wake",
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["cache-control"], "no-store");

    // Percent-encoded padding and other parameters still work; the token
    // parameter never reaches handlers that reject unknown query fields.
    let encoded = subscribe.token.replace('=', "%3D");
    let response = call(
        &app,
        "GET",
        &format!("{records}?from=0&token={encoded}"),
        None,
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let page = json(response).await;
    assert_eq!(page["records"].as_array().unwrap().len(), 1);

    // Purpose separation holds on the URL too.
    let response = call(
        &app,
        "GET",
        &format!("{records}?from=0&token={}", publish.token),
        None,
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = call(
        &app,
        "POST",
        &format!("{records}?token={}", subscribe.token),
        None,
        b"x",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Ordinary API credentials and sessions are refused in a query string,
    // but remain valid in the header.
    for token in [&plain.token, &admin] {
        let response = call(
            &app,
            "GET",
            &format!("{records}?from=0&token={token}"),
            None,
            b"",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = call(
        &app,
        "GET",
        &format!("{records}?from=0"),
        Some(&plain.token),
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["cache-control"], "no-store");

    // Header and query together, duplicates, empty and garbage are all refused.
    let both = call(
        &app,
        "GET",
        &format!("{records}?from=0&token={}", subscribe.token),
        Some(&subscribe.token),
        b"",
    )
    .await;
    assert_eq!(both.status(), StatusCode::UNAUTHORIZED);
    let twice = format!("{records}?token={0}&token={0}", subscribe.token);
    assert_eq!(
        call(&app, "GET", &twice, None, b"").await.status(),
        StatusCode::UNAUTHORIZED
    );
    for bad in ["token=", "token=%zz", "token=not-a-token"] {
        let response = call(&app, "GET", &format!("{records}?from=0&{bad}"), None, b"").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{bad}");
    }
    // No token at all is unchanged behavior.
    assert_eq!(
        call(&app, "GET", &format!("{records}?from=0"), None, b"")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Revocation applies to URL credentials like any other.
    let response = call(
        &app,
        "DELETE",
        &format!("/credentials/{}", subscribe.credential_id),
        Some(&admin),
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = call(
        &app,
        "GET",
        &format!("{records}?from=0&token={}", subscribe.token),
        None,
        b"",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
