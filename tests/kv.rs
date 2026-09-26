mod common;
use patchwork::{
    Error,
    auth::{Action, Grant, Selector},
    model::{Position, Retention, Revision, StreamConfig},
    store::{
        Store,
        kv::{self, Condition, Event},
    },
};
fn put(key: &str, value: &[u8], condition: Option<Condition>) -> Event {
    Event::put(
        key.into(),
        value,
        "application/octet-stream".into(),
        condition,
    )
    .unwrap()
}
#[test]
fn generic_and_adapter_writes_share_authoritative_conditions_and_tombstones() {
    let (dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let stream = store.create_stream(&"kv/state".parse().unwrap()).unwrap();
    let attachment = store.enable_kv(&token, &stream.id, Revision::ZERO).unwrap();
    assert!(
        store
            .append(&stream.id, b"arbitrary", "text/plain")
            .is_err()
    );
    let first = store
        .kv_mutate(
            &token,
            &stream.id,
            &attachment.id,
            &put("theme", b"dark", Some(Condition::Absent)),
            None,
        )
        .unwrap();
    assert_eq!(first.position.as_deref(), Some("0"));
    assert_eq!(first.status, 201);
    let event = put(
        "theme",
        b"light",
        Some(Condition::Revision {
            revision: "0".into(),
        }),
    );
    store
        .append_authorized(
            &token,
            &stream.id,
            &event.encode().unwrap(),
            "application/json",
            None,
        )
        .unwrap();
    assert!(matches!(
        store.kv_mutate(&token, &stream.id, &attachment.id, &event, None),
        Err(Error::RevisionMismatch)
    ));
    let delete = Event::delete(
        "theme".into(),
        Some(Condition::Revision {
            revision: "1".into(),
        }),
    )
    .unwrap();
    store
        .kv_mutate(&token, &stream.id, &attachment.id, &delete, None)
        .unwrap();
    assert!(matches!(
        store.kv_get(&token, &stream.id, &attachment.id, "theme"),
        Err(Error::NotFound)
    ));
    let next = store
        .kv_mutate(
            &token,
            &stream.id,
            &attachment.id,
            &put("theme", b"again", Some(Condition::Absent)),
            None,
        )
        .unwrap();
    assert_eq!(next.revision.as_deref(), Some("3"));
    assert!(matches!(
        store.kv_mutate(&token, &stream.id, &attachment.id, &event, None),
        Err(Error::RevisionMismatch)
    ));
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    let value = store
        .kv_get(&token, &stream.id, &attachment.id, "theme")
        .unwrap();
    assert_eq!(value.bytes, b"again");
    assert_eq!(value.applied_position, "4");
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_record BEFORE INSERT ON records BEGIN SELECT RAISE(ABORT,'fault'); END;").unwrap();
    assert!(
        store
            .kv_mutate(
                &token,
                &stream.id,
                &attachment.id,
                &put("theme", b"rollback", None),
                Some("fault")
            )
            .is_err()
    );
    assert_eq!(
        store
            .kv_get(&token, &stream.id, &attachment.id, "theme")
            .unwrap()
            .bytes,
        b"again"
    );
    assert_eq!(store.stream(&stream.id).unwrap().tail.get(), 4);
    assert_eq!(
        db.query_row("SELECT count(*) FROM receipts WHERE key='fault'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn retries_survive_changed_state_and_pipeline_and_require_current_kv_authority() {
    let (_dir, mut store, key) = common::fixture();
    let admin = common::login(&mut store, &key);
    let st = store.create_stream(&"kv/retry".parse().unwrap()).unwrap();
    let a = store.enable_kv(&admin, &st.id, Revision::ZERO).unwrap();
    let writer = store
        .mint(
            &admin,
            &[Grant {
                actions: vec![Action::KvRead, Action::KvWrite],
                selector: Selector::Stream(st.id.as_str().into()),
            }],
            600,
        )
        .unwrap();
    let event = put("x", b"first", Some(Condition::Absent));
    store
        .kv_mutate(&writer.token, &st.id, &a.id, &event, Some("once"))
        .unwrap();
    store
        .kv_mutate(&admin, &st.id, &a.id, &put("x", b"second", None), None)
        .unwrap();
    let changed = StreamConfig {
        filters: vec![patchwork::pipeline::Filter::RejectIfContains {
            data_base64: String::new(),
        }],
        ..Default::default()
    };
    store
        .replace_config(&st.id, Revision::new(1).unwrap(), &changed)
        .unwrap();
    let retry = store
        .kv_mutate(&writer.token, &st.id, &a.id, &event, Some("once"))
        .unwrap();
    assert_eq!(retry.deduplicated, Some(true));
    assert_eq!(retry.position.as_deref(), Some("0"));
    assert!(
        store
            .append_authorized(
                &writer.token,
                &st.id,
                &event.encode().unwrap(),
                "application/json",
                None
            )
            .is_err()
    );
    assert!(matches!(
        store.kv_mutate(
            &writer.token,
            &st.id,
            &a.id,
            &put("x", b"changed", None),
            Some("once")
        ),
        Err(Error::Conflict)
    ));
    store.revoke(&admin, &writer.credential_id).unwrap();
    assert!(
        store
            .kv_mutate(&writer.token, &st.id, &a.id, &event, Some("once"))
            .is_err()
    );
}
#[test]
fn competing_kv_conditions_have_one_winner() {
    let (dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let st = store.create_stream(&"kv/race".parse().unwrap()).unwrap();
    let a = store.enable_kv(&token, &st.id, Revision::ZERO).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let mut s = Store::open(dir.path()).unwrap();
            let token = token.clone();
            let sid = st.id.clone();
            let aid = a.id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                s.kv_mutate(
                    &token,
                    &sid,
                    &aid,
                    &put("one", b"winner", Some(Condition::Absent)),
                    None,
                )
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::RevisionMismatch)))
            .count(),
        3
    );
    assert_eq!(store.stream(&st.id).unwrap().tail.get(), 1);
}
#[test]
fn size_limits_canonical_validation_installation_and_source_retention() {
    let (_dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let config = StreamConfig {
        retention: Retention::Bounded {
            max_bytes: Some(1),
            max_age_seconds: None,
        },
        ..Default::default()
    };
    let st = store
        .create_stream_with(&"kv/bounds".parse().unwrap(), &config, &Default::default())
        .unwrap();
    let a = store.enable_kv(&token, &st.id, Revision::ZERO).unwrap();
    let event = put("boundary", &vec![0; kv::MAX_VALUE_BYTES], None);
    store
        .kv_mutate(&token, &st.id, &a.id, &event, None)
        .unwrap();
    assert_eq!(store.stream(&st.id).unwrap().head, Position::ZERO);
    assert!(
        Event::put(
            "x".into(),
            &vec![0; kv::MAX_VALUE_BYTES + 1],
            "text/plain".into(),
            None
        )
        .is_err()
    );
    let size = event.encode().unwrap().len();
    let mut smaller = config.clone();
    smaller.max_record_bytes = size - 1;
    store
        .replace_config(&st.id, Revision::new(1).unwrap(), &smaller)
        .unwrap();
    assert!(matches!(
        store.kv_mutate(&token, &st.id, &a.id, &event, None),
        Err(Error::TooLarge)
    ));
    smaller.max_record_bytes = size;
    store
        .replace_config(&st.id, Revision::new(2).unwrap(), &smaller)
        .unwrap();
    store
        .kv_mutate(&token, &st.id, &a.id, &event, None)
        .unwrap();
    for invalid in [
        br#"{"version":1,"op":"delete","key":"x","unknown":true}"#.as_slice(),
        br#"{"version":2,"op":"delete","key":"x"}"#,
        br#"{"version":1,"op":"delete","key":"x","key":"y"}"#,
    ] {
        assert!(Event::parse(invalid).is_err());
    }
    let nonempty = store
        .create_stream(&"kv/nonempty".parse().unwrap())
        .unwrap();
    store.append(&nonempty.id, b"x", "text/plain").unwrap();
    assert!(
        store
            .enable_kv(&token, &nonempty.id, Revision::ZERO)
            .is_err()
    );
    let live = store
        .create_stream_with(
            &"kv/live".parse().unwrap(),
            &StreamConfig {
                retention: Retention::None,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
    assert!(store.enable_kv(&token, &live.id, Revision::ZERO).is_err());
}
