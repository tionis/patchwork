use super::*;

#[test]
fn durable_connection_settings_and_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let mut store = Store::open(dir.path()).unwrap();
        let c = &store.connection;
        assert_eq!(
            c.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            c.pragma_query_value(None, "synchronous", |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            c.pragma_query_value(None, "foreign_keys", |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(
            c.pragma_query_value(None, "busy_timeout", |r| r.get::<_, i64>(0))
                .unwrap(),
            2000
        );
        // Synthetic boundary fixture: exhaustion must be detected before insertion.
        let name: StreamName = format!("limit/{}", uuid::Uuid::new_v4()).parse().unwrap();
        let stream = store.create_stream(&name).unwrap();
        store
            .connection
            .execute(
                "UPDATE streams SET head=?2,tail=?2 WHERE id=?1",
                params![stream.id.as_str(), i64::MAX],
            )
            .unwrap();
        assert!(matches!(
            store.append(&stream.id, b"", "text/plain"),
            Err(Error::Exhausted)
        ));
        assert_eq!(store.stream(&stream.id).unwrap().tail.get(), i64::MAX);
    }
}
