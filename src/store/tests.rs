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

#[test]
fn record_count_seals_empty_payload_segment_and_clock_rollback_is_conservative() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"segments".parse().unwrap()).unwrap();
    // Seed a real contiguous prefix in one transaction to avoid 9,999 fsyncs.
    let future = 4_000_000_000_000_i64;
    store.connection.execute(
        "WITH RECURSIVE positions(p) AS (SELECT 0 UNION ALL SELECT p+1 FROM positions WHERE p<9998)
         INSERT INTO records SELECT ?1,p,x'', 'text/plain',?2 FROM positions",
        params![stream.id.as_str(), future],
    ).unwrap();
    store
        .connection
        .execute(
            "UPDATE streams SET tail=9999 WHERE id=?1",
            [stream.id.as_str()],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO segments VALUES (?1,0,9999,9999,0,?2,?2,0)",
            params![stream.id.as_str(), future],
        )
        .unwrap();
    store.append(&stream.id, b"", "text/plain").unwrap();
    store.append(&stream.id, b"", "text/plain").unwrap();
    let segments = store.segments(&stream.id, Position::ZERO, 10).unwrap();
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].record_count, SEGMENT_TARGET_RECORDS);
    assert_eq!(segments[0].end.get(), 10000);
    assert_eq!(segments[0].payload_bytes, 0);
    assert!(segments[0].sealed);
    assert_eq!(segments[0].max_accepted_at_ms, future);
    assert!(segments[0].min_accepted_at_ms < future);
    assert_eq!(segments[1].start.get(), 10000);
    drop(store);
    let mut reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        reopened.segments(&stream.id, Position::ZERO, 10).unwrap(),
        segments
    );
}

#[test]
fn revision_exhaustion_and_segment_faults_roll_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"faults".parse().unwrap()).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_segment BEFORE INSERT ON segments BEGIN SELECT RAISE(ABORT, 'test fault'); END;").unwrap();
    assert!(store.append(&stream.id, b"rollback", "text/plain").is_err());
    assert_eq!(store.stream(&stream.id).unwrap().tail, Position::ZERO);
    assert!(
        store
            .read(&stream.id, Position::ZERO, 10, 100)
            .unwrap()
            .records
            .is_empty()
    );
    store
        .connection
        .execute_batch("DROP TRIGGER fail_segment")
        .unwrap();
    store.append(&stream.id, b"kept", "text/plain").unwrap();
    let segments = store.segments(&stream.id, Position::ZERO, 10).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_tail BEFORE UPDATE OF tail ON streams BEGIN SELECT RAISE(ABORT, 'test fault'); END;").unwrap();
    assert!(store.append(&stream.id, b"rollback", "text/plain").is_err());
    assert_eq!(
        store.segments(&stream.id, Position::ZERO, 10).unwrap(),
        segments
    );
    assert_eq!(
        store
            .read(&stream.id, Position::ZERO, 10, 100)
            .unwrap()
            .records
            .len(),
        1
    );
    store
        .connection
        .execute(
            "UPDATE streams SET config_revision=?1,metadata_revision=?1",
            [i64::MAX],
        )
        .unwrap();
    let max = Revision::new(i64::MAX).unwrap();
    assert!(matches!(
        store.replace_config(&stream.id, max, &StreamConfig::default()),
        Err(Error::Exhausted)
    ));
    assert!(matches!(
        store.replace_metadata(&stream.id, max, &Metadata::default()),
        Err(Error::Exhausted)
    ));
    assert!(matches!(
        store.delete_stream(&stream.id, max),
        Err(Error::Exhausted)
    ));
    assert_eq!(store.lookup_stream(&stream.name).unwrap().id, stream.id);
    assert_eq!(store.config(&stream.id).unwrap().revision, max);
    assert_eq!(store.metadata(&stream.id).unwrap().revision, max);
}
