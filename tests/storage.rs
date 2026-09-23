use patchwork::{
    Error,
    model::{Position, Revision, StreamId, StreamName},
    store::{MAX_RECORD_BYTES, Store},
};

#[test]
fn fresh_append_read_and_reopen_preserves_bytes_and_positions() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store
        .create_stream(&"events/test".parse().unwrap())
        .unwrap();
    assert_eq!(stream.head, Position::ZERO);
    assert_eq!(stream.tail, Position::ZERO);
    assert!(matches!(
        store.create_stream(&stream.name),
        Err(Error::Conflict)
    ));
    let payloads = [vec![0, 255, 128, b'\n'], vec![], vec![42; MAX_RECORD_BYTES]];
    for (i, payload) in payloads.iter().enumerate() {
        assert_eq!(
            store
                .append(&stream.id, payload, "application/octet-stream")
                .unwrap()
                .get(),
            i as i64
        );
    }
    let page = store
        .read(&stream.id, Position::ZERO, 100, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(page.tail.get(), 3);
    assert_eq!(page.next_position.get(), 3);
    assert_eq!(
        page.records.iter().map(|r| &r.payload).collect::<Vec<_>>(),
        payloads.iter().collect::<Vec<_>>()
    );
    let original = page.records;
    drop(store);
    let mut reopened = Store::open(dir.path()).unwrap();
    assert_eq!(reopened.stream(&stream.id).unwrap().name, stream.name);
    assert_eq!(
        reopened
            .read(&stream.id, Position::ZERO, 100, 4 * 1024 * 1024)
            .unwrap()
            .records,
        original
    );
    assert_eq!(
        reopened
            .append(&stream.id, b"next", "text/plain")
            .unwrap()
            .get(),
        3
    );
    assert!(
        reopened
            .read(&stream.id, Position::new(4).unwrap(), 1, 1)
            .unwrap()
            .records
            .is_empty()
    );
    assert!(matches!(
        reopened.read(&stream.id, Position::new(5).unwrap(), 1, 1),
        Err(Error::PositionAhead)
    ));
}

#[test]
fn rejected_append_does_not_allocate_and_page_budget_makes_progress() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"a".parse().unwrap()).unwrap();
    assert!(matches!(
        store.append(&stream.id, &vec![0; MAX_RECORD_BYTES + 1], "text/plain"),
        Err(Error::TooLarge)
    ));
    assert!(store.append(&stream.id, b"abc", "\r\n").is_err());
    assert_eq!(
        store
            .append(&stream.id, b"abc", "text/plain")
            .unwrap()
            .get(),
        0
    );
    store.append(&stream.id, b"def", "text/plain").unwrap();
    let page = store.read(&stream.id, Position::ZERO, 10, 1).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].payload, b"abc");
    assert_eq!(page.next_position.get(), 1);
    assert!(store.read(&stream.id, Position::ZERO, 0, 1).is_err());
    assert!(store.read(&stream.id, Position::ZERO, 1, 0).is_err());
    let unknown: StreamId = "str_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse().unwrap();
    assert!(matches!(
        store.append(&unknown, b"", "text/plain"),
        Err(Error::NotFound)
    ));
}

#[test]
fn domain_values_are_checked() {
    for value in ["", "-1", "+1", "01", "1.0", " 1", "9223372036854775808"] {
        assert!(value.parse::<Position>().is_err(), "{value}");
        assert!(value.parse::<Revision>().is_err(), "{value}");
    }
    assert!(Position::new(-1).is_err());
    assert!(Revision::new(-1).is_err());
    assert!(Position::new(i64::MAX).unwrap().next().is_err());
    assert!(Revision::new(i64::MAX).unwrap().next().is_err());
    assert_eq!("0".parse::<Revision>().unwrap(), Revision::ZERO);
    for name in [
        "",
        "/foo",
        "foo/",
        "foo//bar",
        "foo/..",
        ".",
        "é",
        "foo%2Fbar",
        "a\\b",
        "a\0",
    ] {
        assert!(name.parse::<StreamName>().is_err(), "{name:?}");
    }
    assert!("x".repeat(241).parse::<StreamName>().is_err());
    for id in [
        "str_1",
        "",
        "snap_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "str_00000000-0000-0000-0000-000000000000",
    ] {
        assert!(id.parse::<StreamId>().is_err());
    }
}

#[test]
fn foreign_and_future_databases_are_rejected_without_migration() {
    let dir = tempfile::tempdir().unwrap();
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    db.execute_batch("CREATE TABLE legacy(secret TEXT); INSERT INTO legacy VALUES ('preserve');")
        .unwrap();
    assert!(matches!(
        Store::open(dir.path()),
        Err(Error::DatabaseFormat)
    ));
    assert_eq!(
        db.query_row("SELECT secret FROM legacy", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "preserve"
    );
    let fresh = tempfile::tempdir().unwrap();
    drop(Store::open(fresh.path()).unwrap());
    let db = rusqlite::Connection::open(fresh.path().join("patchwork-v1.sqlite3")).unwrap();
    db.pragma_update(None, "user_version", 999).unwrap();
    assert!(matches!(
        Store::open(fresh.path()),
        Err(Error::DatabaseFormat)
    ));
}

#[test]
fn concurrent_connections_append_contiguous_positions() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"concurrent".parse().unwrap()).unwrap();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let id = &stream.id;
                let path = dir.path();
                scope.spawn(move || {
                    let mut store = Store::open(path).unwrap();
                    for _ in 0..10 {
                        store.append(id, b"x", "text/plain").unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let page = store.read(&stream.id, Position::ZERO, 100, 100).unwrap();
    assert_eq!(page.tail.get(), 40);
    assert_eq!(
        page.records
            .iter()
            .map(|r| r.position.get())
            .collect::<Vec<_>>(),
        (0..40).collect::<Vec<_>>()
    );
}

#[test]
fn database_enforces_immutability_and_transaction_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"immutable".parse().unwrap()).unwrap();
    store.append(&stream.id, b"original", "text/plain").unwrap();
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    assert!(db.execute("UPDATE records SET payload=x'00'", []).is_err());
    // Fail the second statement of append, proving the inserted row rolls back too.
    db.execute_batch("CREATE TRIGGER fail_tail BEFORE UPDATE ON streams BEGIN SELECT RAISE(ABORT, 'test fault'); END;").unwrap();
    assert!(
        store
            .append(&stream.id, b"must roll back", "text/plain")
            .is_err()
    );
    let page = store.read(&stream.id, Position::ZERO, 100, 100).unwrap();
    assert_eq!(page.tail.get(), 1);
    assert_eq!(page.records.len(), 1);
    db.execute_batch("DROP TRIGGER fail_tail").unwrap();
    assert_eq!(
        store
            .append(&stream.id, b"next", "text/plain")
            .unwrap()
            .get(),
        1
    );
}
