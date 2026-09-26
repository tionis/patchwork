use patchwork::{
    Error,
    model::{Metadata, Position, Retention, Revision, StreamConfig},
    store::{MAX_RECORD_BYTES, Store},
};

#[test]
fn lifecycle_cas_and_recreation_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let name = "events/lifecycle".parse().unwrap();
    assert!(matches!(store.lookup_stream(&name), Err(Error::NotFound)));
    let stream = store.create_stream(&name).unwrap();
    let metadata: Metadata = r#"{"retention":"none","title":"hello"}"#.parse().unwrap();
    let revision = store
        .replace_metadata(&stream.id, Revision::ZERO, &metadata)
        .unwrap();
    assert_eq!(revision.get(), 1);
    assert!(matches!(
        store.replace_metadata(&stream.id, Revision::ZERO, &Metadata::default()),
        Err(Error::RevisionMismatch)
    ));
    assert_eq!(store.config(&stream.id).unwrap().revision, Revision::ZERO);
    let config = StreamConfig {
        max_record_bytes: 3,
        ..Default::default()
    };
    let config_revision = store
        .replace_config(&stream.id, Revision::ZERO, &config)
        .unwrap();
    assert!(matches!(
        store.append(&stream.id, b"four", "text/plain"),
        Err(Error::TooLarge)
    ));
    store.append(&stream.id, b"abc", "text/plain").unwrap();
    assert!(matches!(
        store.delete_stream(&stream.id, Revision::ZERO),
        Err(Error::RevisionMismatch)
    ));
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert_eq!(store.lookup_stream(&name).unwrap().id, stream.id);
    assert_eq!(store.config(&stream.id).unwrap().value, config);
    assert_eq!(store.metadata(&stream.id).unwrap().value, metadata);
    assert_eq!(store.metadata(&stream.id).unwrap().revision, revision);
    store.delete_stream(&stream.id, config_revision).unwrap();
    let replacement = store.create_stream(&name).unwrap();
    assert_ne!(replacement.id, stream.id);
    assert_eq!(replacement.tail, Position::ZERO);
    assert!(matches!(store.stream(&stream.id), Err(Error::NotFound)));
    assert!(matches!(
        store.append(&stream.id, b"old", "text/plain"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.read(&stream.id, Position::ZERO, 1, 1),
        Err(Error::NotFound)
    ));
    assert!(matches!(store.config(&stream.id), Err(Error::NotFound)));
    assert!(matches!(store.metadata(&stream.id), Err(Error::NotFound)));
    assert!(matches!(
        store.replace_config(&stream.id, config_revision, &config),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.replace_metadata(&stream.id, revision, &metadata),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.segments(&stream.id, Position::ZERO, 10),
        Err(Error::NotFound)
    ));
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.lookup_stream(&name).unwrap().id, replacement.id);
    assert!(matches!(store.stream(&stream.id), Err(Error::NotFound)));
}

#[test]
fn competing_config_and_metadata_cas_each_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store.create_stream(&"cas".parse().unwrap()).unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=2)
            .map(|n| {
                let id = &stream.id;
                let barrier = &barrier;
                let path = dir.path();
                scope.spawn(move || {
                    let mut store = Store::open(path).unwrap();
                    barrier.wait();
                    let config = store.replace_config(
                        id,
                        Revision::ZERO,
                        &StreamConfig {
                            max_record_bytes: n,
                            ..Default::default()
                        },
                    );
                    let metadata = store.replace_metadata(
                        id,
                        Revision::ZERO,
                        &format!("{{\"winner\":{n}}}").parse().unwrap(),
                    );
                    (config, metadata)
                })
            })
            .collect();
        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|(c, _)| c.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|(_, m)| m.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|(c, _)| matches!(c, Err(Error::RevisionMismatch)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, m)| matches!(m, Err(Error::RevisionMismatch)))
                .count(),
            1
        );
    });
}

#[test]
fn live_descriptors_reject_retained_operations_and_mode_switches() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let config = StreamConfig {
        retention: Retention::None,
        ..Default::default()
    };
    let stream = store
        .create_stream_with(&"live".parse().unwrap(), &config, &Metadata::default())
        .unwrap();
    assert!(matches!(
        store.append(&stream.id, b"", "text/plain"),
        Err(Error::StreamMode)
    ));
    assert!(matches!(
        store.read(&stream.id, Position::ZERO, 1, 1),
        Err(Error::StreamMode)
    ));
    assert!(matches!(
        store.replace_config(&stream.id, Revision::ZERO, &StreamConfig::default()),
        Err(Error::StreamMode)
    ));
    let retained = store.create_stream(&"retained".parse().unwrap()).unwrap();
    assert!(matches!(
        store.replace_config(&retained.id, Revision::ZERO, &config),
        Err(Error::StreamMode)
    ));
    assert_eq!(store.stream(&stream.id).unwrap().tail, Position::ZERO);
    assert!(
        serde_json::from_str::<StreamConfig>(
            r#"{"retention":{"mode":"none"},"max_record_bytes":100,"attachments":["kv"]}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<StreamConfig>(
            r#"{"retention":{"mode":"none"},"max_record_bytes":100,"recovery_requirements":[{}]}"#
        )
        .is_err()
    );
    for size in [0, MAX_RECORD_BYTES + 1] {
        assert!(
            store
                .create_stream_with(
                    &"invalid".parse().unwrap(),
                    &StreamConfig {
                        max_record_bytes: size,
                        ..Default::default()
                    },
                    &Metadata::default()
                )
                .is_err()
        );
    }
    assert!(matches!(
        store.lookup_stream(&"invalid".parse().unwrap()),
        Err(Error::NotFound)
    ));
    for input in ["null", "[]", "1", "{", "\"hello\""] {
        assert!(input.parse::<Metadata>().is_err());
    }
    let exact = format!("{{\"x\":\"{}\"}}", "x".repeat(65536 - 8));
    assert!(exact.parse::<Metadata>().is_ok());
    assert!(matches!(
        (exact + " ").parse::<Metadata>(),
        Err(Error::TooLarge)
    ));
}

#[test]
fn byte_segments_match_rows_across_streams_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let a = store.create_stream(&"a".parse().unwrap()).unwrap();
    let b = store.create_stream(&"b".parse().unwrap()).unwrap();
    for _ in 0..9 {
        store
            .append(
                &a.id,
                &vec![7; MAX_RECORD_BYTES],
                "application/octet-stream",
            )
            .unwrap();
        store.append(&b.id, b"", "text/plain").unwrap();
    }
    let before = store.segments(&a.id, Position::ZERO, 10).unwrap();
    assert_eq!(before.len(), 2);
    assert_eq!(
        (
            before[0].start.get(),
            before[0].end.get(),
            before[0].record_count,
            before[0].payload_bytes,
            before[0].sealed
        ),
        (0, 8, 8, 8 * MAX_RECORD_BYTES as i64, true)
    );
    assert_eq!(
        (before[1].start.get(), before[1].end.get(), before[1].sealed),
        (8, 9, false)
    );
    let b_segments = store.segments(&b.id, Position::ZERO, 10).unwrap();
    assert_eq!(
        (b_segments[0].record_count, b_segments[0].payload_bytes),
        (9, 0)
    );
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert_eq!(store.segments(&a.id, Position::ZERO, 10).unwrap(), before);
    let page = store
        .read(&a.id, Position::ZERO, 100, 16 * MAX_RECORD_BYTES)
        .unwrap();
    for segment in &before {
        let records: Vec<_> = page
            .records
            .iter()
            .filter(|r| r.position >= segment.start && r.position < segment.end)
            .collect();
        assert_eq!(records.len() as i64, segment.record_count);
        assert_eq!(
            records.iter().map(|r| r.payload.len() as i64).sum::<i64>(),
            segment.payload_bytes
        );
        assert_eq!(
            records.iter().map(|r| r.accepted_at_ms).min().unwrap(),
            segment.min_accepted_at_ms
        );
        assert_eq!(
            records.iter().map(|r| r.accepted_at_ms).max().unwrap(),
            segment.max_accepted_at_ms
        );
    }
    assert_eq!(
        store.segments(&a.id, Position::new(8).unwrap(), 1).unwrap(),
        before[1..]
    );
}
