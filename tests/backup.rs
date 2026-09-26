mod common;
use patchwork::{
    Error,
    auth::{Action, Grant, Selector},
    model::{Position, Revision},
    store::{
        Store,
        hooks::{Config, Input, Transform},
        kv::Event,
    },
};
#[test]
fn online_backup_restore_preserves_kv_receipts_policy_revocation_and_secrets() {
    let (dir, mut store, key) = common::fixture();
    let token = common::login(&mut store, &key);
    let st = store.create_stream(&"backup/kv".parse().unwrap()).unwrap();
    let a = store.enable_kv(&token, &st.id, Revision::ZERO).unwrap();
    let event = Event::put(
        "key".into(),
        b"\0\xffvalue",
        "application/octet-stream".into(),
        None,
    )
    .unwrap();
    store
        .kv_mutate(&token, &st.id, &a.id, &event, Some("retry-restored"))
        .unwrap();
    let reader = store
        .mint(
            &token,
            &[Grant {
                actions: vec![Action::KvRead],
                selector: Selector::Stream(st.id.as_str().into()),
            }],
            600,
        )
        .unwrap();
    store.revoke(&token, &reader.credential_id).unwrap();
    let hooks = store
        .create_stream(&"backup/hooks".parse().unwrap())
        .unwrap();
    let hook = store
        .put_hook(
            &token,
            None,
            None,
            &Input {
                config: Config {
                    stream_id: hooks.id.as_str().into(),
                    enabled: true,
                    git_ref: None,
                    transform: Transform::Raw,
                    success_status: 200,
                },
                secret: Some("restore-private-secret-123".into()),
            },
        )
        .unwrap();
    let backup = dir.path().join("backup");
    let manifest = store.backup(&backup).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(backup.join("database.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let restored = dir.path().join("restored");
    Store::restore(&backup, &restored, &manifest.instance_id, &manifest.origin).unwrap();
    let mut recovered = Store::open(&restored).unwrap();
    assert_eq!(
        recovered
            .kv_get(&token, &st.id, &a.id, "key")
            .unwrap()
            .bytes,
        b"\0\xffvalue"
    );
    assert_eq!(
        recovered
            .kv_mutate(&token, &st.id, &a.id, &event, Some("retry-restored"))
            .unwrap()
            .deduplicated,
        Some(true)
    );
    assert!(
        recovered
            .kv_get(&reader.token, &st.id, &a.id, "key")
            .is_err()
    );
    assert_eq!(recovered.hook(&token, &hook.id).unwrap().revision, "0");
    assert_eq!(recovered.policy(&token).unwrap().0, Revision::ZERO);
    assert_eq!(
        recovered.stream(&st.id).unwrap().tail,
        Position::new(1).unwrap()
    );
    let db = rusqlite::Connection::open(restored.join("patchwork-v1.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT secret FROM hooks WHERE id=?1", [hook.id], |r| {
            r.get::<_, String>(0)
        })
        .unwrap(),
        "restore-private-secret-123"
    );
    assert!(Store::restore(&backup, &restored, &manifest.instance_id, &manifest.origin).is_err());
    assert!(store.backup(&backup).is_err());
    assert!(
        Store::restore(
            &backup,
            &dir.path().join("wrong"),
            "wrong-instance",
            &manifest.origin
        )
        .is_err()
    );
    assert!(!dir.path().join("wrong").exists());
}
#[test]
fn corruption_and_partial_restores_never_become_runnable() {
    let (dir, store, _key) = common::fixture();
    let backup = dir.path().join("backup");
    let manifest = store.backup(&backup).unwrap();
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(backup.join("database.sqlite3"))
        .unwrap()
        .write_all(b"corrupt")
        .unwrap();
    let dest = dir.path().join("failed");
    assert!(Store::restore(&backup, &dest, &manifest.instance_id, &manifest.origin).is_err());
    assert!(dest.join(".restore-incomplete").exists());
    assert!(matches!(
        Store::open(&dest),
        Err(Error::Invalid("incomplete restore"))
    ));
    assert!(!dest.join("patchwork-v1.sqlite3").exists());
}
#[test]
fn backup_is_consistent_while_an_independent_writer_advances() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let (dir, mut store, _) = common::fixture();
    let st = store
        .create_stream(&"backup/concurrent".parse().unwrap())
        .unwrap();
    for _ in 0..64 {
        store
            .append(&st.id, &vec![7; 65536], "application/octet-stream")
            .unwrap();
    }
    let mut writer = Store::open(dir.path()).unwrap();
    let sid = st.id.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let (started, ready) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut count = 0;
        while !signal.load(Ordering::Acquire) {
            writer.append(&sid, b"online", "text/plain").unwrap();
            count += 1;
            if count == 1 {
                started.send(()).unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        count
    });
    ready.recv().unwrap();
    let backup = dir.path().join("snapshot");
    let manifest = store.backup(&backup).unwrap();
    stop.store(true, Ordering::Release);
    assert!(thread.join().unwrap() > 0);
    let restored = dir.path().join("restored");
    Store::restore(&backup, &restored, &manifest.instance_id, &manifest.origin).unwrap();
    let mut recovered = Store::open(&restored).unwrap();
    let snapshot = recovered.stream(&st.id).unwrap();
    assert!(snapshot.tail.get() >= 65);
    assert!(snapshot.tail <= store.stream(&st.id).unwrap().tail);
    let page = recovered
        .read(&st.id, Position::new(64).unwrap(), 1000, 65536)
        .unwrap();
    assert_eq!(page.records.len() as i64, snapshot.tail.get() - 64);
    assert!(page.records.iter().all(|r| r.payload == b"online"));
}
