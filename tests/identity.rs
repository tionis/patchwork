use base64::{Engine, engine::general_purpose::STANDARD};
use patchwork::{
    Error,
    auth::{Action, Grant, Selector, ssh},
    model::Position,
    store::Store,
};
use std::process::Command;
fn fixture() -> (tempfile::TempDir, Store, ssh_key::PrivateKey) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let private =
        ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(&path).unwrap()).unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    store
        .bootstrap(
            &private.public_key().to_openssh().unwrap(),
            "http://127.0.0.1:8080",
        )
        .unwrap();
    (dir, store, private)
}
fn login(store: &mut Store, key: &ssh_key::PrivateKey) -> String {
    let challenge = store
        .challenge(&key.public_key().to_openssh().unwrap())
        .unwrap();
    let payload = STANDARD.decode(&challenge.payload_base64).unwrap();
    let signature = key
        .sign(ssh::NAMESPACE, ssh_key::HashAlg::Sha512, &payload)
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap();
    let session = store.exchange(&challenge.challenge_id, &signature).unwrap();
    assert!(store.exchange(&challenge.challenge_id, &signature).is_err());
    session.token
}
#[test]
fn authenticated_commands_scoping_revocation_and_restart() {
    let (dir, mut store, key) = fixture();
    assert!(matches!(
        store.bootstrap(
            &key.public_key().to_openssh().unwrap(),
            "http://127.0.0.1:8080"
        ),
        Err(Error::Conflict)
    ));
    let session = login(&mut store, &key);
    let name = "events/test".parse().unwrap();
    let stream = store
        .authorized(&session, Action::StreamCreate, None, &name, |s| {
            s.create_stream(&name)
        })
        .unwrap();
    let scope = vec![Grant {
        actions: vec![Action::RecordRead],
        selector: Selector::Prefix("events/".into()),
    }];
    let reader = store.mint(&session, &scope, 600).unwrap();
    assert!(store.mint(&reader.token, &scope, 600).is_err());
    assert!(
        store
            .authorized(
                &reader.token,
                Action::RecordAppend,
                Some(&stream.id),
                &name,
                |s| s.append(&stream.id, b"denied", "text/plain")
            )
            .is_err()
    );
    store
        .authorized(
            &session,
            Action::RecordAppend,
            Some(&stream.id),
            &name,
            |s| s.append(&stream.id, b"hello", "text/plain"),
        )
        .unwrap();
    let page = store
        .authorized(
            &reader.token,
            Action::RecordRead,
            Some(&stream.id),
            &name,
            |s| s.read(&stream.id, Position::ZERO, 10, 100),
        )
        .unwrap();
    assert_eq!(page.records[0].payload, b"hello");
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert!(
        store
            .authorized(
                &reader.token,
                Action::RecordRead,
                Some(&stream.id),
                &name,
                |s| s.read(&stream.id, Position::ZERO, 10, 100)
            )
            .is_ok()
    );
    store.revoke(&session, &reader.credential_id).unwrap();
    assert!(
        store
            .authorized(
                &reader.token,
                Action::RecordRead,
                Some(&stream.id),
                &name,
                |s| s.read(&stream.id, Position::ZERO, 10, 100)
            )
            .is_err()
    );
}
#[test]
fn credential_expiry_principal_disable_and_policy_removal_take_effect() {
    let (dir, mut store, key) = fixture();
    let session = login(&mut store, &key);
    let name = "events/test".parse().unwrap();
    let db = rusqlite::Connection::open(dir.path().join("patchwork-v1.sqlite3")).unwrap();
    db.execute("UPDATE principals SET grants='[]'", []).unwrap();
    assert!(
        store
            .authorized(&session, Action::StreamCreate, None, &name, |s| s
                .create_stream(&name))
            .is_err()
    );
    db.execute("UPDATE principals SET enabled=0", []).unwrap();
    assert!(store.mint(&session, &[], 100).is_err());
    db.execute("UPDATE principals SET enabled=1", []).unwrap();
    db.execute("UPDATE credentials SET expires_at=0", [])
        .unwrap();
    assert!(store.mint(&session, &[], 100).is_err());
    assert!(store.lookup_stream(&name).is_err());
}

#[test]
fn failed_challenge_attempts_are_bounded_and_exact_scopes_do_not_follow_names() {
    let (_dir, mut store, key) = fixture();
    let challenge = store
        .challenge(&key.public_key().to_openssh().unwrap())
        .unwrap();
    for _ in 0..5 {
        assert!(
            store
                .exchange(&challenge.challenge_id, "malformed")
                .is_err()
        );
    }
    let signature = key
        .sign(
            ssh::NAMESPACE,
            ssh_key::HashAlg::Sha512,
            &STANDARD.decode(&challenge.payload_base64).unwrap(),
        )
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap();
    assert!(store.exchange(&challenge.challenge_id, &signature).is_err());
    let session = login(&mut store, &key);
    let name = "events/exact".parse().unwrap();
    let stream = store.create_stream(&name).unwrap();
    let scope = [Grant {
        actions: vec![Action::RecordRead],
        selector: Selector::Stream(stream.id.as_str().into()),
    }];
    let reader = store.mint(&session, &scope, 600).unwrap();
    assert!(
        store
            .authorized(
                &reader.token,
                Action::RecordRead,
                Some(&stream.id),
                &name,
                |s| s.read(&stream.id, Position::ZERO, 1, 1)
            )
            .is_ok()
    );
    store
        .delete_stream(&stream.id, patchwork::model::Revision::ZERO)
        .unwrap();
    let replacement = store.create_stream(&name).unwrap();
    assert!(
        store
            .authorized(
                &reader.token,
                Action::RecordRead,
                Some(&replacement.id),
                &name,
                |s| s.read(&replacement.id, Position::ZERO, 1, 1)
            )
            .is_err()
    );
}
