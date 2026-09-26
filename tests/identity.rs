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

#[test]
fn administration_cas_and_old_issuance_ceilings_fence_policy_expansion() {
    let (dir, mut store, admin_key) = fixture();
    let admin = login(&mut store, &admin_key);
    let path = dir.path().join("second-key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let key = ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(path).unwrap()).unwrap();
    let mut input = patchwork::store::PrincipalInput {
        ssh_public_key: key.public_key().to_openssh().unwrap(),
        enabled: true,
        can_mint: false,
        grants: vec![Grant {
            actions: vec![Action::RecordRead],
            selector: Selector::Prefix("events/".into()),
        }],
    };
    let principal = store.put_principal(&admin, None, None, &input).unwrap();
    let user = login(&mut store, &key);
    let name = "events/admin-test".parse().unwrap();
    let stream = store.create_stream(&name).unwrap();
    input.grants[0].actions.push(Action::RecordAppend);
    store
        .put_principal(
            &admin,
            Some(&principal.id),
            Some(patchwork::model::Revision::ZERO),
            &input,
        )
        .unwrap();
    assert!(matches!(
        store.put_principal(
            &admin,
            Some(&principal.id),
            Some(patchwork::model::Revision::ZERO),
            &input
        ),
        Err(Error::RevisionMismatch)
    ));
    assert!(
        store
            .authorized(&user, Action::RecordAppend, Some(&stream.id), &name, |s| s
                .append(&stream.id, b"no", "text/plain"))
            .is_err()
    );
    let fresh = login(&mut store, &key);
    store
        .authorized(&fresh, Action::RecordAppend, Some(&stream.id), &name, |s| {
            s.append(&stream.id, b"yes", "text/plain")
        })
        .unwrap();
    assert!(store.principals(&user, "", 100).is_err());
    input.enabled = false;
    store
        .put_principal(
            &admin,
            Some(&principal.id),
            Some(patchwork::model::Revision::new(1).unwrap()),
            &input,
        )
        .unwrap();
    assert!(
        store
            .authorized(&fresh, Action::RecordRead, Some(&stream.id), &name, |s| s
                .read(&stream.id, Position::ZERO, 1, 1))
            .is_err()
    );
    let (revision, _) = store.policy(&admin).unwrap();
    store
        .replace_policy(
            &admin,
            revision,
            &patchwork::store::AuthPolicy {
                max_api_lifetime_seconds: 60,
            },
        )
        .unwrap();
    assert!(store.mint(&admin, &[], 61).is_err());
    assert!(
        store
            .credentials(&admin, "", 100)
            .unwrap()
            .iter()
            .all(|v| v.get("token").is_none())
    );
}

#[test]
fn pipeline_receipts_survive_reauthentication_reopen_and_configuration_changes() {
    use patchwork::{
        model::{Revision, StreamConfig},
        pipeline::{Filter, Validator},
    };
    let (dir, mut store, key) = fixture();
    let session = login(&mut store, &key);
    let stream = store
        .create_stream(&"events/pipeline".parse().unwrap())
        .unwrap();
    let config = StreamConfig {
        filters: vec![
            Filter::UppercaseAscii,
            Filter::DropIfContains {
                data_base64: STANDARD.encode(b"DROP"),
            },
        ],
        validators: vec![Validator::Utf8],
        ..Default::default()
    };
    store
        .replace_config(&stream.id, Revision::ZERO, &config)
        .unwrap();
    let first = store
        .append_authorized(
            &session,
            &stream.id,
            b"hello",
            "text/plain",
            Some("request-1"),
        )
        .unwrap();
    assert_eq!(first.position.as_deref(), Some("0"));
    assert_eq!(
        store
            .read(&stream.id, Position::ZERO, 1, 100)
            .unwrap()
            .records[0]
            .payload,
        b"HELLO"
    );
    let dropped = store
        .append_authorized(&session, &stream.id, b"drop", "text/plain", Some("drop-1"))
        .unwrap();
    assert_eq!(dropped.outcome, "dropped");
    let changed = StreamConfig {
        filters: vec![Filter::RejectIfContains {
            data_base64: String::new(),
        }],
        ..Default::default()
    };
    store
        .replace_config(&stream.id, Revision::new(1).unwrap(), &changed)
        .unwrap();
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    let fresh = login(&mut store, &key);
    let retry = store
        .append_authorized(
            &fresh,
            &stream.id,
            b"hello",
            "text/plain",
            Some("request-1"),
        )
        .unwrap();
    assert_eq!(retry.deduplicated, Some(true));
    assert_eq!(retry.position, first.position);
    assert_eq!(
        store
            .append_authorized(&fresh, &stream.id, b"drop", "text/plain", Some("drop-1"))
            .unwrap()
            .deduplicated,
        Some(true)
    );
    assert!(matches!(
        store.append_authorized(
            &fresh,
            &stream.id,
            b"different",
            "text/plain",
            Some("request-1")
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.append_authorized(&fresh, &stream.id, b"new", "text/plain", None),
        Err(Error::Rejected)
    ));
    assert_eq!(store.stream(&stream.id).unwrap().tail.get(), 1);
    store
        .revoke(
            &fresh,
            store.whoami(&session).unwrap()["credential_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert!(
        store
            .append_authorized(
                &session,
                &stream.id,
                b"hello",
                "text/plain",
                Some("request-1")
            )
            .is_err()
    );
}

#[test]
fn bounded_retention_preserves_receipts_and_updates_partial_segment_summaries() {
    use patchwork::model::{Retention, StreamConfig};
    let (dir, mut store, key) = fixture();
    let session = login(&mut store, &key);
    let config = StreamConfig {
        retention: Retention::Bounded {
            max_age_seconds: None,
            max_bytes: Some(4),
        },
        ..Default::default()
    };
    let stream = store
        .create_stream_with(
            &"events/trim".parse().unwrap(),
            &config,
            &Default::default(),
        )
        .unwrap();
    store
        .append_authorized(&session, &stream.id, b"aaa", "text/plain", Some("trimmed"))
        .unwrap();
    store
        .append_authorized(&session, &stream.id, b"bbb", "text/plain", None)
        .unwrap();
    assert_eq!(store.stream(&stream.id).unwrap().head.get(), 1);
    assert!(matches!(
        store.read(&stream.id, Position::ZERO, 10, 100),
        Err(Error::HistoryLost)
    ));
    let segment = store
        .segments(&stream.id, Position::ZERO, 10)
        .unwrap()
        .remove(0);
    assert_eq!(
        (
            segment.start.get(),
            segment.end.get(),
            segment.record_count,
            segment.payload_bytes
        ),
        (1, 2, 1, 3)
    );
    let receipt = store
        .append_authorized(&session, &stream.id, b"aaa", "text/plain", Some("trimmed"))
        .unwrap();
    assert_eq!(receipt.position.as_deref(), Some("0"));
    assert_eq!(receipt.deduplicated, Some(true));
    drop(store);
    let mut store = Store::open(dir.path()).unwrap();
    assert_eq!(
        store
            .read(&stream.id, Position::new(1).unwrap(), 1, 100)
            .unwrap()
            .records[0]
            .payload,
        b"bbb"
    );
}
