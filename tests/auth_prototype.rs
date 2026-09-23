//! Executable G-AUTH starting spike. Never linked into the production binaries.
use biscuit_auth::{
    AuthorizerBuilder, Biscuit, BlockBuilder, KeyPair,
    builder::{fact, string},
};

fn issue(root: &KeyPair) -> Biscuit {
    Biscuit::builder()
        .fact(fact("principal", &[string("alice")]))
        .unwrap()
        .fact(fact("credential", &[string("credential-1")]))
        .unwrap()
        .build(root)
        .unwrap()
}

fn authorize(token: &Biscuit, action: &str, resource: &str, valid: bool) -> bool {
    let mut builder = AuthorizerBuilder::new()
        // Semantic tests must not depend on a 1 ms scheduler window on CI.
        // Production parsing/execution budgets remain a separate gate.
        .set_limits(biscuit_auth::AuthorizerLimits {
            max_time: std::time::Duration::from_secs(1),
            ..Default::default()
        })
        .code(include_str!("../prototypes/authorization.datalog"))
        .unwrap()
        .fact(fact("operation", &[string(action)]))
        .unwrap()
        .fact(fact("resource", &[string("stream"), string(resource)]))
        .unwrap();
    if valid {
        builder = builder
            .fact(fact("credential_valid", &[string("credential-1")]))
            .unwrap();
    }
    // Current server policy AND the frozen issuance ceiling must match the request.
    for (action, resource) in [
        ("record.append", "s1"),
        ("record.read", "s1"),
        ("record.append", "s2"),
    ] {
        builder = builder
            .fact(fact(
                "current_right",
                &[
                    string("alice"),
                    string(action),
                    string("stream"),
                    string(resource),
                ],
            ))
            .unwrap()
            .fact(fact(
                "issued_right",
                &[
                    string("credential-1"),
                    string(action),
                    string("stream"),
                    string(resource),
                ],
            ))
            .unwrap();
    }
    match builder.build(token).unwrap().authorize() {
        Ok(_) => true,
        Err(biscuit_auth::error::Token::FailedLogic(
            biscuit_auth::error::Logic::Unauthorized { .. }
            | biscuit_auth::error::Logic::NoMatchingPolicy { .. },
        )) => false,
        Err(error) => panic!("unexpected prototype failure (not a policy denial): {error}"),
    }
}

#[test]
fn issuance_signature_verification_and_default_deny() {
    let root = KeyPair::new();
    let bytes = issue(&root).to_vec().unwrap();
    let verified = Biscuit::from(&bytes, root.public()).unwrap();
    assert!(authorize(&verified, "record.append", "s1", true));
    assert!(!authorize(&verified, "stream.delete", "s1", true));
    assert!(!authorize(&verified, "record.read", "s2", true));
    assert!(!authorize(&verified, "record.append", "s1", false));
    assert!(Biscuit::from(&bytes, KeyPair::new().public()).is_err());
    let mut tampered = bytes;
    tampered[10] ^= 1;
    assert!(Biscuit::from(&tampered, root.public()).is_err());
}

#[test]
fn offline_attenuation_restricts_action_and_resource() {
    let root = KeyPair::new();
    let parent_bytes = issue(&root).to_vec().unwrap();
    // Holder has only the serialized token and public key; no issuer call/private key.
    let holder = Biscuit::from(&parent_bytes, root.public()).unwrap();
    let child = holder
        .append(
            BlockBuilder::new()
                .code("check if operation(\"record.append\"), resource(\"stream\", \"s1\");")
                .unwrap(),
        )
        .unwrap();
    let child = Biscuit::from(child.to_vec().unwrap(), root.public()).unwrap();
    assert!(authorize(&holder, "record.read", "s1", true));
    assert!(authorize(&holder, "record.append", "s2", true));
    assert!(authorize(&child, "record.append", "s1", true));
    assert!(!authorize(&child, "record.read", "s1", true));
    assert!(!authorize(&child, "record.append", "s2", true));
}

#[test]
fn attenuation_facts_cannot_grant_privilege_or_satisfy_parent_checks() {
    let root = KeyPair::new();
    let parent = issue(&root);
    let forged = BlockBuilder::new()
        .code(
            r#"
        principal("admin"); credential("admin-credential");
        credential_valid("credential-1"); credential_valid("admin-credential");
        operation("record.append"); resource("stream", "s1");
        current_right("alice", "stream.delete", "stream", "s1");
        issued_right("credential-1", "stream.delete", "stream", "s1");
        current_right("admin", "stream.delete", "stream", "s1");
        issued_right("admin-credential", "stream.delete", "stream", "s1");
    "#,
        )
        .unwrap();
    let attack = parent.append(forged.clone()).unwrap();
    assert!(!authorize(&attack, "stream.delete", "s1", true));
    assert!(!authorize(&attack, "record.append", "s1", false));
    let restricted = parent
        .append(
            BlockBuilder::new()
                .code("check if operation(\"record.append\"), resource(\"stream\", \"s1\");")
                .unwrap(),
        )
        .unwrap();
    let attack = restricted.append(forged).unwrap();
    let verified = Biscuit::from(attack.to_vec().unwrap(), root.public()).unwrap();
    assert!(authorize(&verified, "record.append", "s1", true));
    assert!(!authorize(&verified, "record.read", "s1", true));
    assert!(!authorize(&verified, "record.append", "s2", true));
}
