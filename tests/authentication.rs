use biscuit_auth::{Biscuit, BlockBuilder, KeyPair};
use patchwork::auth::{
    ssh,
    token::{self, VerifiedToken},
};
use std::{
    process::Command,
    time::{Duration, SystemTime},
};

#[test]
fn bounded_verification_rejects_forgery_and_checks_attenuation() {
    let root = KeyPair::new();
    let encoded = token::issue(&root, "alice", "credential", "instance").unwrap();
    let now = SystemTime::now();
    let verified = VerifiedToken::parse(&encoded, root.public()).unwrap();
    assert_eq!(verified.principal, "alice");
    assert!(verified.is_unattenuated());
    assert!(
        verified
            .check("record.read", "stream", "s1", "events/a", "instance", now)
            .is_ok()
    );
    assert!(
        verified
            .check("record.read", "stream", "s1", "events/a", "wrong", now)
            .is_err()
    );
    assert!(VerifiedToken::parse(&encoded, KeyPair::new().public()).is_err());
    let parent = Biscuit::from_base64(encoded, root.public()).unwrap();
    let child = parent
        .append(
            BlockBuilder::new()
                .code("check if operation(\"record.read\"), resource(\"stream\", \"s1\");")
                .unwrap(),
        )
        .unwrap();
    let attack = child.append(BlockBuilder::new().code(
        "principal(\"admin\"); credential(\"admin\"); issued_instance(\"wrong\"); operation(\"record.read\"); resource(\"stream\",\"s1\");"
    ).unwrap()).unwrap();
    let verified = VerifiedToken::parse(&attack.to_base64().unwrap(), root.public()).unwrap();
    assert_eq!(verified.principal, "alice");
    assert!(!verified.is_unattenuated());
    assert!(
        verified
            .check("record.append", "stream", "s1", "events/a", "instance", now)
            .is_err()
    );
    assert!(
        verified
            .check("record.read", "stream", "s2", "events/a", "instance", now)
            .is_err()
    );
    assert!(
        verified
            .check("record.read", "stream", "s1", "events/a", "instance", now)
            .is_ok()
    );
    let expired = parent
        .append(
            BlockBuilder::new()
                .code("check if time($t), $t < 2000-01-01T00:00:00Z;")
                .unwrap(),
        )
        .unwrap();
    let verified = VerifiedToken::parse(&expired.to_base64().unwrap(), root.public()).unwrap();
    assert!(
        verified
            .check("record.read", "stream", "s1", "events/a", "instance", now)
            .is_err()
    );
    let mut oversized = parent;
    for _ in 0..token::MAX_BLOCKS {
        oversized = oversized.append(BlockBuilder::new()).unwrap();
    }
    assert!(VerifiedToken::parse(&oversized.to_base64().unwrap(), root.public()).is_err());
    assert!(VerifiedToken::parse(&"A".repeat(token::MAX_TOKEN_BYTES + 1), root.public()).is_err());
    for size in 0..256 {
        assert!(VerifiedToken::parse(&"x".repeat(size), root.public()).is_err());
    }
    assert!(now.duration_since(SystemTime::UNIX_EPOCH).unwrap() > Duration::ZERO);
}

#[test]
fn openssh_signatures_interoperate_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .unwrap()
            .success()
    );
    let public_text = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    let public = ssh::public_key(&public_text).unwrap();
    let payload = b"patchwork instance/origin/key/nonce/expiry fixture";
    let message = dir.path().join("challenge");
    std::fs::write(&message, payload).unwrap();
    assert!(
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&key_path)
            .args(["-n", ssh::NAMESPACE])
            .arg(&message)
            .output()
            .unwrap()
            .status
            .success()
    );
    let signature = std::fs::read_to_string(message.with_extension("sig")).unwrap();
    ssh::verify(&public, payload, &signature).unwrap();
    assert!(ssh::verify(&public, b"other origin", &signature).is_err());
    let private =
        ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(&key_path).unwrap()).unwrap();
    let signed = private
        .sign(ssh::NAMESPACE, ssh_key::HashAlg::Sha512, payload)
        .unwrap();
    std::fs::write(
        message.with_extension("sig"),
        signed.to_pem(ssh_key::LineEnding::LF).unwrap(),
    )
    .unwrap();
    let allowed = dir.path().join("allowed");
    std::fs::write(&allowed, format!("alice {public_text}")).unwrap();
    let output = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "alice", "-n", ssh::NAMESPACE, "-s"])
        .arg(message.with_extension("sig"))
        .stdin(std::fs::File::open(&message).unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let wrong = private
        .sign("other-namespace", ssh_key::HashAlg::Sha512, payload)
        .unwrap()
        .to_pem(ssh_key::LineEnding::LF)
        .unwrap();
    assert!(ssh::verify(&public, payload, &wrong).is_err());
}

#[cfg(unix)]
#[test]
fn agent_backed_public_key_can_sign_login_challenges() {
    struct Agent(std::process::Child);
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key");
    let socket = dir.path().join("agent.sock");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let _agent = Agent(
        Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &socket)
            .output()
            .unwrap()
            .status
            .success()
    );
    let message = dir.path().join("message");
    let payload = b"agent-backed challenge bytes";
    std::fs::write(&message, payload).unwrap();
    assert!(
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(key.with_extension("pub"))
            .args(["-n", ssh::NAMESPACE])
            .arg(&message)
            .env("SSH_AUTH_SOCK", &socket)
            .output()
            .unwrap()
            .status
            .success()
    );
    let public =
        ssh::public_key(&std::fs::read_to_string(key.with_extension("pub")).unwrap()).unwrap();
    ssh::verify(
        &public,
        payload,
        &std::fs::read_to_string(message.with_extension("sig")).unwrap(),
    )
    .unwrap();
}
