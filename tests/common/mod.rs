use base64::{Engine, engine::general_purpose::STANDARD};
use patchwork::{auth::ssh, store::Store};
use std::process::Command;
pub fn fixture() -> (tempfile::TempDir, Store, ssh_key::PrivateKey) {
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
pub fn login(store: &mut Store, key: &ssh_key::PrivateKey) -> String {
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
