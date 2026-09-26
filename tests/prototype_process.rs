//! Authenticated real-process prototype: binary I/O, scoped tokens and hard restart.
#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn cli(args: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_patchwork"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().unwrap()
}
fn ok(args: &[&str], input: Option<&[u8]>) -> Output {
    let output = cli(args, input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn start(dir: &str, address: &str, url: &str) -> Server {
    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_patchwork-server"))
            .args(["--data-dir", dir, "--listen", address, "--data-api"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(server.0.try_wait().unwrap().is_none(), "server exited");
        if cli(&["health", "--url", url], None).status.success() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(25));
    }
    server
}
#[test]
fn bootstrap_login_binary_stream_scoped_credentials_and_hard_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();
    let key = dir.path().join("key");
    let public = dir.path().join("key.pub");
    let session = dir.path().join("session");
    let reader = dir.path().join("reader");
    let scope = dir.path().join("scope.json");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap().to_string();
    drop(probe);
    let url = format!("http://{address}");
    ok(
        &[
            "admin",
            "bootstrap",
            "--data-dir",
            path,
            "--ssh-public-key",
            public.to_str().unwrap(),
            "--origin",
            &url,
        ],
        None,
    );
    assert!(
        !cli(
            &[
                "admin",
                "bootstrap",
                "--data-dir",
                path,
                "--ssh-public-key",
                public.to_str().unwrap(),
                "--origin",
                &url
            ],
            None
        )
        .status
        .success()
    );
    let mut server = start(path, &address, &url);
    ok(
        &[
            "login",
            "--url",
            &url,
            "--ssh-key",
            key.to_str().unwrap(),
            "--ssh-public-key",
            public.to_str().unwrap(),
            "--output",
            session.to_str().unwrap(),
        ],
        None,
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&session).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let output = ok(
        &[
            "stream",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "create",
            "events/prototype",
        ],
        None,
    );
    let created: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = created["id"].as_str().unwrap();
    let attenuated = dir.path().join("attenuated");
    ok(
        &[
            "token",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "attenuate",
            "--read-only",
            "--stream",
            id,
            "--output",
            attenuated.to_str().unwrap(),
        ],
        None,
    );
    let bytes = b"\x00\xffbinary\nrecord";
    let output = ok(
        &[
            "append",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            id,
            "--idempotency-key",
            "restart-retry",
        ],
        Some(bytes),
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["position"], "0");
    assert_eq!(
        ok(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .stdout,
        bytes
    );
    std::fs::write(
        &scope,
        json!([{"actions":["record.read"],"selector":{"kind":"prefix","value":"events/"}}])
            .to_string(),
    )
    .unwrap();
    let output = ok(
        &[
            "token",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "mint",
            "--scope-file",
            scope.to_str().unwrap(),
            "--output",
            reader.to_str().unwrap(),
        ],
        None,
    );
    let credential: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("token"));
    assert_eq!(
        ok(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .stdout,
        bytes
    );
    assert!(
        !cli(
            &[
                "append",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                id
            ],
            Some(b"forbidden")
        )
        .status
        .success()
    );
    assert!(
        !cli(
            &[
                "stream",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                "show",
                id
            ],
            None
        )
        .status
        .success()
    );
    server.0.kill().unwrap();
    server.0.wait().unwrap();
    drop(server);
    let mut restarted = start(path, &address, &url);
    let retried: Value = serde_json::from_slice(
        &ok(
            &[
                "append",
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
                id,
                "--idempotency-key",
                "restart-retry",
            ],
            Some(bytes),
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(retried["position"], "0");
    assert_eq!(retried["deduplicated"], true);
    assert_eq!(
        ok(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                attenuated.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .stdout,
        bytes
    );
    assert!(
        !cli(
            &[
                "append",
                "--url",
                &url,
                "--token-file",
                attenuated.to_str().unwrap(),
                id
            ],
            Some(b"denied")
        )
        .status
        .success()
    );
    for command in [["admin", "policy"], ["admin", "creation-rules"]] {
        ok(
            &[
                command[0],
                command[1],
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
            ],
            None,
        );
    }
    ok(
        &[
            "admin",
            "principals",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "list",
        ],
        None,
    );
    ok(
        &[
            "token",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "whoami",
        ],
        None,
    );
    ok(
        &[
            "token",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "list",
        ],
        None,
    );
    ok(
        &[
            "stream",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "list",
        ],
        None,
    );
    for command in ["config", "metadata"] {
        ok(
            &[
                "stream",
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
                command,
                id,
            ],
            None,
        );
    }
    assert_eq!(
        ok(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .stdout,
        bytes
    );
    let page: Value = serde_json::from_slice(
        &ok(
            &[
                "read",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                id,
            ],
            None,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(page["tail"], "1");
    ok(
        &[
            "token",
            "--url",
            &url,
            "--token-file",
            session.to_str().unwrap(),
            "revoke",
            credential["credential_id"].as_str().unwrap(),
        ],
        None,
    );
    assert!(
        !cli(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                reader.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .status
        .success()
    );
    let _follow = Server(
        Command::new(env!("CARGO_BIN_EXE_patchwork"))
            .args([
                "follow",
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
                id,
                "--from",
                "1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        Command::new("kill")
            .args(["-TERM", &restarted.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(7);
    while restarted.0.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "shutdown hung with active follow"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let recovered: Value = serde_json::from_slice(
        &ok(
            &[
                "admin",
                "recover",
                "--data-dir",
                path,
                "--ssh-public-key",
                public.to_str().unwrap(),
            ],
            None,
        )
        .stdout,
    )
    .unwrap();
    assert_eq!(recovered["action"], "administrator_restored");
    let _recovered_server = start(path, &address, &url);
    assert_eq!(
        ok(
            &[
                "get",
                "--url",
                &url,
                "--token-file",
                session.to_str().unwrap(),
                id,
                "0"
            ],
            None
        )
        .stdout,
        bytes
    );
}
