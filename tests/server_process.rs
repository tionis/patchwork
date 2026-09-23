//! Real process/CLI smoke test; graceful restart, NOT a hard-crash test.
#![cfg(unix)]
use patchwork::{model::Position, store::Store};
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn explicit_directory_server_cli_and_graceful_reopen() {
    let dir = tempfile::tempdir().unwrap();
    // Create real storage data, then prove server startup can reopen the same format.
    let mut store = Store::open(dir.path()).unwrap();
    let stream = store
        .create_stream(&"process/smoke".parse().unwrap())
        .unwrap();
    store
        .append(
            &stream.id,
            b"\x00\xffpersistent",
            "application/octet-stream",
        )
        .unwrap();
    drop(store);
    for _ in 0..2 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let mut server = Server(
            Command::new(env!("CARGO_BIN_EXE_patchwork-server"))
                .args([
                    "--data-dir",
                    dir.path().to_str().unwrap(),
                    "--listen",
                    &address.to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "server exited during startup"
            );
            let result = Command::new(env!("CARGO_BIN_EXE_patchwork"))
                .args(["health", "--url", &format!("http://{address}")])
                .output()
                .unwrap();
            if result.status.success() {
                assert_eq!(result.stdout, b"healthy\n");
                break;
            }
            assert!(Instant::now() < deadline, "health startup timeout");
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            Command::new("kill")
                .args(["-TERM", &server.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = server.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "graceful shutdown timeout");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let mut reopened = Store::open(dir.path()).unwrap();
    let records = reopened.read(&stream.id, Position::ZERO, 10, 100).unwrap();
    assert_eq!(records.tail.get(), 1);
    assert_eq!(records.records[0].payload, b"\x00\xffpersistent");
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_patchwork-server"))
            .output()
            .unwrap()
            .status
            .success()
    );
}
