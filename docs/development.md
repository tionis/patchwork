# Rust development

Design entrypoint: [unified objects, directories and streams](unified-design.md). Its object APIs are planned; the runnable commands below still exercise the health-only bootstrap.

Run from the repository root. Install rustup and a native C toolchain (Linux: compiler, linker, standard C headers); bundled SQLite compiles C. `rust-toolchain.toml` pins Rust 1.98.1, rustfmt and clippy. Dependency resolution is recorded in `Cargo.lock`; include that file when committing this bootstrap. No Git commit or staging is performed automatically.

```bash
cargo build --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Validate the wiki from the repository root with `vulcan --vault docs --output json doctor --fail-on-issues`. It checks links, parsing and index consistency, not roadmap semantics or runtime behavior. After external edits, `vulcan --vault docs index scan` refreshes the index; `docs/AGENTS.md` and `docs/.agents/skills/` document Vulcan workflows.

Format changes with `cargo fmt --all`. GitHub Actions runs the same verification. First build needs crates.io access; subsequent native builds can use `--offline` once dependencies are cached. This is a single package, not a multi-crate workspace.

Start with a fresh, private directory (keep the printed path to reopen it):

```bash
patchwork_data_dir=$(mktemp -d /tmp/patchwork-dev.XXXXXX)
printf '%s\n' "$patchwork_data_dir"
cargo run --locked --bin patchwork-server -- \
  --data-dir "$patchwork_data_dir" --listen 127.0.0.1:8080 --log-filter info
```

In another terminal:

```bash
cargo run --locked --bin patchwork -- \
  health --url http://127.0.0.1:8080
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Use Ctrl-C or SIGTERM for graceful shutdown; repeat the server command with the same directory to reopen. `--data-dir` is required, `--listen` defaults to loopback, and configuration errors exit nonzero. JSON tracing goes to stderr without payloads/credentials. Health CLI prints `healthy` and exits zero only if both endpoints return 200; transport errors and non-200 statuses exit nonzero. It accepts only an HTTP origin, no embedded credentials, path/query/fragment or redirects. TLS client support is deferred with authenticated CLI work; this command targets the local bootstrap server.

The only routes are `GET /healthz` and `GET /readyz` (Axum also handles HEAD). No stream, login, UI, or admin data API is exposed. Unknown routes return 404. Readiness is startup readiness, not a continuous disk-pressure or writeability check. On initialization/migration error the process exits without a listener; a live router defaults to 503 readiness until explicitly activated and is marked unready on shutdown.

Exercise the real internal storage and the independent authorization spike:

```bash
cargo test --locked --test storage
cargo test --locked --test server_process
cargo test --locked --test auth_prototype
```

Each test uses temporary directories. The process test launches both binaries, checks health, sends SIGTERM, restarts, and verifies previously stored bytes. It runs on Unix. This is **not** hard-kill or power-loss validation. Storage tests open actual file-backed databases, including WAL/FULL settings, byte/position persistence, concurrency, rollback, constraints, and foreign-format refusal.

`Store` is synchronous and internal. Do not call its writes from HTTP handlers yet: the next service boundary needs bounded admission, authorization, pipeline evaluation and commit-time revision checks. Infinite retention is the only implemented mode. Appends take at most 1 MiB; reads require 1–1000 records and 1 byte–16 MiB payload budget. One record may exceed the requested read byte budget so pagination progresses. Arbitrary binary bytes and empty records are valid.

Use a private data directory and filesystem permissions appropriate for its contents. Startup does not change existing directory permissions. Never copy only an active SQLite main file as a backup. Backup/restore, filesystem durability certification, migrations beyond new schema version 1, and deployments are future work. See [roadmap](roadmap.md), [status](implementation-status.md), and [dependency/prototype findings](dependency-decisions.md).
