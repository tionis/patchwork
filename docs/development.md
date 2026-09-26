# Rust development

## Authenticated loopback prototype

The initial prototype is runnable. From the repository root, run `./scripts/prototype-demo.sh`. It builds the binaries, creates an isolated temporary data directory and Ed25519 key, starts a loopback server, logs in with SSHSIG, creates a stream, round-trips binary bytes and verifies a read-only credential cannot append. It stops its server and prints the retained data/log directory. Requires Rust, a C toolchain, OpenSSH tools and Python 3. No credentials are printed.

For an interactive instance, build with `cargo build --locked --bins`, use a fresh private data directory, and bootstrap against its intended origin:

```bash
./target/debug/patchwork admin bootstrap \
  --data-dir /tmp/patchwork-local \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --origin http://127.0.0.1:8080
./target/debug/patchwork-server --data-dir /tmp/patchwork-local \
  --listen 127.0.0.1:8080 --data-api
```

In another terminal, authenticate and create a stream:

```bash
./target/debug/patchwork login --url http://127.0.0.1:8080 \
  --ssh-key "$HOME/.ssh/id_ed25519" \
  --ssh-public-key "$HOME/.ssh/id_ed25519.pub" \
  --output /tmp/patchwork-local/session
./target/debug/patchwork stream --token-file /tmp/patchwork-local/session create events/demo
```

Use the returned `str_…` ID with `append ID` (binary stdin), `read ID --from 0` (JSON/base64), or `get ID 0` (exact binary stdout); all accept `--token-file` and `--url`. `stream resolve NAME`, `stream show ID`, and `stream delete ID --config-revision N` are also available. Run each command with `--help` for argument placement. Session/output credential files are created exclusively with mode 0600; use a new output path when logging in again. Agent-backed login uses the public-key path as `--ssh-key` with the matching key loaded in `ssh-agent`.

SSH sessions expire after 15 minutes. `token mint --scope-file FILE --output FILE --lifetime-seconds 3600` requires a fresh unattenuated SSH session. Scope files contain arrays such as `[{"actions":["record.read"],"selector":{"kind":"prefix","value":"events/"}}]`; exact selectors use `{"kind":"stream","value":"str_…"}`. A nonempty prefix must end with `/`; the empty prefix explicitly covers all canonical names. API tokens cannot mint credentials. `token revoke ID` invalidates the credential and its offline descendants. Token secrets live in files, never command arguments.

The API contract is repository-root `openapi.json` (OpenAPI 3.1). HTTP includes authenticated stream lookup/create/inspect/delete, config/metadata CAS, append, JSON replay, raw records, SSH challenge/exchange and credential mint/revoke. Config and metadata GET return ETags; PUT and delete require If-Match. Unsupported idempotency keys and object links fail explicitly. No pipeline can be configured yet; retained writes preserve the submitted bytes. The 32-operation admission bound, 1 MiB request/record cap, 64 KiB metadata bound, 32 KiB encoded-token cap, eight token blocks, 1,000 facts, 100 iterations and 50 ms Datalog execution ceiling are prototype limits, not measured capacity claims. Challenges last 60 seconds, admit at most five exchanges and are globally capped at 128 pending entries.

This is a loopback-only development prototype, not the stage-1 release. TLS client support, complete principal/policy administration, authorization fuzzing/benchmarks, durable idempotency, pipelines/KV, follow/watch and backup remain pending. Full authorization, durability and capacity release gates remain open. Recreate old development data after the schema changes; no conversion is performed. The default server remains health-only unless `--data-api` is supplied; data mode requires bootstrap before startup.

Design entrypoint: [unified objects, directories and streams](unified-design.md). Its object APIs are planned; the following section retains the health-only bootstrap commands; the authenticated prototype is described above.

Run from the repository root. Install rustup and a native C toolchain (Linux: compiler, linker, standard C headers); bundled SQLite compiles C. `rust-toolchain.toml` pins Rust 1.98.1, rustfmt and clippy. Dependency resolution is recorded in `Cargo.lock`; include that file when committing this bootstrap. Commits are made only when requested; this prototype was implemented in focused commits.

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

Without `--data-api`, the only routes are `GET /healthz` and `GET /readyz` (Axum also handles HEAD), and unknown routes return 404. The opt-in authenticated routes are described above; UI and general principal/policy administration remain unavailable. Readiness is startup readiness, not a continuous disk-pressure or writeability check. On initialization/migration error the process exits without a listener; a live router defaults to 503 readiness until explicitly activated and is marked unready on shutdown.

Exercise the real internal storage and the independent authorization spike:

```bash
cargo test --locked --test storage
cargo test --locked --test server_process
cargo test --locked --test auth_prototype
```

Each test uses temporary directories. The process test launches both binaries, checks health, sends SIGTERM, restarts, and verifies previously stored bytes. It runs on Unix. This is **not** hard-kill or power-loss validation. Storage tests open actual file-backed databases, including WAL/FULL settings, byte/position persistence, concurrency, rollback, constraints, and foreign-format refusal.

`Store` is synchronous and internal. HTTP handlers use the bounded blocking DataService and authorized command transaction; raw Store methods remain trusted internal APIs. Pipeline configuration/evaluation is unavailable, so only the empty pipeline is supported. Infinite retention is the only implemented record-storage mode. Internal lifecycle APIs also persist live (`none`) descriptors; append/replay and live delivery remain unavailable for these. Config supports a 1-byte–1-MiB record limit, with independent config/metadata CAS. Metadata is a JSON object bounded to 64 KiB of UTF-8 input; no object links are supported. Logical deletion frees the name and hides the old ID while retaining its rows for future reclamation. Segment summaries seal at 8 MiB of payload or 10,000 records and can be paged through the internal Store API. Appends take at most 1 MiB; reads require 1–1000 records and 1 byte–16 MiB payload budget. One record may exceed the requested read byte budget so pagination progresses. Arbitrary binary bytes and empty records are valid.

Use a private data directory and filesystem permissions appropriate for its contents. Startup does not change existing directory permissions. Never copy only an active SQLite main file as a backup. Backup/restore, filesystem durability certification, schema upgrades and deployments are future work. Until the first release, schema changes edit `migrations/0001_streams.sql` in place (D29): a data directory created by an older build is not upgraded; recreate it after pulling a schema change. Startup checks required lifecycle columns, so bootstrap-era schemas now fail startup, but the unchanged version number is not a general schema compatibility guarantee. See [roadmap](roadmap.md), [status](implementation-status.md), and [dependency/prototype findings](dependency-decisions.md).
