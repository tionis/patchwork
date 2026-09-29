# Patchwork

Patchwork is a Rust, single-node backend for ordered streams, immutable objects, and revisioned references. The **authentication and stream core is runnable**: SSH login, scoped/offline-attenuated credentials, principal administration and recovery, retained/live streams, processed idempotent appends, retention, config/metadata CAS, follow/live/watch subscriptions, transactional KV attachments, signed GitHub webhook ingress and online SQLite backup with verified restore. Objects and the broader platform remain planned.

Run the isolated demo from the repository root:

```sh
./scripts/prototype-demo.sh
```

It builds the binaries, uses temporary keys/data, verifies a binary round trip and read-only access, then stops its server. Requires Rust 1.98.1, a C/C++ toolchain with CMake, OpenSSH and Python 3. For an interactive server, follow the [prototype runbook](docs/development.md#authenticated-loopback-prototype). Data routes require local bootstrap and `--data-api`; the default server is health-only. Recreate older development databases after schema changes.

See the [OpenAPI 3.1 contract](openapi.json), [implementation status](docs/implementation-status.md), [roadmap](docs/roadmap.md), and [design wiki](docs/index.md). This prototype is not the complete stage-1 release: operational metrics, public deployment, load/fault evidence and the remaining release gates are pending, and the OpenAPI contract does not yet describe the KV, attachment and hook routes.

```sh
cargo build --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
vulcan --vault docs --output json doctor --fail-on-issues
```

The crate, migrations and tests live at the repository root. The wiki uses Vulcan; its instructions are in `docs/AGENTS.md`.
