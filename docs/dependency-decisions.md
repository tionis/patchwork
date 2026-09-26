# Dependency and prototype decisions

Checked 2026-09-23 using crates.io metadata, downloaded source/manifests and executable tests. Toolchain 1.98.1 was already installed and is pinned exactly. Cargo.lock captures transitive resolution; semver manifest ranges allow deliberate future updates. No dependency selection is a claim that G-AUTH or a complete license/security audit has passed.

| Direct dependency | Resolved version | License | Purpose |
| --- | --- | --- | --- |
| axum | 0.8.9 | MIT | Health and authenticated prototype routes on Tokio; HTTP/1 only |
| tokio | 1.53.1 | MIT | Async server, signals, tests |
| clap | 4.6.7 | MIT OR Apache-2.0 | Typed server/CLI arguments |
| rusqlite | 0.40.2 | MIT | Explicit synchronous SQLite transactions |
| reqwest | 0.13.5 | MIT OR Apache-2.0 | Timeout-bounded local HTTP CLI; redirects disabled, TLS not enabled |
| serde | 1.0.229 | MIT OR Apache-2.0 | Typed API/config JSON |
| thiserror | 2.0.20 | MIT OR Apache-2.0 | Shared typed errors |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | MIT | Structured stderr logs and checked filter |
| uuid | 1.26.1 | Apache-2.0 OR MIT | Random stable resource IDs |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | Test isolation (dev only) |
| tower | 0.5.3 | MIT | Router tests (dev only) |
| biscuit-auth | 6.0.0 | Apache-2.0 | Pinned prototype identity and attenuation verifier; initial spike retained |
| ssh-key | 0.6.7 | MIT OR Apache-2.0 | Pinned Ed25519 SSHSIG verification; std/ed25519 features |
| base64 | 0.22.1 | MIT OR Apache-2.0 | Binary API/challenge encoding |
| rand | 0.8.8 | MIT OR Apache-2.0 | OS-random 256-bit login challenge nonces |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | Bounded metadata, grants, API payloads |

Bundled SQLite uses `libsqlite3-sys 0.38.2` (MIT wrapper; SQLite itself public domain). This avoids varying system SQLite versions and makes STRICT tables/subsecond timestamps reproducible. It requires a C compiler. Native dependency metadata can be inspected without fetching other platforms:

```bash
cargo metadata --locked --offline \
  --format-version 1 --filter-platform x86_64-unknown-linux-gnu
```

API evidence: [Axum 0.8.9](https://docs.rs/axum/0.8.9/axum/), [rusqlite 0.40.2](https://docs.rs/rusqlite/0.40.2/rusqlite/), [Biscuit 6.0.0 builders](https://docs.rs/biscuit-auth/6.0.0/biscuit_auth/struct.AuthorizerBuilder.html), [reqwest 0.13.5](https://docs.rs/reqwest/0.13.5/reqwest/). Source/manifests for all listed direct dependencies were available through Cargo metadata; compile/tests exercise the APIs used. These are established projects; no separate maintenance SLA was assessed.

SQLite connections enable WAL, FULL synchronization, foreign keys and a two-second busy timeout. Startup uses application ID plus schema version to refuse foreign/newer databases and a transaction to apply migration 0001 atomically. There is one synchronous connection per Store, with `&mut self` write operations. The prototype uses a 32-permit blocking admission boundary and a shared Store mutex; authorization/lifecycle and mutations share an immediate transaction, with nested savepoints for storage operations. [SQLite WAL](https://www.sqlite.org/wal.html) and [synchronous documentation](https://www.sqlite.org/pragma.html#pragma_synchronous) describe the engine behavior; tests prove reopen behavior, not device power-loss guarantees.

## Biscuit initial spike

Semantic tests use a one-second execution ceiling (other library limits retain their defaults) to avoid relying on the library's one-millisecond default on CI. Negative assertions require an actual policy/check denial: parser, execution and budget failures fail the test. This is not validation of production resource budgets.

Run `cargo test --locked --test auth_prototype`.

`tests/auth_prototype.rs` issues an Ed25519 Biscuit, serializes it, verifies it with the root public key and rejects a wrong key/tampering. Dynamic principal/credential/request/server facts use typed `fact`/`string` builders, never interpolated Datalog. The static prototype policy in `prototypes/authorization.datalog` joins principal, credential, exact operation, kind/resource, current rights and issuance rights. It has no blanket permit. A request contains one action and resource, avoiding unrelated existential matches.

Offline holders append a check limiting action AND resource without the issuer key. Tests prove a permitted parent operation becomes denied for the child. A forged attenuation block asserting principal, credential validity, ambient action/resource and current/issued rights cannot make a denied delete or revoked credential pass. A grandchild's forged facts also cannot satisfy a parent's restrictive check. These exercise subsets of A01, A02, A05, A06 and A10, not their entire integration contracts. Crucially, default policy trust excludes attenuation facts; widening trust to all/previous blocks in grant rules would invalidate this design.

Library finding: `biscuit-auth 6.0.0` fails compilation with all default features disabled because builder modules unconditionally import feature-gated `ToAnyParam`. Enabling **datalog-macro** fixes it; regex-full and PEM remain disabled. Its macro dependency emits a future Rust incompatibility warning from `proc-macro-error2 2.0.1`. Current pinned-toolchain builds work; monitor upstream before a toolchain upgrade. This is a documented dependency issue, not evidence that Biscuit is unsuitable.

The 2026-09-26 prototype implements typed Rust current-grant/ceiling checks, bounded Biscuit verification, instance binding, session-only issuance, persisted expiry/revocation, atomic challenge exchange and OpenSSH/ssh-agent Ed25519 fixtures. Prototype API evidence: [ssh-key SSHSIG](https://docs.rs/ssh-key/0.6.7/ssh_key/struct.SshSig.html), [Biscuit authorizer limits](https://docs.rs/biscuit-auth/6.0.0/biscuit_auth/struct.Authorizer.html). Issuer identity queries explicitly trust only authority; request facts use typed builders. The token vocabulary uses issuer-only `issued_instance` separately from server `instance` to avoid ambiguous trust origins. Third-party blocks are rejected.

Still required for G-AUTH/G-SSH/G-LIMITS: complete administrative schemas, prefix/forged-time adversarial vectors, sustained malformed-token fuzzing, measured latency/memory, per-source admission and full challenge race/origin/expiry matrices. Active-work refresh remains dependent on future subscriptions. The prototype admits 32 encoded KiB, eight blocks and Datalog limits of 1,000 facts/100 iterations/50 ms; these are bounded implementation settings, not performance certification. The loopback prototype is not a production deployment approval. Dependency resolution is recorded in Cargo.lock; adding ssh-key with the available offline index also re-resolved target-specific wasm packages. Native builds and tests passed.
