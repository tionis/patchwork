# Implementation status

Verified bootstrap: 2026-09-23 (design revised 2026-09-25), Linux x86_64, Rust/Cargo 1.98.1. **Authenticated loopback prototype runnable as of 2026-09-26; M0/M1 remain partial.** Start with [design index](index.md), [roadmap](roadmap.md) and [development commands](development.md).

## Available behavior

The 2026-09-26 M1-04 increment adds internal exact-name lookup, config and metadata CAS, lifecycle tombstones, and atomic logical segment summaries. One Rust package provides server/CLI binaries, typed config/errors and JSON tracing; checked names/UUID IDs/positions/revisions; new-format SQLite initialization and migration 0001; WAL/FULL/foreign keys/busy handling; internal infinite-retention stream creation, immutable retained append and bounded replay; byte/position persistence across reopen; health/readiness, graceful SIGINT/SIGTERM and health CLI. GitHub verification workflow is configured.

The initial dev-only Biscuit spike is retained. Biscuit 6.0.0 now also verifies prototype bearer credentials, with typed Rust current-grant/issuance-ceiling intersection. OpenSSH-compatible Ed25519 SSHSIG login, persisted short-lived sessions, scoped token mint/revoke and bounded authorized HTTP commands are runnable behind `--data-api` on loopback.

## Unavailable behavior and decisions

Public deployment, full principal/policy administration, objects/references, snapshots/GC, pipelines, KV, webhooks, subscriptions, UI, backup/restore, Apps, Functions, P2P/media and CRDT integration remain unavailable. Opt-in loopback HTTP exposes the prototype stream/auth operations listed below; the default remains health-only. Readiness means startup completed, not continuous storage health. The synchronous Store remains trusted internal code; HTTP uses bounded blocking admission and authorized transactions.

Implementation choices: one repository-root Rust package; exact toolchain/lockfile; explicit data directory and `patchwork-v1.sqlite3` with application ID `0x50574348` and schema version 1; foreign/future DB refusal; canonical UUID IDs; checked counters; 1 MiB records and bounded pages; local HTTP-only CLI with health, SSH login, stream create/resolve/show/delete, binary append/get, JSON replay and scoped token mint/revoke. [Dependency decisions](dependency-decisions.md) records APIs, licenses and prototype findings.

The design uses three data primitives (objects, references, streams), one authoritative SQLite transaction domain, one object graph and one job/lease lifecycle. Directory/app/snapshot formats compose these. Hierarchical named references are SQLite-indexed typed-root pointers with CAS and root retention, not a second mutable KV engine. Multi-key app changes use map batch + ref CAS; commands append at most one record. Server and external recovery requirements share trim safety and per-requirement lag budgets. Server authorization is a typed allow-only grant model; Biscuit carries identity and attenuation only. GC and backup are designed to run online. Work is staged: streams, then objects and recovery, then structured objects; later integrations are frozen. The operational UI and hosted apps use one browser session implementation with separate origin, audience and grant ceilings; a fresh SSH handoff is required for operational mint provenance. Exact format, runtime and integration choices remain gates, not implemented features.

## Historical bootstrap verification — 2026-09-23

These commands passed on the repository-root package:

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `cargo build --locked --all-targets` | Pass |
| `cargo clippy --locked --all-targets -- -D warnings` | Pass |
| `cargo test --locked --all-targets` | 13 passed: 1 store unit, 6 storage, 3 auth prototype, 2 health, 1 process/CLI |
| `cargo tree --locked -e normal --prefix none` | No Biscuit in production dependency graph |

Storage tests cover fresh/reopened DB, exact binary/empty/large payloads, ordered/concurrent appends, rollback, page progress, invalid values/overflow and foreign-format preservation. Process tests start the server/CLI, shut down with SIGTERM and reopen persisted data. These are **not hard-kill, power-loss or capacity tests**. No object, snapshot, app, function, media or CRDT conformance case is fully implemented. Auth tests cover only specified subsets.

Known upstream warning: `proc-macro-error2 2.0.1` future Rust compatibility, documented with the required Biscuit `datalog-macro` feature. Current pinned checks pass. Remote CI has not run.

The storage design now records SQLite's row-per-record append and prefix-trim costs, WAL/page-reuse limits and the data-lifetime boundary between records, object roots, snapshots, KV, jobs and live traffic. Logical segments are internal summaries, not a physical deletion optimization. G19–G21 and M2-07 specify evidence still needed; append summaries now exist, but no append/trim benchmark, retention GC or vacuum policy has been implemented.

## M1-04 storage increment — 2026-09-26

M1-04 is partial. Implemented internal operations: exact live-name lookup; atomic creation with concrete config and metadata; independently revisioned config and metadata replacement; config-CAS logical deletion with durable tombstones and reusable names; retained append with per-stream record limits; and bounded logical-segment pages. Segments seal at 8 MiB payload or 10,000 records and maintain count, byte total and minimum/maximum acceptance timestamps in the record transaction. Clock rollback does not hide a newer timestamp in the maximum summary.

Supported config is intentionally limited to infinite retention or storage-only live descriptors and record size limits. Live append/replay is rejected; there is no live delivery service. Bounded retention, pipelines, attachments, recovery requirements and object links remain unavailable; unknown config fields fail deserialization. Metadata is a bounded JSON object and does not configure privileges or establish object roots. Logical deletion retains underlying rows until a future reclamation implementation. No public data routes were added.

Verification passed: `cargo fmt --all -- --check`, `cargo build --locked --offline --all-targets`, `cargo clippy --locked --offline --all-targets -- -D warnings`, and `cargo test --locked --offline --all-targets` (19 tests). The new `stream_lifecycle` integration target has four tests covering concurrent config/metadata CAS winners, independent revisions, deletion/recreation, per-stream limits, live-mode rejection, invalid config/metadata, interleaved byte segments, summary-to-row comparison and reopen. Two added store unit tests cover revision exhaustion, inserted-record/segment rollback on faults, the 10,000-record boundary, empty payload accounting, timestamp rollback and reopened summaries. This is storage-level evidence only; public CAS statuses, object roots, full mode-none attachment validation, prefix trimming and hard-kill/power-loss conformance remain unverified.

Migration 0001 changed in place under D29; recreate development data directories. No existing data was converted. Startup now checks the lifecycle columns, so old bootstrap schemas fail startup. The existing upstream future-compatibility warning remains unchanged.

## Authenticated prototype verification — 2026-09-26

The authenticated HTTP server and CLI are runnable; see [development](development.md#authenticated-loopback-prototype). Local one-time bootstrap registers an Ed25519 key and stores instance identity, origin and issuer key in the same SQLite database. Challenge redemption and session issuance are atomic. Current grants, principal/credential validity and immutable ceilings are rechecked in the command transaction. Signature and initial attenuation checks run before the write lock; a bounded final attenuation check refreshes time after any lock wait. Exact scopes do not follow deleted/recreated names; prefixes intentionally cover future matching names.

`cargo build --locked --offline --all-targets`, `cargo fmt --all -- --check`, `cargo clippy --locked --offline --all-targets -- -D warnings`, and `cargo test --locked --offline --all-targets` passed: **30 tests**. Added evidence includes the typed action matrix and prefix containment, malicious attenuation identity/request facts, expiry/block/byte rejection, bidirectional ssh-keygen signatures, agent-backed signatures, one-use challenge exchange, five-attempt exhaustion, persisted revocation and scoped access, HTTP CAS/error/body limits, and a real-process bootstrap/login/binary-I/O/restricted-token workflow that kills and restarts the server after an acknowledged append. This single hard-kill fixture is not a complete fault matrix or power-loss proof. `scripts/prototype-demo.sh` provides an isolated runnable demonstration. The repository-root OpenAPI 3.1 contract documents the implemented subset and passed `openapi-spec-validator`; the isolated demo script also passed its binary comparison and read-only rejection checks.

M0-05/06/07, M1-05/06 and M4-03 have prototype subsets, not completed release gates. Full administrative policy APIs, fuzz/property/load evidence, per-source login admission, broader authorization adversarial coverage, TLS support, pipeline integration, idempotency and release operations remain pending. SQL serializes the prototype command path, including reads; capacity is unmeasured. SSH sessions use a 15-minute lifetime; general API credentials cap at one day. Native dependencies now include Biscuit, ssh-key, rand, base64 and serde_json; the historical no-Biscuit production-graph observation no longer applies.

## Documentation verification

Run `vulcan --vault docs --output json doctor --fail-on-issues` from the repository root. It passed with zero unresolved/ambiguous links, broken embeds, parse/type issues, stale or missing index rows, and orphan notes/assets. Vulcan doctor does not validate roadmap task-ID uniqueness or dependency cycles; those remain review obligations until an equivalent wiki collection check exists. `git diff --check` checks tracked-file whitespace. None of these checks proves architectural correctness or runtime conformance.

## Next work and safety

Next work: finish the authentication/policy gates and M1-04 configuration subset, then M3-01 pipeline integration and M1-07 durable idempotency on the stage-1 path in the [roadmap](roadmap.md#release-stages). The runnable prototype is not the complete streams release. Object work (O-01) starts in stage 2. G-AUTH/G-SSH, format/graph, sandbox, crash and capacity gates remain open.
