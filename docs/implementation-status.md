# Implementation status

Verified core milestone: 2026-09-26, Linux x86_64, Rust/Cargo 1.98.1. **The authenticated HTTP server and CLI now run the authentication and stream core end to end.** This is not the complete stage-1 release or the full platform. Start with [design index](index.md), [roadmap](roadmap.md) and [development commands](development.md).

## Available behavior

The 2026-09-26 M1-04 increment adds internal exact-name lookup, config and metadata CAS, lifecycle tombstones, and atomic logical segment summaries. One Rust package provides server/CLI binaries, typed config/errors and JSON tracing; checked names/UUID IDs/positions/revisions; new-format SQLite initialization and migration 0001; WAL/FULL/foreign keys/busy handling; internal infinite-retention stream creation, immutable retained append and bounded replay; byte/position persistence across reopen; health/readiness, graceful SIGINT/SIGTERM and health CLI. GitHub verification workflow is configured.

The initial dev-only Biscuit spike is retained. Biscuit 6.0.0 now also verifies prototype bearer credentials, with typed Rust current-grant/issuance-ceiling intersection. OpenSSH-compatible Ed25519 SSHSIG login, persisted short-lived sessions, scoped token mint/revoke and bounded authorized HTTP commands are runnable behind `--data-api` on loopback.

## Unavailable behavior and decisions

Objects/references, snapshots/GC, KV, webhooks, UI, backup/restore, Apps, Functions, P2P/media and CRDT integration remain unavailable. Public deployment and release certification remain open. The server binds loopback and supports a TLS frontend; the CLI verifies HTTPS using platform trust. The default server remains health-only. Readiness means startup completed, not continuous storage health.

Implementation choices: one repository-root Rust package; exact toolchain/lockfile; explicit data directory and `patchwork-v1.sqlite3` with application ID `0x50574348` and schema version 1; foreign/future DB refusal; canonical UUID-based IDs; decimal-string positions/revisions/byte bounds; RFC3339 wire timestamps; 1 MiB records and bounded replay. HTTP uses canonical `/v1` data routes, with earlier root aliases preserved. CLI covers SSH login, credential inspection/list/mint/revoke/offline attenuation, principal/policy/creation-rule administration, local recovery, stream lifecycle/config/metadata/listing, retained/live append, replay, follow/live/watch. [Dependency decisions](dependency-decisions.md) records the original API/license findings.

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

## Authentication and stream core — 2026-09-26

Implemented and exercised: revisioned principal/key/grant administration with last-admin protection; policy lifetime caps; credential listing without secrets; typed offline attenuation; audited local administrator recovery that preserves existing credentials and issuance ceilings; per-peer/global login admission; canonical HTTP and HTTPS CLI support. Credential/principal changes are checked transactionally, and active subscriptions reauthorize before batches and every second or faster while idle.

Retained streams support binary append/read, config and metadata CAS, bounded name listing, longest-prefix creation rules, opt-in atomic create-on-append, deterministic built-in filters/validators, principal-scoped 24-hour idempotency receipts, and plain-stream age/byte retention. Receipts survive payload trimming and restart. Live streams publish through bounded ephemeral channels with process epochs and no durable cursor. Retained follow resumes with `STREAM_ID:NEXT_POSITION`; watch emits hints only and checks all explicit selectors. Prefix watch requires an unattenuated token with universal prefix authority; arbitrary Datalog selector implication is not inferred. Explicit stream selectors support offline attenuation.

Work bounds: 64 requests admitted before body extraction, 10-second request/upload deadline, 32 blocking operations, 128 subscriptions, eight queued live records per stream, 256 watch hints, bounded retention batches and receipt cleanup. Login admits 32 requests per socket peer and 256 globally per 60-second window, with a bounded peer map and Retry-After. Forwarded client-IP headers are not trusted; a TLS proxy shares its socket-peer budget. Token parsing caps encoded bytes at 32 KiB and blocks at eight; initial and derived facts are both bounded at 1,000, iterations at 100 and Datalog execution at 50 ms. No general user-code engine is enabled.

New tests cover simultaneous same-key retries, expiry/key reuse, pipeline drop/reject behavior, receipts after changed config and trimming, creation-rule atomicity, principal policy expansion/removal, live overflow, watch-only privacy, retained resume/history loss, revocation closure, malformed/mutated token corpus and the initial-fact limit. A real-process fixture covers admin/list/config CLI paths, offline attenuation, hard restart plus deduplicated retry, local recovery, and graceful shutdown with an active follow. These are targeted regression and process-fault tests, not a complete power-loss proof or sustained fuzz campaign. Reproduce verifier measurements with `cargo run --locked --release --example auth-benchmark -- 100`; see [development](development.md#verification-and-measurements).

Migration 0001 changed in place under D29. Use a fresh development directory; no existing data was converted. Recovery requirements, attachments and object links are rejected until their storage protection is implemented. Logical deletion still retains underlying rows; plain-stream retention reclaims record rows but does not compact the SQLite file automatically.

Verification for this core increment passed: full all-target test suite (**44 tests**), Clippy with warnings denied, rustfmt, OpenAPI 3.1 validation, Vulcan doctor and the isolated demo (including a deduplicated retry). Focused commits preserve the implementation slices. The existing upstream future-compatibility warning is unchanged.

The final release-profile verifier sample is stored at repository-root `benchmarks/auth-2026-09-26.jsonl`: Linux x86_64, Intel Core i7-8650U @ 1.90 GHz, Rust 1.98.1, 100 requests per matrix cell, on a shared development host with concurrent build activity. Accepted cases (1/8 blocks, 10/100 extra facts with checks) measured p50 0.501–2.503 ms, p95 3.061–4.605 ms and p99 4.382–9.504 ms. Process cumulative peak RSS reached about 4.4 MB; this is not isolated per-request allocation. All 32-block cases and all 1,000-extra-fact cases were rejected (authority/ambient facts also count). These short, contended samples establish bounded behavior and provide a reproduction baseline, not sustained HTTP capacity or a latency SLO. A check of the initial benchmark exposed the initial-fact limit gap; both initial and derived limits now fail closed and have a regression test.

## Documentation verification

Run `vulcan --vault docs --output json doctor --fail-on-issues` from the repository root. It passed with zero unresolved/ambiguous links, broken embeds, parse/type issues, stale or missing index rows, and orphan notes/assets. Vulcan doctor does not validate roadmap task-ID uniqueness or dependency cycles; those remain review obligations until an equivalent wiki collection check exists. `git diff --check` checks tracked-file whitespace. None of these checks proves architectural correctness or runtime conformance.

## Next work and safety

Next work: stage-1 KV, signed webhook ingress, DB backup/restore, operational metrics and broader release-gate evidence. The core stream system is runnable; the full stage-1 release also requires these services. Object work starts in stage 2. G-AUTH/G-SSH still need a longer fuzz campaign and deployment/load review; durability/capacity gates need the remaining fault and pressure matrix. Format/graph and sandbox gates apply to later stages.