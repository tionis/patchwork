# Patchwork Implementation TODO

Plan baseline date: 2026-02-15

This file is the execution plan for implementing the new service in `projects/skald`.
It combines architecture evaluation, sequencing, and definition-of-done checkpoints.

## Core Product Focus (Non-Negotiable)

- SQLite DBs are treated as document units.
- Built-in sync is part of the document model, not an optional afterthought.
- Service endpoints are structured around explicit `db_id` ownership.
- Human auth path is OIDC in the web app.
- Machine auth path is scoped service tokens issued via the web interface.

## Architecture Evaluation

### Strengths

- Clear product axis: document-centric SQLite service with DB-scoped endpoints.
- Clear capability split: `message pubsub` vs `streams` avoids mixing incompatible semantics.
- Multi-tenant boundary is explicit (`db_id` scoped APIs + ACL actions).
- Durability boundaries are explicit:
  - durable: message pubsub, webhook inbox, blob metadata, leases
  - non-durable: stream relay channels
- Security model is pragmatic: hashed tokens, no plaintext webhook secret storage.
- Legacy integration path is clear for stream behavior parity from old patchwork.

### Primary Risks

- Query watch invalidation (`v0` global reeval) can become expensive under write-heavy load.
- Stream compatibility parity is subtle (`Patch-H-*`, `Patch-Status`, `?switch=true`).
- Per-DB runtime model needs careful lifecycle management to avoid goroutine leaks.
- Message replay/wildcard behavior must remain consistent across HTTP SSE and MQTT adapter.
- Blob GC and reference union across DBs can be costly without indexing + batching strategy.

### Locked Decisions (from design + recent decisions)

- SQLite DBs are first-class documents with built-in sync and DB-centered APIs.
- OIDC is the primary web authentication model.
- Machine tokens are created and managed from the web UI and stored as hashes.
- Native DB-scoped auth only (no legacy Forgejo ACL compatibility).
- Message pubsub payload limit: `1 MiB`.
- Streams: no fixed app-level payload cap in v1 (rate limits still apply).
- Webhook ingest is DB-scoped, persist-first, query-consumed, no built-in consumer API in v1.
- Webhook ingress auth uses `Authorization` header tokens; HMAC request signatures are deferred.
- Lease authority is local SQLite state using single-writer lock discipline.
- Blob finalize must verify object hash before completion success.

### Open Questions (must be revisited during implementation)

- Legacy compatibility coverage depth (strict parity vs high-usage subset).
- Message retention defaults (currently no default TTL; operator-defined policy).
- Reactive query invalidation launch target (`v0` vs table-aware).
- Legacy webhook-proxy feature keep/change/drop.
- SQL extension bridge timing (MVP vs later).

## Implementation Strategy

Deliver in thin vertical slices with tests per capability.
Prefer enabling a minimal but working API surface per phase before adding optimizations.
Prioritize document runtime + sync + OIDC/token UX before secondary capability breadth.

## Phase 0: Project Skeleton, Document Runtime, and Sync Core

- [x] Create Go service skeleton and module structure (`cmd/`, `internal/`, `migrations/`).
- [x] Add config loading for bind address, data dir, logging, limits, and feature flags.
- [x] Define document registry model for `db_id` lifecycle (open/create/lookup).
- [x] Add HTTP router baseline and required operational endpoints:
  - [x] `/healthz`
  - [x] `/status`
  - [x] `/metrics`
- [x] Implement DB runtime manager:
  - [x] one DB worker goroutine per `db_id`
  - [x] channel-based operation dispatch (no connection pool)
  - [x] idle DB worker cleanup policy
- [x] Add sync scaffolding per DB document:
  - [x] snapshot/export interface
  - [x] change-feed/sync event interface
  - [x] sync transport hooks (implementation can start minimal, but API boundary must exist)
- [x] Add migration runner for service/global metadata and per-DB schema bootstrapping.
- [x] Add structured logging and baseline Prometheus metrics wiring.

Exit criteria:
- service starts, serves health endpoints, can open/create DB runtime by `db_id`, and exposes a minimal sync boundary.

## Phase 1: Web Identity, Token Issuance, and Authorization Core

- [ ] Implement OIDC login flow for web users:
  - [ ] auth redirect + callback
  - [ ] secure web session handling
  - [ ] user identity binding for ownership/audit
- [x] Implement token storage schema with hashed token secrets.
- [x] Implement token issue/revoke/list endpoints for machine credentials (`admin.token` scope).
- [ ] Implement web UI/API for machine token management:
  - [ ] create token with DB/action scopes
  - [ ] list/revoke token metadata
  - [ ] show plaintext token only at creation time
- [x] Implement auth middleware:
  - [x] parse `Authorization` header
  - [x] token hash validation
  - [x] expiry checks
- [x] Implement ACL evaluator for DB-scoped actions and optional topic/resource prefixes.
- [x] Add request rate limiting (global + per-token hooks for future tuning).

Exit criteria:
- OIDC web login works, machine tokens can be minted in UI, and auth/ACL behavior is tested for all MVP actions.

## Phase 2: Query API + Reactive Query Watch

- [ ] Implement query execute endpoint(s) under `/api/v1/db/:db_id/query/*`.
- [ ] Enforce parameterized SQL contract and statement class restrictions by scope:
  - [ ] `query.read`
  - [ ] `query.write`
  - [ ] `query.admin`
- [ ] Add query resource bounds (time/rows/result bytes).
- [ ] Implement reactive query watch SSE endpoint:
  - [ ] `POST /api/v1/db/:db_id/query/watch`
  - [ ] events: `snapshot`, `update`, `heartbeat`, `error`
  - [ ] deterministic `result_hash`
- [ ] Implement invalidation `v0`: reevaluate all active watches on successful write commit.

Exit criteria:
- deterministic watch update behavior under concurrent read/write tests.

## Phase 3: Message PubSub (Durable)

- [ ] Add `messages` storage schema and indexes.
- [ ] Implement publish endpoint:
  - [ ] `POST /api/v1/db/:db_id/messages`
  - [ ] enforce `1 MiB` payload limit
  - [ ] persist-before-ack behavior
- [ ] Implement SSE subscribe endpoint:
  - [ ] `GET /api/v1/db/:db_id/events/stream`
  - [ ] repeated `topic` filters
  - [ ] replay via `since_id` and `tail`
  - [ ] wildcard topic matching (`+`, `#`) scoped to DB
- [ ] Add retained/queued-message groundwork needed for future persistent session support.
- [ ] Ensure no default TTL is applied unless DB/operator policy defines one.

Exit criteria:
- publish + replay + wildcard filters validated by integration tests.

## Phase 4: Streams Capability (Legacy Behavior Parity)

- [x] Port/adapt core stream behavior from `../patchwork`:
  - [x] blocking rendezvous queue
  - [x] non-blocking broadcast mode
  - [x] request/responder (`/req`, `/res`)
  - [x] responder switch mode (`?switch=true`)
  - [x] passthrough headers (`Patch-H-*`) and `Patch-Status`
- [x] Implement stream API routes:
  - [x] `GET /api/v1/db/:db_id/streams/queue/:topic/next`
  - [x] `POST /api/v1/db/:db_id/streams/queue/:topic`
  - [x] `POST /api/v1/db/:db_id/streams/req/:path`
  - [x] `POST /api/v1/db/:db_id/streams/res/:path`
- [x] Add compatibility aliases for legacy route shapes (`/public/*`, `/p/*`, `/u/{user}/*` mapping policy).
- [x] Enforce stream auth scopes (`stream.read`, `stream.write`).

Exit criteria:
- parity tests for known old patchwork stream scripts pass against compatibility routes.

## Phase 5: Webhook Ingest (Persist-First)

- [x] Create/verify `webhook_inbox` table and index bootstrap.
- [x] Implement webhook ingest endpoint:
  - [x] `POST /api/v1/db/:db_id/webhooks/:endpoint`
  - [x] auth scope: `webhook.ingest`
  - [x] capture payload + method + headers + query + content type + timestamp
  - [x] persist in one transaction and return success after commit
- [x] Ensure inserts use explicit column lists so extra columns in `webhook_inbox` do not break writes.
- [x] Add docs/examples for query-based consumption pattern.
- [x] Keep HMAC verification out of MVP; add extension hooks for future implementation.

Exit criteria:
- webhook ingest remains correct when `webhook_inbox` includes additional user-defined columns.

## Phase 6: Lease/Fencing API

- [ ] Implement `fencing_tokens` schema bootstrap.
- [ ] Implement endpoints:
  - [ ] acquire
  - [ ] renew
  - [ ] release
- [ ] Enforce monotonic fence behavior and owner checks.
- [ ] Use transactional lock discipline (`BEGIN IMMEDIATE`) in DB worker.
- [ ] Add fence validation hooks for protected operations.

Exit criteria:
- concurrent lease tests verify monotonicity and conflict correctness.

## Phase 7: Blob Control Plane

- [ ] Implement blob metadata schema.
- [ ] Implement APIs:
  - [ ] init-upload
  - [ ] complete-upload
  - [ ] read-url
  - [ ] claim
  - [ ] release
- [ ] Integrate object storage pre-signing.
- [ ] Enforce hash verification in `complete-upload`.
- [ ] Add global GC job:
  - [ ] union references from DB `blobs` tables
  - [ ] grace-period deletion rules

Exit criteria:
- end-to-end upload/finalize/read flow passes, including hash mismatch rejection.

## Phase 8: Compatibility and Hardening

- [ ] Build explicit legacy compatibility matrix (`kept / changed / dropped`) in docs.
- [ ] Add load tests for:
  - [ ] query watch under write load
  - [ ] message fanout/replay
  - [ ] high-concurrency streams
- [ ] Add chaos/failure tests:
  - [ ] DB worker restart
  - [ ] partial webhook writes
  - [ ] lease renewal contention
  - [ ] blob finalize/GC race windows
- [ ] Add deployment artifacts and operational runbooks.

Exit criteria:
- MVP feature set is stable under target concurrency and failure scenarios.

## Deferred (Post-MVP)

- [ ] MQTT adapter implementation details and persistent session semantics.
- [ ] Query watch dependency-aware invalidation (`v1`).
- [ ] SQL extension bridge and outbox workers.
- [ ] Webhook HMAC request signature validation (optional per endpoint).
- [ ] Legacy webhook-proxy feature decision + implementation (if kept).
- [ ] HuProxy/OIDC SSH claim integration (if reintroduced).

## Suggested Working Order for Immediate Next Steps

1. Phase 0 skeleton + DB runtime manager + sync scaffolding.
2. Phase 1 OIDC + token issuance UX + auth/ACL.
3. Phase 5 webhook ingest (small vertical slice, validates DB/auth path quickly).
4. Phase 4 streams parity (largest compatibility surface).
5. Phase 3 durable message pubsub.
6. Phase 2 query + watch.
7. Phase 6 lease.
8. Phase 7 blobs.
