# Patchwork Sync Server Design (Draft)

This document defines the new sync server that merges the "Skald" direction with selected functionality from the existing Patchwork service.

## Status and Naming

- Working implementation folder: `projects/skald`
- Planned external product name: `patchwork` (reuse of old name)
- Planned primary domain: `patch.tionis.dev`

If naming changes later, this design remains valid and only naming strings/routes/docs should be updated.

## Core Decisions

1. Keep projects separate by responsibility.
2. Keep token management separate for now (no shared issuer across forge/ratatoskr/patchwork yet).
3. Build this as a standalone Go service (not integrated into ratatoskr runtime).
4. Reuse old Patchwork domain and fold useful Patchwork features into this server.
5. Keep S3 as data plane for large blobs; service acts as control plane.
6. Treat each SQLite DB as a document unit with built-in sync surfaces.
7. Keep primary API structure DB-scoped (`db_id` first).
8. Use OIDC for interactive web authentication.
9. Issue scoped machine tokens from the web UI for non-interactive clients.

## Specification Approach

This project is intentionally developed interactively:

- API contracts, schema details, and capability internals can evolve during prototype implementation.
- Design updates should be committed alongside behavior changes.
- Stable invariants should be introduced only when needed for correctness/interoperability.

## Goals

- Provide a generic scripting backend that can grow incrementally.
- Support machine-to-machine and CLI-heavy workflows.
- Provide document/DB-scoped SQL, realtime messaging, and coordination primitives.
- Add optional web-oriented access paths (SSE, HTTP, optional MQTT).
- Centralize access control and auditability for these operations.

## Product Focus

- SQLite DBs are first-class documents.
- Built-in sync is part of the core DB runtime model.
- Service endpoints are structured around explicit `db_id`s.
- Human users authenticate via OIDC in the web app.
- Machines authenticate via scoped service tokens created from the web interface.

## Non-Goals (For Now)

- No immediate unified auth fabric with ratatoskr/forge.
- No requirement to proxy all blob bytes through the API.
- No attempt to make fencing strongly consistent over multi-master replication.
- No tight runtime coupling to ratatoskr internals.

## Service Model

Patchwork is a multi-tenant document backend where each document is represented by one SQLite database (`db_id`).

- APIs are scoped to explicit `db_id`s.
- Each DB runtime includes sync primitives as part of the document model.
- ACLs are evaluated at `db_id` + action (+ optional topic/resource scope).
- Wildcards are allowed in topic filters, but not in `db_id`.

## Capability Activation ("Duck Typing, but explicit")

Capabilities are activated only when both conditions hold:

1. Capability declared in metadata table.
2. Required capability tables/views are present.

```sql
CREATE TABLE IF NOT EXISTS patchwork_capabilities (
  capability TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  consistency_mode TEXT NOT NULL, -- single_writer | multi_master
  enabled INTEGER NOT NULL DEFAULT 1
);
```

This preserves flexibility while preventing accidental capability enablement from incidental table names.

## Capability: Query API

Purpose: controlled SQL access for scripts/webapps.

- Endpoint family: `/api/v1/db/:db_id/query/*`
- Allow parameterized SQL only.
- Optional statement class restrictions:
  - read-only tokens: `SELECT`, `EXPLAIN`
  - write-enabled tokens: constrained `INSERT/UPDATE/DELETE`
- Optional SQLite authorizer callback for table/column restrictions (sprite-oidc-db style).

Recommended modes:

- `query.read`
- `query.write`
- `query.admin` (schema migration/maintenance)

### Reactive Queries (SSE Watch)

Purpose: let clients subscribe to query results that update when underlying data changes.

#### Endpoint

- `POST /api/v1/db/:db_id/query/watch`
- Transport: SSE response stream
- Input: normal SQLite `SELECT` query + bind args + watch options

Example request shape:

```json
{
  "sql": "SELECT id, title, done FROM tasks WHERE project_id = ? ORDER BY id",
  "args": ["project-123"],
  "options": {
    "heartbeat_seconds": 15,
    "max_rows": 5000
  }
}
```

#### Event Model

- `snapshot`: first full result set after subscription creation.
- `update`: emitted when reevaluation produces a changed result hash.
- `heartbeat`: keepalive for idle periods.
- `error`: terminal or non-terminal watch execution errors.

Each `snapshot`/`update` event should include:

- canonical result payload
- `result_hash` (deterministic hash of canonical encoded rows)
- server sequence/cursor metadata

#### Execution Rules

- Watched statements must be read-only `SELECT`.
- Statement and result size limits are required.
- ACL must permit `query.read` for the target `db_id`.
- Query with unstable ordering should require explicit `ORDER BY` (or be documented as potentially noisy).

#### Change Detection Strategy

Prototype-first phased strategy:

1. **v0 (simple/correct)**: reevaluate all active watches on any successful write commit.
2. **v1 (table-aware)**: track table dependencies and reevaluate only affected watches.
3. **v2 (optional optimization)**: row/delta-aware optimizations for large watch sets.

Implementation guidance:

- Prefer generic DB change tracking over per-watch trigger generation.
- Keep an in-memory registry of active watches and last `result_hash`.
- On reevaluation, emit `update` only when hash changes.

#### Dependency Tracking

Acceptable mechanisms:

- SQL analysis / parser-assisted table dependency extraction.
- SQLite authorizer callback during prepared statement compilation.
- Conservative fallback to full reevaluation when dependencies are unknown.

## Optional Capability: SQLite Extension Bridge

Purpose: allow SQL-driven integrations (for example pubsub emits from triggers) while keeping service safety and operability.

### Safety Model

- Do not allow arbitrary user-controlled `load_extension`.
- Service loads only trusted extension code at startup (or compiles equivalent functions into process).
- Query API users can call approved SQL functions but cannot load native code.

### Upstream Configuration

Store upstream targets in an internal table scoped to DB/document:

```sql
CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,             -- e.g. "patchwork", "http"
  url TEXT NOT NULL,
  token_ref TEXT,                 -- reference to secret store entry
  enabled INTEGER NOT NULL DEFAULT 1,
  timeout_ms INTEGER NOT NULL DEFAULT 10000,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

Notes:

- `token_ref` should point to service-managed secrets, not expose plaintext tokens in normal query paths.
- Internal admin APIs should manage secret values.

### SQL Surface (Proposed)

- `patch_publish(topic, payload[, content_type])`:
  - enqueues message for local pubsub delivery.
- `patch_forward(upstream_id, topic, payload[, content_type])`:
  - enqueues outbound delivery to configured upstream.

These functions should be side-effect safe for SQL use by writing to internal outbox tables, not by doing direct network I/O inline.

### Outbox-Based Delivery

Use durable outbox workers for network and fanout side effects:

- SQL function writes an outbox row in the caller transaction.
- Background worker reads committed outbox rows and delivers.
- Retries with backoff and dead-letter handling.
- Delivery semantics: at-least-once (use `dedupe_key` for idempotency).

Recommended minimal outbox table:

```sql
CREATE TABLE IF NOT EXISTS pubsub_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,             -- local | upstream
  upstream_id TEXT,
  topic TEXT NOT NULL,
  payload BLOB NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/json',
  dedupe_key TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | inflight | done | failed
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### Trigger Ergonomics

Example pattern:

```sql
CREATE TRIGGER IF NOT EXISTS trg_tasks_publish
AFTER INSERT ON tasks
BEGIN
  SELECT patch_publish(
    'tasks/insert',
    json_object('id', NEW.id, 'title', NEW.title, 'done', NEW.done),
    'application/json'
  );
END;
```

This enables SQL-native event emission without coupling application code to transport details.

## Capability: Message PubSub API

Purpose: durable message-oriented pubsub inside a DB namespace, including MQTT-compatible topic semantics.

### Publish

- `POST /api/v1/db/:db_id/messages`
- Request includes:
  - `topic`
  - `payload` (bytes or JSON)
  - optional `content_type`
  - optional `dedupe_key`

### Message Constraints and Semantics

- Strict payload size limits are enforced for message publish APIs.
- v1 message payload limit: 1 MiB maximum request payload.
- Message publishes are durable: persist before successful publish acknowledgment.
- Replay is based on persisted message IDs (`since_id`/`tail`).
- Wildcard subscriptions are supported (`+`, `#`).
- MQTT integration includes last-will semantics in the message capability.
- No default TTL for retained/persistent message data; DB operators may define retention policies.

### Subscribe (SSE)

- `GET /api/v1/db/:db_id/events/stream`
- Query params:
  - `topic=<filter>` (repeat param allowed)
  - `since_id` (per-DB message cursor)
  - `tail=n` (optional)
- v1 scope is per-DB stream/replay only (no cross-DB replay cursor).

### Wildcard Semantics

- `db_id` must be explicit; no wildcard in DB selection.
- Topic filter supports MQTT-style wildcards:
  - `+` one segment
  - `#` rest-of-topic
- Wildcards apply only inside selected DB namespace.

### Minimal Storage

```sql
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  topic TEXT NOT NULL,
  payload BLOB NOT NULL,
  content_type TEXT NOT NULL DEFAULT 'application/json',
  producer TEXT,
  dedupe_key TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_topic_id ON messages(topic, id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
```

## Capability: Streams (Legacy Patchwork Behavior)

Purpose: preserve old Patchwork bytestream relay behavior for script ergonomics and efficient data proxying.

Streams are intentionally separate from message pubsub:

- no durability/replay guarantees
- no last-will/retained-message semantics
- no MQTT transport mapping
- no message wildcard subscription semantics
- optimized for efficient byte relay and passthrough headers
- no fixed application payload cap in v1 (service rate limits still apply)

Preserved behavior from old patchwork:

- blocking queue-style rendezvous
- non-blocking broadcast mode
- request/responder channel pattern
- passthrough metadata headers (`Patch-H-*`, `Patch-Status`)
- responder switch mode (`?switch=true`)

Proposed stream API shapes:

- Stream queue receive: `GET /api/v1/db/:db_id/streams/queue/:topic/next`
- Stream queue send: `POST /api/v1/db/:db_id/streams/queue/:topic`
- Stream request: `POST /api/v1/db/:db_id/streams/req/:path`
- Stream response: `POST /api/v1/db/:db_id/streams/res/:path`

Compatibility aliases should map legacy paths into this stream capability.

## Capability: Webhook Ingest (DB-scoped)

Purpose: accept external webhook deliveries and store them durably in the target DB.

Design choices:

- No dedicated `/h`/`/r` secret-hook behavior in v1.
- Access control uses normal DB-scoped auth rules on webhook endpoints.
- Webhook writers authenticate using standard `Authorization` headers and DB-scoped token scopes.
- No webhook secret needs to be stored in plaintext; token verification uses existing hash-based token storage.
- Webhook ingest is persist-first; there is no built-in consumer API in v1.
- Users consume webhook data using normal query APIs from DB tables.

Proposed API shape:

- `POST /api/v1/db/:db_id/webhooks/:endpoint`

Ingest behavior:

- Accept request body and metadata (`method`, headers, query, content type).
- Insert delivery into DB-local inbox table in one transaction.
- Return success only after insert commit.
- Request timeout behavior is standard HTTP server behavior; no extra webhook-specific timeout contract.

Recommended minimal inbox table:

```sql
CREATE TABLE IF NOT EXISTS webhook_inbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint TEXT NOT NULL,
  received_at TEXT NOT NULL,
  method TEXT NOT NULL,
  query_string TEXT,
  headers_json TEXT NOT NULL,
  content_type TEXT,
  payload BLOB NOT NULL,
  signature_valid INTEGER,
  delivery_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_webhook_inbox_endpoint_id
ON webhook_inbox(endpoint, id);
```

Schema extensibility requirement:

- Ingest code must insert using an explicit column list for required columns.
- Presence of extra columns in `webhook_inbox` must not break inserts.

HMAC request-signature validation is not part of MVP.
It can be added later as optional per-endpoint hardening.

## Capability: Fencing/Leases

Purpose: single-writer safety for workers and critical write paths.

Required behavior:

- `acquire(resource, owner, ttl)` returns monotonic `fence`.
- `renew(resource, owner, ttl)` keeps ownership; no fence decrement.
- `release(resource, owner)` best-effort explicit release.
- Protected operations must provide current fence.

Storage:

```sql
CREATE TABLE IF NOT EXISTS fencing_tokens (
  resource TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  token_hash BLOB NOT NULL,
  fence INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

Consistency constraints:

- Lease authority must be single-writer and linearizable.
- Lease authority is backed by local SQLite state for this service deployment (no external coordinator in MVP).
- Do not run fencing authority on multi-master CRDT replication.
- Use transactional SQLite lock discipline (`BEGIN IMMEDIATE`).

## Capability: Blob Control Plane

Purpose: remove raw S3 credentials from forge/related clients while preserving S3 performance.

### Model

- Service stores blob metadata, refs, and GC state.
- Service issues pre-signed URLs for direct S3 upload/download.
- Clients upload/download directly to object storage.
- Blob IDs are content hashes (`blake3`) and objects are content-addressed.
- No payload encryption for initial version.

### Why

- Central policy and ACL enforcement.
- No API bandwidth bottleneck for large objects.
- Reuse mature S3 multipart/caching behavior.
- Keep blob liveness scoping aligned to document databases.

### Minimal Blob API

- `POST /api/v1/db/:db_id/blobs/init-upload`
- `POST /api/v1/db/:db_id/blobs/complete-upload`
- `GET /api/v1/db/:db_id/blobs/:blob_id/read-url`
- `POST /api/v1/db/:db_id/blobs/:blob_id/claim`
- `POST /api/v1/db/:db_id/blobs/:blob_id/release`

### Addressing and Upload Rules

- Blob identifier: lowercase BLAKE3 digest (hex).
- Object key should be derived from hash (for example: `<prefix>/blobs/xx/<full-hash>`).
- Upload flow:
  1. Client requests upload intent for hash.
  2. Server returns pre-signed URL (or multipart plan).
  3. Client uploads object bytes directly.
  4. Client calls complete endpoint with hash + size metadata.
  5. Server verifies uploaded object content hash matches declared blob hash before marking complete.

### DB-Scoped Blob References

Blob keep-sets are document-scoped.

- Any DB can opt into blob GC participation by defining a `blobs` table.
- Presence in this table means "this hash must not be garbage collected" for that DB.

Recommended minimal keep-set table:

```sql
CREATE TABLE IF NOT EXISTS blobs (
  hash TEXT PRIMARY KEY,          -- blake3 hex digest
  created_at TEXT NOT NULL
);
```

### Global GC Model

GC is global across object storage but references are sourced from all DB keep-sets.

- Server maintains blob metadata index (hash, size, first_seen, last_seen, storage_key).
- Periodic GC job computes live hash union from all participating DBs (`SELECT hash FROM blobs`).
- Objects not in live union are eligible for deletion.
- Deletion is performed by server-side GC worker.

This keeps storage ownership and liveness anchored in DB/document scope.

### GC Race Handling

To avoid deleting in-flight uploads before references are written:

- GC should apply a minimum age/grace period for unreferenced objects.
- `complete-upload` should update blob metadata `first_seen`/`last_seen`.
- GC eligibility should require:
  - not referenced in any DB keep-set, and
  - older than configured grace period.

### Limits and Accounting (Initial Policy)

For v1:

- No per-DB hard quota enforcement in blob API.
- Primary protection is request rate limiting.
- Resource accounting and storage control are handled by periodic GC and metadata tracking.

Optional hardening (future):

- maximum single-object upload size
- per-token burst limits
- soft quota alerts without hard rejects
- inline proxy uploads for tiny payloads
- scan/transform hooks before finalize

## Auth and ACL

Identity and credential paths:

- Human/web authentication: OIDC-backed login/session in the web interface.
- Machine authentication: DB-scoped service tokens issued via the web interface.

Token model (local to this service for now):

- Token secret: random 128-bit minimum.
- Stored value: only cryptographic hash of token secret.
- Token scope:
  - `db_id`
  - action (query/pubsub/lease/blob/etc.)
  - optional `topic_prefix` or resource prefix
  - optional expiry
- Legacy Forgejo `.patchwork/config.yaml` ACL loading is not part of this service.

Suggested action set:

- `query.read`
- `query.write`
- `pub.publish`
- `pub.subscribe`
- `stream.read`
- `stream.write`
- `webhook.ingest`
- `queue.send`
- `queue.recv`
- `req.send`
- `res.send`
- `lease.acquire`
- `lease.renew`
- `lease.release`
- `blob.upload`
- `blob.read`
- `blob.claim`
- `admin.token`

## Transport

- HTTP/JSON for control plane APIs.
- SSE for server-to-client realtime streams and replay.
- MQTT (optional adapter) for message pubsub capability.

MQTT mapping rule:

- Topic shape includes explicit DB scope (for example `db/<db_id>/<topic...>`).
- Wildcard evaluation remains confined inside `db_id` scope.
- Last-will behavior is handled in the message pubsub path, not the stream path.

## Behavior carried forward from old patchwork

The old service provided valuable operational patterns that should be retained:

- channel-style script ergonomics
- stream semantics (blocking relay, broadcast mode, req/res)
- request/responder flow
- passthrough metadata headers

Migration approach:

1. Preserve `patch.tionis.dev`.
2. Expose canonical DB-scoped APIs only.
3. Use native service tokens from day one (no legacy `config.yaml` auth compatibility layer).
4. Do not provide legacy route aliases.

Compatibility parity targets for v1:

- stream script ergonomics (blocking relay + broadcast mode)
- request/responder flow including passthrough header behavior
- `Patch-H-*` passthrough and `Patch-Status` response status override
- responder switch (`?switch=true`) behavior

Out-of-scope for MVP:

- huproxy tunneling should stay separate unless explicitly reintroduced.

## Optional Capability: HuProxy Integration

If HuProxy-style tunneling is reintroduced, identity should be anchored in OIDC-provided SSH public keys.

### OIDC SSH Key Mapping

- Configure a multi-valued OIDC claim for SSH keys (default: `sshpubkey`).
- Claim values should be OpenSSH public key strings (authorized_keys format).
- Keys are bound to OIDC subject (`sub`) and refreshed on auth/session renewal.
- Service should cache resolved keys with a short TTL to avoid per-request IdP round trips.

### Authorization Model (HuProxy)

- Require explicit `huproxy.connect` scope (and host/port allowlist scope).
- Host access rules should remain token-scoped (`host:port` patterns).
- Optional hardening: require SSH signature challenge validation against OIDC keys in addition to bearer token.

### Audit Requirements

For each HuProxy session, log at least:

- subject/user identifier
- key fingerprint used (if signature mode enabled)
- target host and port
- decision outcome (allow/deny) and reason

## Data and Replication Strategy

- Per-document SQLite DB files.
- Optional `cr-sqlite` for multi-master document data replication.
- Fencing authority remains single-writer even if document data is multi-master.
- Backups can be handled independently from sync protocol (litestream/file snapshots/object copies).

## Integration Boundaries

- `forge`: use this service for coordination, messaging, controlled blob metadata flows.
- `ratatoskr`: remains Automerge collaboration backend; integrate only via external APIs when needed.
- `mimir + grafana`: observability and long-term metrics dashboards.
- `s3`: durable object storage data plane.

## Operations and Observability

Required endpoints:

- `/healthz`
- `/status`
- `/metrics` (Prometheus)

Recommended metrics:

- requests by endpoint/status/action
- publish/subscribe counts and fanout depth
- queue latency and delivery success
- lease acquire/renew conflict rates
- blob init/complete/read-url issuance counts

## Security Notes

- Hash stored tokens, never store plaintext.
- Enforce strict ACL checks before DB open/query execution.
- Bound query resources (time/rows/result bytes) per token scope.
- Validate topic filters and reject cross-DB wildcard attempts.
- Require fence validation for protected state transitions.

## Rollout Plan

1. Finalize naming and repo rename (`skald` -> `patchwork` if confirmed).
2. Implement core auth + capability activation + query read.
3. Implement message pubsub publish + SSE subscribe + replay.
4. Add stream (queue/req/res/broadcast) canonical endpoints.
5. Add lease/fencing API with single-writer authority.
6. Add blob control plane with pre-signed URL flows.
7. Publish API examples for canonical endpoints.
8. Add ansible deployment role updates in `projects/gandalf`.

## Open Questions

1. Do we need any migration aids beyond canonical DB-scoped routes?
2. Which capabilities are mandatory in v1 (`query + message pubsub + streams + lease`) and which are optional (`blob`)?
3. What retention policy is desired for `messages` per DB (size/time/count)?
4. Reactive query invalidation phase target at launch: v0 (global), v1 (table-aware), or mixed?
5. Do we keep/reintroduce the old webhook-proxy feature, and if yes should it be implemented as a stream capability or separate adapter?
6. If HuProxy is enabled, which OIDC claim name should be canonical for SSH keys (`sshpubkey` default?) and is signature challenge mandatory?
7. Should SQL extension bridge be in MVP, or staged after core query/pubsub/fencing APIs?
