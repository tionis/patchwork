# Patchwork Sync Server (Working Folder: `skald`)

This directory is currently named `skald`, but the planned external/project name is `patchwork` with `patch.tionis.dev` as primary domain.

## Design Document

Canonical design and migration notes live in:

- `projects/skald/DESIGN.md`
- `projects/skald/FUTURE_CONSIDERATIONS.md` (deferred decisions/checklist)
- `projects/skald/ops/RUNBOOK.md` (operations runbook)
- `projects/skald/LLM_API.md` (API integration guide for LLM/tooling clients)

That document includes:

- architecture decisions and scope
- capability model (query, reactive query watch/SSE, pubsub/fencing/hooks/blob control plane)
- auth/token/ACL model (service-local for now)
- migration and rollout phases

## Implemented API (Current)

### DB ID Rules

- All DB-scoped APIs use `:db_id` in the route.
- `db_id` must match: `^[A-Za-z0-9._-]{1,128}$`
- DB runtimes/documents are created on-demand when first used.

### Runtime Endpoints

- Open/ensure runtime: `POST /api/v1/db/:db_id/_open` (`query.read`)
- Runtime health/path: `GET /api/v1/db/:db_id/_status` (`query.read`)

### Webhook Ingest

- Route: `POST /api/v1/db/:db_id/webhooks/:endpoint`
- Auth: bearer token with `webhook.ingest` scope for the target `db_id`
- Behavior: request is persisted to `webhook_inbox` in the document DB and only acknowledged after commit
- HMAC/signature checks are not enforced by default in MVP, but a server-side validation hook exists for future provider-specific verification.

Stored columns (explicit insert list):

- `endpoint`
- `received_at`
- `method`
- `query_string`
- `headers_json` (`Authorization`/cookie headers are redacted)
- `content_type`
- `payload`
- `signature_valid` (currently `NULL`, reserved for future HMAC validation)
- `delivery_id` (best-effort extracted from common webhook delivery headers)

Example ingest:

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data '{"event":"push"}' \
  "http://localhost:8080/api/v1/db/public/webhooks/github/push?ref=main"
```

Example query-based consumption:

```sql
SELECT id, endpoint, received_at, method, content_type, payload
FROM webhook_inbox
ORDER BY id DESC
LIMIT 100;
```

### Streams

- Queue receive: `GET /api/v1/db/:db_id/streams/queue/:topic/next`
- Queue send: `POST /api/v1/db/:db_id/streams/queue/:topic`
- Requester: `POST /api/v1/db/:db_id/streams/req/:path`
- Responder: `POST /api/v1/db/:db_id/streams/res/:path`
- Auth scopes:
  - queue receive: `stream.read`
  - queue send/request/responder: `stream.write`

Supported stream behaviors:

- blocking rendezvous queue (producer waits for consumer)
- request/responder flow with `Patch-H-*` passthrough + `Patch-Status`
- switch mode on responder (`?switch=true`) for dynamic response channel handoff
- optional non-blocking broadcast on queue send via `?pubsub=true`

Use canonical DB-scoped routes under `/api/v1/db/:db_id/streams/...`.

### Durable Messages (Publish)

- Route: `POST /api/v1/db/:db_id/messages`
- Auth: bearer token with `pub.publish` scope for target `db_id`
- Durability: message is inserted into SQLite `messages` table before `201 Created` is returned
- Payload limit: `1 MiB` maximum payload bytes

Accepted payload shapes (exactly one):

- `payload` (raw JSON value, stored as bytes)
- `payload_base64` (decoded to bytes)
- `payload_text` (stored as UTF-8 text bytes)

### Durable Messages (SSE Subscribe)

- Route: `GET /api/v1/db/:db_id/events/stream`
- Auth: bearer token with `pub.subscribe` scope for target `db_id`
- Query parameters:
  - repeated `topic=<filter>` (MQTT wildcards supported: `+`, `#`)
  - `since_id=<message_id>` for replay from a cursor
  - `tail=<n>` for replay of the latest `n` messages (max `1000`)
  - `since_id` and `tail` are mutually exclusive

SSE event types:

- `message` (contains persisted message metadata + base64 payload)
- `heartbeat` (keepalive)

### Persistent Session Groundwork

The document migration now includes schema groundwork for future MQTT/session durability:

- `retained_messages`
- `queued_session_messages`

No default TTL policy is applied by the service. `expires_at` is nullable and retention remains operator/DB-defined.

### Query API (Exec)

- Route: `POST /api/v1/db/:db_id/query/exec`
- Request shape:

```json
{
  "sql": "SELECT id, name FROM items WHERE id = ?",
  "args": [123]
}
```

Statement class to scope mapping:

- read statements (`SELECT`, `EXPLAIN`, `WITH`) -> `query.read`
- write statements (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`) -> `query.write`
- admin statements (`CREATE`, `ALTER`, `DROP`, `PRAGMA`, etc.) -> `query.admin`

Current resource bounds:

- max execution time: `5s`
- max rows returned: `5000`
- max JSON result bytes: `1 MiB`
- multiple SQL statements in one request are rejected

### Query API (Reactive Watch)

- Route: `POST /api/v1/db/:db_id/query/watch`
- Request shape:

```json
{
  "sql": "SELECT id, name FROM items ORDER BY id",
  "args": [],
  "options": {
    "heartbeat_seconds": 15,
    "max_rows": 5000
  }
}
```

Behavior:

- read-only statements only
- SSE events: `snapshot`, `update`, `heartbeat`, `error`
- `result_hash` is deterministic (hash over canonical `columns + rows` JSON)
- v0 invalidation: active watches are reevaluated on committed document writes

### Lease / Fencing API

Routes:

- `POST /api/v1/db/:db_id/leases/acquire`
- `POST /api/v1/db/:db_id/leases/renew`
- `POST /api/v1/db/:db_id/leases/release`

Auth scopes:

- `lease.acquire`
- `lease.renew`
- `lease.release`

Behavior:

- acquire returns a monotonic `fence` and a lease token (token hash persisted)
- renew keeps the same fence and extends expiry when owner+token match
- release requires owner+token match
- transactional lease updates use `BEGIN IMMEDIATE` lock discipline
- `ValidateLeaseFence(...)` exists as an internal hook for protected operations

### Token Management UI

- Route: `GET /ui/tokens`
- Provides a lightweight admin page for machine token create/list/revoke flows against:
  - `GET /api/v1/admin/tokens`
  - `POST /api/v1/admin/tokens`
  - `DELETE /api/v1/admin/tokens/:id`
- Admin API auth:
  - bearer principal with `db_id="*"`, `action="admin.token"` (or admin token)
  - or OIDC web session for configured admin subjects
- Plaintext token is only shown in the create response payload.
- OIDC login flow is available via:
  - `GET /auth/oidc/login`
  - `GET /auth/oidc/callback`
  - `GET /auth/logout`
- When OIDC is configured, web sessions are stored in `web_sessions` and allowed OIDC subjects can manage machine tokens without pasting a bearer token in the UI.

### Blob Control Plane

Document migration now includes initial blob-control tables:

- `blob_metadata`
- `blob_claims`
- `blobs` (keep-set metadata: filename/description + archival pin)
- `blob_tags` (tag-indexed keep-set labels)
- `app_singlefile_uploads`

Service metadata table used for CDN-style publication tracking:

- `public_blob_exports`

Blob management UI:

- Route: `GET /ui/blobs`
- Includes DB-scoped blob listing and a multipart upload form targeting the SingleFile endpoint.

Current blob API routes:

- `POST /api/v1/db/:db_id/blobs/init-upload`
- `PUT /api/v1/db/:db_id/blobs/upload/:blob_id`
- `POST /api/v1/db/:db_id/blobs/complete-upload`
- `GET /api/v1/db/:db_id/blobs/list`
- `GET /api/v1/db/:db_id/blobs/:blob_id/read-url`
- `GET /api/v1/db/:db_id/blobs/object/:blob_id`
- `POST /api/v1/db/:db_id/blobs/:blob_id/claim`
- `POST /api/v1/db/:db_id/blobs/:blob_id/release`
- `POST /api/v1/db/:db_id/blobs/:blob_id/keep`
- `POST /api/v1/db/:db_id/blobs/:blob_id/unkeep`
- `POST /api/v1/db/:db_id/blobs/:blob_id/publish`
- `POST /api/v1/db/:db_id/blobs/:blob_id/unpublish`
- `POST /api/v1/db/:db_id/apps/singlefile/rest-form`
- `GET /o/:blob_hash` (public CDN-style permalink for published blobs)
- `HEAD /o/:blob_hash`

Blob scope summary:

- `blob.upload`: init/upload/complete, keep/unkeep, singlefile ingest
- `blob.read`: list/read-url/object
- `blob.claim`: claim
- `blob.release`: release
- `blob.publish`: publish/unpublish

`complete-upload` verifies the staged blob hash before marking metadata as `complete`.

SingleFile REST Form integration:

- Endpoint accepts `multipart/form-data` and returns JSON with `url`/`read_url`/`blob_id`.
- Works with SingleFile's configurable file/url field names.
- Requires bearer auth with `blob.upload` scope for target DB.
- Persists upload metadata in `app_singlefile_uploads` for audit/manage workflows.
- Uploaded blobs are pinned by default in the DB keep-set (`blobs`) for long-term archiving.
- Optional form fields are supported for archival metadata (`description`, `tags`/`tag`).

Blob signed URL support:

- If `PATCHWORK_BLOB_SIGNING_KEY` is configured, `init-upload` and `read-url` return signed data-plane URLs.
- Signed upload/object URLs can be used without a bearer token until `PATCHWORK_BLOB_SIGNED_URL_TTL` expires.
- If blob signing is not configured, upload/object routes require normal bearer-token authorization.

Current storage backend uses local disk paths under the service data dir (`blobs/` and `blob-staging/`) with signed URL semantics layered on top of those routes.

Background GC:

- started automatically with the server process
- unions live hashes from per-DB `blobs` tables and active `blob_claims`
- includes hashes from active `public_blob_exports` to protect published objects
- removes unreferenced object files older than configured grace period

Load-oriented integration tests now cover:

- query-watch behavior under concurrent write churn
- durable message replay fanout across multiple subscribers
- high-concurrency stream queue producer/consumer flow

Chaos-oriented integration tests now cover:

- DB runtime idle cleanup and restart
- webhook transaction rollback on forced insert failure
- lease renew contention behavior
- blob finalize vs GC safety window

### Request Rate Limiting

Rate limiting middleware is enabled with configurable global and per-token buckets:

- `PATCHWORK_RATE_LIMIT_GLOBAL_RPS`
- `PATCHWORK_RATE_LIMIT_GLOBAL_BURST`
- `PATCHWORK_RATE_LIMIT_TOKEN_RPS`
- `PATCHWORK_RATE_LIMIT_TOKEN_BURST`

Set an `*_RPS` value to `0` to disable that limiter.

### Sync Scaffolding

The document runtime now exposes minimal sync boundaries for future transport work:

- `ExportSnapshot(ctx, dbID, writer)` on `docruntime.Manager`
- `SubscribeChanges(ctx, dbID, buffer)` change-feed subscription
- `RegisterSyncTransportHook(hook)` for adapter-specific event forwarding

### SQLite Driver and Extensions

Patchwork now uses `github.com/mattn/go-sqlite3` via an internal driver registration package (`internal/sqlitedriver`) and keeps the SQL driver name as `sqlite`.

Operational implications:

- build requires `CGO_ENABLED=1` and a C toolchain on the build host
- SQLite compile options are checked once at first DB connection via `PRAGMA compile_options`
- missing recommended options are logged by default
- startup can be made strict with `PATCHWORK_SQLITE_REQUIRED_COMPILE_OPTIONS`

Recommended compile options (current default warning set):

- `ENABLE_FTS5`
- `ENABLE_SESSION`
- `ENABLE_PREUPDATE_HOOK`
- `ENABLE_SNAPSHOT`
- `ENABLE_RBU`
- `ENABLE_ICU`
- `ENABLE_RTREE`
- `ENABLE_GEOPOLY`

Default extension load attempts per connection:

- cr-sqlite candidates: `crsqlite`, `crsqlite0` (+ `lib*` and platform suffix variants)
- sqlite-vec candidates: `vec0`, `sqlite_vec` (+ `lib*` and platform suffix variants)
- sqlean bundle candidate: `sqlean` (+ `lib*` and platform suffix variants)
- optional safe sqlean module set (`crypto`, `math`, `regexp`, `stats`, `text`, `time`, `unicode`, `uuid`) via `PATCHWORK_SQLITE_EXTENSION_SQLEAN_DIR`

Extension env behavior:

- explicit `PATCHWORK_SQLITE_EXTENSION_*` paths are treated as required
- optional/default discovery logs one-time warnings if no candidate loads
- extra required extensions can be listed with `PATCHWORK_SQLITE_EXTENSIONS` (`path` or `path|entrypoint`, comma-separated)

Build example (non-ICU):

```bash
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_SNAPSHOT -DSQLITE_ENABLE_RBU -DSQLITE_ENABLE_GEOPOLY -DSQLITE_ENABLE_RTREE" \
go build -tags "sqlite_fts5 sqlite_preupdate_hook sqlite_vtable" -o patchwork ./cmd/patchwork
```

For ICU-enabled builds, add `sqlite_icu` to tags and provide ICU link flags/libs on your build host.

### SQLite Extension Tests

`internal/sqlitedriver/driver_test.go` includes:

- deterministic tests for required compile-option and required-extension failure behavior
- integration probes for cr-sqlite, sqlite-vec, and sqlean functionality

Run integration probes by providing extension paths through test env vars:

- `PATCHWORK_SQLITE_TEST_CRSQLITE_PATH` (optional `PATCHWORK_SQLITE_TEST_CRSQLITE_ENTRYPOINT`)
- `PATCHWORK_SQLITE_TEST_VEC_PATH` (optional `PATCHWORK_SQLITE_TEST_VEC_ENTRYPOINT`)
- `PATCHWORK_SQLITE_TEST_SQLEAN_PATH` (optional `PATCHWORK_SQLITE_TEST_SQLEAN_ENTRYPOINT`)
- or `PATCHWORK_SQLITE_TEST_SQLEAN_DIR` for sqlean module-directory loading

Example:

```bash
PATCHWORK_SQLITE_TEST_CRSQLITE_PATH=/opt/patchwork/extensions/crsqlite \
PATCHWORK_SQLITE_TEST_VEC_PATH=/opt/patchwork/extensions/vec0 \
PATCHWORK_SQLITE_TEST_SQLEAN_PATH=/opt/patchwork/extensions/sqlean \
go test ./internal/sqlitedriver -v
```
