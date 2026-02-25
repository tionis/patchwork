# Patchwork API Integration Guide (for LLMs and Tooling Agents)

This document is the integration contract for machine clients.
It is written to be directly actionable for LLM agents that need to call Patchwork APIs safely.

## 1. Core Concepts

- Patchwork is **DB-scoped**: almost every API is under `/api/v1/db/:db_id/...`.
- A `db_id` identifies one SQLite document runtime.
- `db_id` format: `^[A-Za-z0-9._-]{1,128}$`.
- DB runtime/doc file is created on first use.

Two messaging models exist and are intentionally different:

- **Durable message pubsub** (`/messages`, `/events/stream`):
  - message-based
  - persisted
  - replay (`since_id`, `tail`)
  - MQTT-style wildcard topic filters in subscribe
  - strict payload size limit (1 MiB)
- **Streams** (`/streams/...`):
  - byte-stream relay semantics (queue/request/response)
  - not durable
  - no app-level payload limit in server logic
  - efficient proxying, header passthrough semantics

## 2. Authentication and Authorization

### Token transport

Provide token in `Authorization` header:

- Preferred: `Authorization: Bearer <token>`
- Also accepted: `Authorization: token <token>`
- Also accepted: `Authorization: <token>`

### Scope model

Each token scope has:

- `db_id`
- `action`
- `resource_prefix` (optional)

Authorization logic:

- `db_id` and `action` must match exactly.
- If `resource_prefix` is set, requested resource must start with that prefix.
- Admin tokens bypass scope checks.

High-signal action map:

- `admin.token`: token management endpoints (`db_id="*"` for non-admin tokens)
- `query.read|query.write|query.admin`: SQL exec/watch/runtime status/open
- `pub.publish|pub.subscribe`: durable message publish and SSE subscribe
- `stream.read|stream.write`: stream queue/request/response endpoints
- `webhook.ingest`: webhook inbox ingest endpoint
- `lease.acquire|lease.renew|lease.release`: lease API
- `blob.upload|blob.read|blob.claim|blob.release|blob.publish`: blob APIs

Resource-prefix note for blob keep/unkeep:

- `keep` uses resource `keep/<blob_hash>`
- `unkeep` uses resource `unkeep/<blob_hash>`

### Admin APIs

Admin token endpoints require one of:

- a bearer principal authorized for `db_id="*"`, `action="admin.token"`
- or an OIDC web session whose subject is in configured admin subjects

## 3. Common HTTP Behavior

- Most DB-scoped JSON endpoints reject unknown fields.
- `POST /api/v1/admin/tokens` currently accepts additional JSON fields.
- Unauthorized auth: `401`.
- Authenticated but forbidden: `403`.
- Validation errors: `400`.
- Not found: `404`.
- Conflicts (e.g. lease held, blob incomplete): `409`.
- Payload limits: typically `413`.
- Rate limiting: `429` + `Retry-After: 1`.

## 4. Endpoint Index

## 4.1 Service and Admin

### `GET /healthz`

- Auth: none
- Returns: `{ "status": "ok" }`

### `GET /status`

- Auth: none
- Returns service uptime/runtime counts.

### `GET /metrics`

- Auth: none
- Prometheus text format.

### `GET /api/v1/admin/tokens`

- Auth: `admin.token` on `db_id="*"` (or OIDC admin session)
- Returns token metadata list.

### `POST /api/v1/admin/tokens`

- Auth: same as above
- Body:

```json
{
  "label": "worker-a",
  "is_admin": false,
  "expires_at": "2026-12-31T23:59:59Z",
  "scopes": [
    { "db_id": "public", "action": "query.read", "resource_prefix": "" }
  ]
}
```

- Returns `201` with plaintext token (only shown at creation).
- Validation:
  - `label` required, max 120 chars
  - non-admin tokens require at least one scope
  - `expires_at` must be in the future if provided

### `DELETE /api/v1/admin/tokens/:id`

- Auth: same as above
- Returns `204`.

## 4.2 DB Runtime

### `POST /api/v1/db/:db_id/_open`

- Auth: `query.read`
- Ensures runtime is open.

### `GET /api/v1/db/:db_id/_status`

- Auth: `query.read`
- Returns db path and health.

## 4.3 Query API

### `POST /api/v1/db/:db_id/query/exec`

Body:

```json
{
  "sql": "SELECT id, name FROM items WHERE id = ?",
  "args": [123]
}
```

Rules:

- Exactly one SQL statement (no multi-statement payload).
- Statement class controls required scope:
  - read (`SELECT`, `EXPLAIN`, `WITH`) -> `query.read`
  - write (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`) -> `query.write`
  - all others -> `query.admin`

Limits:

- execution timeout: 5s
- max rows: 5000
- max JSON result bytes: 1 MiB

Responses:

- read: columns + rows + row_count + result_bytes
- non-read: rows_affected + last_insert_id

### `POST /api/v1/db/:db_id/query/watch`

Body:

```json
{
  "sql": "SELECT id, status FROM jobs ORDER BY id",
  "args": [],
  "options": {
    "heartbeat_seconds": 15,
    "max_rows": 5000
  }
}
```

Rules:

- read-only SQL only
- SSE response stream

SSE events:

- `snapshot` (initial result)
- `update` (on changed result hash)
- `heartbeat`
- `error`

Payload structure for `snapshot`/`update`:

```json
{
  "columns": ["id", "status"],
  "rows": [[1, "ok"]],
  "row_count": 1,
  "result_hash": "..."
}
```

## 4.4 Durable Message PubSub

### `POST /api/v1/db/:db_id/messages`

- Auth: `pub.publish` (resource = topic)
- Topic rules:
  - required
  - max 255 chars
  - cannot start/end with `/`
  - cannot contain `+` or `#`

Body: exactly one payload field must be present:

```json
{
  "topic": "jobs/events",
  "payload": { "kind": "started", "job_id": 42 },
  "content_type": "application/json",
  "producer": "worker-1",
  "dedupe_key": "job-42-start"
}
```

Alternative payload fields:

- `payload_base64` (binary)
- `payload_text` (plain text)

Limit:

- payload max 1 MiB

### `GET /api/v1/db/:db_id/events/stream`

- Auth: `pub.subscribe`
  - if topic filters are present, each filter is authorized as resource
  - no filters -> resource `""`
- SSE stream of durable messages

Query params:

- `topic=<filter>` repeatable
- `since_id=<non-negative int>`
- `tail=<non-negative int, <=1000>`
- `since_id` and `tail` cannot be combined

Filter rules:

- supports MQTT wildcards `+`, `#`
- `#` must be an entire final path segment

SSE event types:

- `message` with SSE `id` set to message id
- `heartbeat`

`message` data payload:

```json
{
  "id": 120,
  "topic": "jobs/events",
  "content_type": "application/json",
  "payload_base64": "...",
  "producer": "worker-1",
  "dedupe_key": "job-42-start",
  "created_at": "2026-02-25T18:30:00.000000000Z"
}
```

## 4.5 Leases / Fencing

### `POST /api/v1/db/:db_id/leases/acquire`

- Auth: `lease.acquire` (resource = `resource`)

Body:

```json
{
  "resource": "sync/primary",
  "owner": "worker-a",
  "ttl_seconds": 30
}
```

Rules:

- `ttl_seconds` default 30
- valid range: 1..3600

Returns fence token pair.

### `POST /api/v1/db/:db_id/leases/renew`

- Auth: `lease.renew`
- Requires resource + owner + token (+ optional ttl).

### `POST /api/v1/db/:db_id/leases/release`

- Auth: `lease.release`
- Requires resource + owner + token.

## 4.6 Webhook Inbox

### `POST /api/v1/db/:db_id/webhooks/:endpoint`

- Auth: `webhook.ingest` (resource = normalized endpoint path)
- Any payload/content-type accepted.
- Persist-first semantics: returns success only after DB commit.
- Headers are stored with sensitive headers redacted (`Authorization`, cookies).
- Data lands in `webhook_inbox`.

## 4.7 Streams (Bytestream transport)

Queue:

- consume next: `GET /api/v1/db/:db_id/streams/queue/:topic/next` (`stream.read`)
- send: `POST|PUT /api/v1/db/:db_id/streams/queue/:topic` (`stream.write`)

Request/response:

- requester: `POST|PUT /api/v1/db/:db_id/streams/req/:path` (`stream.write`)
- responder: `POST|PUT /api/v1/db/:db_id/streams/res/:path` (`stream.write`)
- responder switch mode: `?switch=true`

Semantics:

- body is treated as raw bytes
- request headers can be forwarded via `Patch-H-*`
- responder can set `Patch-Status` to control HTTP status code
- queue publish-style fanout: add `?pubsub=true` on queue send

Only canonical DB-scoped stream routes are supported:

- `/api/v1/db/:db_id/streams/queue/...`
- `/api/v1/db/:db_id/streams/req/...`
- `/api/v1/db/:db_id/streams/res/...`

## 4.8 Blobs and Archival

Blob object hash is SHA-256 hex (64 chars).

### Upload flow

1. `POST /api/v1/db/:db_id/blobs/init-upload` (`blob.upload`)
2. `PUT /api/v1/db/:db_id/blobs/upload/:blob_id` (`blob.upload` or valid signed URL)
3. `POST /api/v1/db/:db_id/blobs/complete-upload` (`blob.upload`)

`complete-upload` verifies staged bytes hash equals requested hash.

Data-plane upload limit:

- 256 MiB per upload request

### Read/list

- `GET /api/v1/db/:db_id/blobs/list` (`blob.read`)
  - query: `limit` (1..1000, default 100), `status` (`pending|complete|failed`)
- `GET /api/v1/db/:db_id/blobs/:blob_id/read-url` (`blob.read`)
- `GET /api/v1/db/:db_id/blobs/object/:blob_id` (`blob.read` or valid signed URL)

### Claim/release (GC references)

- `POST /api/v1/db/:db_id/blobs/:blob_id/claim` (`blob.claim`)
- `POST /api/v1/db/:db_id/blobs/:blob_id/release` (`blob.release`)

### Keep-set metadata

- `POST /api/v1/db/:db_id/blobs/:blob_id/keep` (`blob.upload`)
- `POST /api/v1/db/:db_id/blobs/:blob_id/unkeep` (`blob.upload`)

`keep` request body (optional):

```json
{
  "filename": "article.html",
  "description": "Snapshot",
  "tags": ["archive/news", "singlefile"],
  "replace_tags": false
}
```

Tag normalization:

- lowercased
- duplicates removed
- comma/newline/tab-separated values are split

### Public permalink publication

- `POST /api/v1/db/:db_id/blobs/:blob_id/publish` (`blob.publish`)
- `POST /api/v1/db/:db_id/blobs/:blob_id/unpublish` (`blob.publish`)
- `GET /o/:blob_hash` (public)
- `HEAD /o/:blob_hash` (public)

Public object response headers:

- `Cache-Control: public, max-age=31536000, immutable`
- `ETag: "<hash>"`
- `Accept-Ranges: bytes`

### SingleFile ingest endpoint

- `POST /api/v1/db/:db_id/apps/singlefile/rest-form` (`blob.upload`)
- multipart/form-data
- file field:
  - default `file`
  - override with `?file_field=<name>`
- source URL field:
  - default `url`
  - override with `?url_field=<name>`
- optional metadata fields:
  - `description` (override key with `?description_field=<name>`)
  - tags via `tags` / `tag` (override key with `?tags_field=<name>`)

Returns `201` with URLs (`url`, `read_url`, `cdn_url`) and blob metadata.

## 5. Blob Signed URL Mode

If `PATCHWORK_BLOB_SIGNING_KEY` is configured:

- `init-upload` and `read-url` return signed URLs
- signed URLs include query params:
  - `exp` (unix seconds expiry)
  - `sig` (HMAC-SHA256 signature)
- signed data-plane requests are valid until expiry and do not require bearer auth

If signing key is absent, data-plane routes require bearer auth.

## 6. Recommended Client Strategy

- Always send explicit `Content-Type`.
- For JSON APIs, send only documented fields.
- Handle `401`, `403`, `429`, and retryable `5xx` distinctly.
- For SSE endpoints, implement reconnect with:
  - pubsub: persist last seen message id and reconnect via `since_id`
  - query watch: reconnect by re-opening watch request
- For blobs, treat upload as a 3-step transaction (`init -> upload -> complete`).

## 7. End-to-End cURL Flows

## 7.1 Issue a scoped machine token

```bash
curl -sS -X POST "${BASE_URL}/api/v1/admin/tokens" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "llm-client",
    "is_admin": false,
    "scopes": [
      {"db_id":"public","action":"query.read"},
      {"db_id":"public","action":"query.write"},
      {"db_id":"public","action":"pub.publish"},
      {"db_id":"public","action":"pub.subscribe"}
    ]
  }'
```

## 7.2 Execute SQL

```bash
curl -sS -X POST "${BASE_URL}/api/v1/db/public/query/exec" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"sql":"SELECT 1 AS ok","args":[]}'
```

## 7.3 Publish and subscribe durable messages

```bash
curl -sS -X POST "${BASE_URL}/api/v1/db/public/messages" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"topic":"jobs/events","payload":{"kind":"ping"}}'

curl -N "${BASE_URL}/api/v1/db/public/events/stream?topic=jobs/%23&tail=10" \
  -H "Authorization: Bearer ${TOKEN}"
```

## 7.4 Upload and publish a blob

```bash
BLOB_HASH="$(sha256sum archive.html | awk '{print $1}')"

INIT_JSON="$(curl -sS -X POST "${BASE_URL}/api/v1/db/public/blobs/init-upload" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"hash\":\"${BLOB_HASH}\",\"content_type\":\"text/html\"}")"

UPLOAD_URL="$(printf '%s' "$INIT_JSON" | jq -r '.upload_url')"

curl -sS -X PUT "${BASE_URL}${UPLOAD_URL}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: text/html" \
  --data-binary @archive.html

curl -sS -X POST "${BASE_URL}/api/v1/db/public/blobs/complete-upload" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"hash\":\"${BLOB_HASH}\"}"

curl -sS -X POST "${BASE_URL}/api/v1/db/public/blobs/${BLOB_HASH}/publish" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}'

curl -I "${BASE_URL}/o/${BLOB_HASH}"
```

## 8. Tables You Can Query in Each Document DB

Commonly relevant tables:

- `messages`
- `retained_messages`
- `queued_session_messages`
- `fencing_tokens`
- `webhook_inbox`
- `blob_metadata`
- `blob_claims`
- `blobs`
- `blob_tags`
- `app_singlefile_uploads`

Service DB also contains:

- `documents`
- `auth_tokens`, `auth_token_scopes`
- `web_identities`, `web_sessions`
- `public_blob_exports`
