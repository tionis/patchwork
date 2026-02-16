# Patchwork Sync Server (Working Folder: `skald`)

This directory is currently named `skald`, but the planned external/project name is `patchwork` with `patch.tionis.dev` as primary domain.

## Design Document

Canonical design and migration notes live in:

- `projects/skald/DESIGN.md`
- `projects/skald/FUTURE_CONSIDERATIONS.md` (deferred decisions/checklist)

That document includes:

- architecture decisions and scope
- capability model (query, reactive query watch/SSE, pubsub/fencing/hooks/blob control plane)
- compatibility strategy for legacy Patchwork endpoints
- auth/token/ACL model (service-local for now)
- migration and rollout phases

## Implemented API (Current)

### Webhook Ingest

- Route: `POST /api/v1/db/:db_id/webhooks/:endpoint`
- Auth: bearer token with `webhook.ingest` scope for the target `db_id`
- Behavior: request is persisted to `webhook_inbox` in the document DB and only acknowledged after commit

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

### Streams (Legacy Compatibility Core)

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
