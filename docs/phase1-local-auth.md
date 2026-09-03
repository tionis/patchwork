# Phase 1 spec — local identity & token management

Goal (from `TODO.md`): no secret lives in a git repo; tokens are issuable,
rotatable, and revocable from one place; revocation is immediate. Guiding
goal: simple, fast, maintainable. No backwards compatibility is owed.

## Current shape (what gets replaced)

- Per-user auth is a `UserAuth{Tokens map[string]TokenInfo, Ntfy NtfyConfig}`
  fetched from Forgejo (`<user>/.patchwork/config.yaml`), cached in `AuthCache`
  with `ACL_TTL`/`ACL_STALE_GRACE`, coalesced per user (`main.go`).
- `TokenInfo`: `is_admin`, per-method OpenSSH-style pattern lists
  (`GET/POST/PUT/DELETE/PATCH`), `huproxy` list, optional `expires_at`.
- Missing bearer on `/u/{username}/...` selects a literal token named
  `public`. Admin endpoints (`/_/invalidate_cache`) require `is_admin`.
- Ntfy backend config rides in the same document.

Everything above keeps its semantics; only the source changes from
Forgejo-repo-file to local sqlite.

## Storage

- Engine: `modernc.org/sqlite` (pure Go, no cgo — the Podman cross-builds
  were just made host-independent; `mattn/go-sqlite3` would regress that).
  New vendored dependency; Phase 1 is the sanction for it.
- Location: single file, `PATCHWORK_DB_PATH` (default `./patchwork.db`),
  `0600`. Backups are plain file copies through the existing ansible setup —
  no litestream. The operator bind-mounts/volumes it wherever the deployment
  needs it; the exact path is documentation, not code. WAL mode on; single
  writer (admin API), readers on every data-plane request.
- Lookup is direct per request (prepared statements, indexed); **no TTL or
  stale-grace cache**. This is what makes revocation immediate and deletes
  the `AuthCache` refresh/coalescing machinery outright.

```sql
CREATE TABLE users (
  id          TEXT PRIMARY KEY,            -- local username, also the {username} in /u/...
  display_name TEXT NOT NULL DEFAULT '',
  is_admin    INTEGER NOT NULL DEFAULT 0,
  active      INTEGER NOT NULL DEFAULT 1,
  oidc_sub    TEXT UNIQUE,                 -- Authentik subject, NULL until first OIDC login
  scim_id     TEXT UNIQUE,                 -- inbound SCIM external id, NULL unless provisioned
  created_at  TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE tokens (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,               -- includes the literal "public" convention
  prefix      TEXT NOT NULL,               -- public lookup hint, e.g. leftmost 8 chars
  token_hash  TEXT NOT NULL UNIQUE,        -- sha256 hex of the bearer; plaintext never stored
  is_admin    INTEGER NOT NULL DEFAULT 0,
  patterns    TEXT NOT NULL DEFAULT '{}',  -- JSON: GET/POST/PUT/DELETE/PATCH/huproxy string lists
  expires_at  TEXT,
  last_used_at TEXT,
  revoked_at  TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_tokens_hash ON tokens(token_hash);
CREATE TABLE ntfy_configs (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  type    TEXT NOT NULL, config TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE groups (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  scim_id      TEXT UNIQUE,               -- inbound SCIM external id
  created_at   TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT ''
);
```

- Pattern JSON reuses the existing `sshUtil.Pattern` compile path, so
  `validateToken` logic moves almost verbatim; only the fetch layer changes.
- Token plaintext format: `pw_` + 32 bytes base64url (from `crypto/rand`).
  API returns it once at creation; only hash + prefix persist.

## Data-plane changes (small)

- `authenticateToken`/`validateToken` resolve `(username, bearer)` against
  sqlite instead of `AuthCache`. Missing bearer still selects the literal
  `public` token. `expires_at` and `revoked_at` both deny.
- `userNtfyHandler` reads `ntfy_configs` instead of the yaml document.
- Delete: `AuthCache`, Forgejo fetch, `ACL_TTL`/`ACL_STALE_GRACE`,
  `FORGEJO_URL`/`FORGEJO_TOKEN`, `/_/invalidate_cache` (nothing to
  invalidate). `last_used_at` updates are best-effort and never fail a
  request: a plain synchronous `UPDATE` whose error is logged and dropped.
  No batching, no background flusher — at personal scale the write is noise
  and the field is informational. Batch only if lock contention is ever
  measured.
- This is also the moment to land the empty `internal/*` split: new
  `internal/auth` (store + validation), `internal/config` (env), with
  handlers following. Touching every auth call site anyway; don't add a
  second auth system onto the monolith.

## Admin API (first-class, versioned)

Base `/api/v1`, authenticated by WebUI session cookie (below). Admin-only
except `GET /api/v1/auth/me`. JSON throughout; failures are RFC 7807-style
`{type,title,status,detail}` — no new error idiom elsewhere.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET/POST` | `/api/v1/users` | list / create user |
| `GET/PATCH/DELETE` | `/api/v1/users/{id}` | inspect, rename/admin-flag/deactivate |
| `GET/POST` | `/api/v1/users/{id}/tokens` | list metadata (never hashes) / issue token (plaintext once) |
| `POST` | `/api/v1/users/{id}/tokens/{tid}/rotate` | new plaintext, old hash revoked atomically |
| `POST` | `/api/v1/users/{id}/tokens/{tid}/revoke` | immediate |
| `GET/PUT` | `/api/v1/users/{id}/ntfy` | notification backend config |
| `GET` | `/api/v1/audit` | filterable audit events |
| `GET/DELETE` | `/api/v1/sessions` (+`/{id}`) | list / revoke sessions |
| `GET` | `/api/v1/groups` (+`/{id}`) | list groups / group with member list (read-only; membership is managed via SCIM) |

Every mutation writes an `audit_events` row. The WebUI is a thin consumer of
exactly this API (same binary, existing `assets/` embed) — no parallel
server-rendered mutation path.

## WebUI sessions (OIDC)

- Standard code flow with PKCE against `PATCHWORK_OIDC_ISSUER`
  (`client_id`/`client_secret` from env), callback at
  `/api/v1/auth/callback`. New vendored deps: `golang.org/x/oauth2` +
  `github.com/coreos/go-oidc` (minimal viable pair; no framework).
- On callback: match `sub` → `users.oidc_sub` (link on first login for an
  existing username only via explicit admin action — never auto-create
  admins). `is_admin` is managed locally, never taken from claims.
- Session: 128-bit opaque id in `sessions`, cookie `Secure`/`HttpOnly`/
  `SameSite=Lax`, 12h expiry sliding, revocable via the API. No JWT
  session state, nothing to rotate.
- Bootstrap problem (first admin, no users yet): `patchwork admin
  create --username ... --oidc-sub ...` CLI subcommand run against
  `PATCHWORK_DB_PATH` (fits the existing `cli/v2` shape next to
  `start`/`healthcheck`). No env-bootstrap secrets, no setup-token dance.
- Data plane never touches OIDC: daemons keep bearer tokens. OIDC is a
  WebUI-login concern only.

## SCIM (optional capability, off by default)

- Gated by `PATCHWORK_SCIM_ENABLED=true` + `PATCHWORK_SCIM_TOKEN`
  (bearer on the SCIM endpoints). Zero cost when off: no routes, no code in
  the request path.
- Minimal RFC 7644 subset for Users and Groups. Users: `POST /scim/v2/Users`
  (create, honoring `externalId` → `scim_id`, `active`), `PUT`/`PATCH`
  (replace, including deactivate), `GET` (standard `filter` on
  `userName`/`externalId` plus `ListResponse` pagination for the provider's
  reconciliation reads). Groups: `POST /scim/v2/Groups` (create with
  `members`), `PUT`/`PATCH` (replace, including member list), `GET`
  (filter on `displayName`, `ListResponse` pagination); member references
  resolve by SCIM id or `userName`. SCIM is a standard — implement the
  standard operations, no house-dialect capture needed. Acceptance is a
  successful provisioning/deprovisioning run against Authentik, not
  pre-recorded request shapes.
- Groups are synced for future group-based ACLs; Phase 1 stores and serves
  membership but enforces nothing from it.

## Cutover

1. Deploy with empty DB; `patchwork admin create` the first admin.
2. Re-issue tokens via admin API; update daemons/scripts/vulcan configs.
3. Remove Forgejo env vars; delete `AuthCache` and related handlers/tests.
4. No import tooling, no shim (per roadmap: no backwards support owed).
   HMAC hook URLs survive automatically via stable `SECRET_KEY`.

## Testing

- Store unit tests (issue/rotate/revoke/expiry semantics, hash never
  persisted in plaintext, `public` fallback).
- Handler tests reusing `newHTTPServerForTest` against a temp DB file.
- OIDC callback tested with a stub provider; SCIM subset tested against
  recorded Authentik request shapes.
- `make verify` stays green; coverage floor holds.

## Exit criteria (Phase 1 done)

- Zero secrets in git: tokens exist only as hashes server-side.
- Revocation is a single API call with immediate effect.
- WebUI login works via Authentik for ≥1 admin; SCIM provisioning works
  when enabled and is inert when disabled.
- Forgejo code/env fully removed; `verify` (fmt, vet, race, coverage) passes.
