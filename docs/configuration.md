# Configuration Guide

## Overview

Patchwork keeps identities, tokens, and notification backends in a local
sqlite store (`PATCHWORK_DB_PATH`, default `./patchwork.db`). There are no
config files in git repositories. Everything is managed through the versioned
admin API under `/api/v1`, authenticated by WebUI sessions; the WebUI (same
binary) is a thin consumer of that API.

## Bootstrap

```bash
# Create the first admin (no running server needed)
patchwork admin create --username alice --admin

# With OIDC, link the identity at creation (or later via PATCH /users/{id})
patchwork admin create --username alice --admin --oidc-sub "<subject>"
```

## Users and tokens

- `POST /api/v1/users` — create a user (`id` is also the `/u/{id}` namespace).
- `GET/PATCH/DELETE /api/v1/users/{id}` — inspect, rename, toggle
  `is_admin`/`active`, link `oidc_sub`. The last active admin cannot be
  removed or deactivated.
- `POST /api/v1/users/{id}/tokens` — issue a bearer token. The response
  contains the plaintext exactly once; only a sha256 hash is stored.
- `POST /api/v1/users/{id}/tokens/{tid}/rotate` — atomically revoke and
  replace; the old bearer stops working immediately.
- `POST /api/v1/users/{id}/tokens/{tid}/revoke` — immediate revocation.
- `GET /api/v1/users/{id}/tokens` — metadata only, never plaintext.

Token payload shape:

```json
{
  "name": "webhook-client",
  "is_admin": false,
  "expires_at": "2027-01-01T00:00:00Z",
  "patterns": {
    "POST": ["/incoming/*", "/_/ntfy"],
    "GET": ["/published/*"],
    "huproxy": ["git.internal.example:22"]
  }
}
```

### Permission patterns

- Empty/absent list denies that method.
- `"*"` allows all subpaths in the namespace.
- OpenSSH-style globs (`projects/*/data`) with `!` negation.
- Selected by HTTP method; `huproxy` targets gate `/huproxy/...` tunnels.
- An omitted `Authorization` header on `/u/{username}/...` selects a literal
  token named `public` — create one per namespace for public-readable paths.
- Lookups hit sqlite on every request: revocation is immediate, no cache.

### Notification backends

- `GET/PUT /api/v1/users/{id}/ntfy` — `{"type": "matrix", "config": {...}}`.
- Delivery endpoint is unchanged: `POST/GET /u/{username}/_/ntfy` with a
  token carrying `POST` permission for `/_/ntfy`.

## WebUI login (OIDC)

Set `PATCHWORK_OIDC_ISSUER`, `PATCHWORK_OIDC_CLIENT_ID`, and
`PATCHWORK_OIDC_CLIENT_SECRET` to enable browser login (`/api/v1/auth/login`
→ Authentik code flow with PKCE → session cookie, 12h, revocable via
`GET/DELETE /api/v1/sessions`).

First login must match a user linked by `oidc_sub`; unknown subjects get
403 and an audit row — admins create/link users explicitly, and `is_admin`
is managed locally, never from claims. OIDC never touches the data plane:
daemons keep bearer tokens.

## SCIM provisioning (optional)

Set `PATCHWORK_SCIM_ENABLED=true` plus `PATCHWORK_SCIM_TOKEN` (provisioner
bearer). With it off, no SCIM routes exist. Covered subset, Users and
Groups: create/replace/patch/deactivate, standard `filter` + `ListResponse`
reconciliation reads, member add/remove. Provisioned users are never admins;
deprovisioning deactivates (tokens stop validating, history preserved).

## HuProxy configuration

Issue a token with `huproxy` patterns, then connect:

```bash
curl -H "Authorization: Bearer TOKEN" \
  https://patchwork.example.com/huproxy/alice/git.internal.example/22
```

## Server environment variables

Server configuration is provided via environment variables:

- `SECRET_KEY` - Server secret key for HMAC generation (required for hooks)
- `PATCHWORK_DB_PATH` - sqlite identity store (default `./patchwork.db`,
  `0600`, plain file backup)
- `METRICS_TOKEN` - Dedicated bearer token that enables `/metrics`. The endpoint
  is disabled when this is unset.
- `PATCHWORK_OIDC_ISSUER` / `PATCHWORK_OIDC_CLIENT_ID` /
  `PATCHWORK_OIDC_CLIENT_SECRET` - WebUI login when the issuer is set
- `PATCHWORK_SCIM_ENABLED` / `PATCHWORK_SCIM_TOKEN` - Inbound SCIM provisioning
- `H2C` - Serve HTTP/2 cleartext directly (`true`/`1`/`yes`)
- `TLS_CERT_FILE` / `TLS_KEY_FILE` - Serve HTTPS directly (HTTP/2 negotiated
  automatically; mutually exclusive with `H2C`)
- `TRUSTED_PROXY_CIDRS` - Comma-separated CIDR ranges for reverse proxies that
  are allowed to supply `X-Forwarded-For`, `CF-Connecting-IP`, or
  `X-Real-IP`. The default trusts none; configure this when Patchwork is behind
  a known proxy so client logging and public rate limiting use the original
  address without accepting spoofed headers from direct clients.
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARN, ERROR)
- `LOG_SOURCE` - Add source information to logs (true/false)
