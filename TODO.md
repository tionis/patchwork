# Roadmap

Target: personal infrastructure (one human + own daemons/scripts). Authentik is
already the central IdP with an established SCIM-adapter convention, so
Patchwork joins that setup instead of building identity infrastructure.

Standing invariants until deliberately changed: queue/pubsub relay paths store
no message bodies; hook URLs remain capability-style.

Guiding goal: simple, fast, maintainable. No backwards compatibility is owed:
breaking changes are allowed and consumers (vulcan, scripts) update in
lockstep.

## Phase 1 — Local identity & token management

Goal: no secret needs to live in a git repo; tokens are issuable, rotatable,
and revocable from one place.

- sqlite as the local store (users, tokens, audit events). Backups are plain
  sqlite file copies through the existing ansible setup — no litestream.
- Admin API first: token/user management lives behind a versioned admin API;
  the WebUI is a thin consumer of it (same binary, existing `assets/` embed).
- WebUI login via Authentik OIDC. SCIM is an optional server capability
  (off by default), following the in-house adapter convention.
- Token CRUD (issue/rotate/revoke), keeping the current `TokenInfo` pattern
  semantics so handlers barely change.
- The Forgejo repo-file auth path is removed outright — no import tooling,
  no compatibility shim. Tokens are re-issued; existing HMAC hook URLs keep
  working as long as `SECRET_KEY` is stable.
- Exit: revocation takes effect immediately (no stale-grace dependence); git
  repos hold references, not credentials.
- Status: backend, admin API, OIDC login, optional SCIM, CLI bootstrap, and
  a thin `/admin` WebUI are implemented and verified (`make verify` green,
  coverage above floor).

## Phase 2 — Identity-aware abuse management

Goal: a misbehaving client can be throttled or cut off by identity.

- Rate limiting moves from in-memory per-IP to DB-backed, keyed on identity
  where the caller is authenticated and on IP/capability where it is not
  (hook open sides stay capability-URL based by design).
- Per-user quotas plus an audit trail of denied/abusive traffic.
- Exit: throttle/revoke by identity works end to end.

## Phase 3 — Dynamic tokens (macaroons)

Goal: least-privilege, self-attenuating credentials for daemons and scripts.

- Macaroon issuance with caveats (channels, read/write, expiry); daemons
  (e.g. vulcan) run on attenuated, short-lived tokens minted without manual
  secret handling.
- Rust-side support in vulcan.
- Exit: no long-lived static secret on any daemon.

## Phase 4 — API redesign

Goal: a versioned API incorporating what the relay has taught us
(sender-selected mode/discard, hook semantics, identity model).

- Breaking changes allowed without compat shims; vulcan updates in lockstep
  (bump `notification.json` version if the advertisement shape changes).
- Reassessment gate: with identity, abuse control, dynamic tokens, and a
  clean API in place, decide what — if anything — comes next.

## Later, only on concrete need

- Durable streams for changeset replication (append-only sqlite log, server
  sequence numbers, bounded retention, `?from=seq` replay) — only if
  replacing the NATS path for cr-sqlite replication. NATS stays until such a
  primitive exists and is tested; a held blocking connection is not
  durability.
- URL shortener (`/s/...`), embedded MQTT, per-script databases, shoutrrr
  swap — deferred; each needs its own justification at the gate.
- HTTP/3/QUIC for direct serving — far future at best; only if a
  direct-connect deployment without a proxy appears (needs UDP exposure,
  cert management, and a QUIC dependency for benefits our stable
  daemon links don't need).

## Non-goals

- Becoming a generic identity provider (Authentik already is that).
- Storing relay bodies outside an explicit durable-stream feature.
- Multi-tenant or enterprise provisioning beyond the single-household setup.
