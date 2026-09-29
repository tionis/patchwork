# Use cases and design pressure

Draft 2026-09-29. The design is driven by the things actually being built or run, not by a fixed set of primitives. This page records those cases and what each needs; [design](design.md) is derived from it. Nothing here changes runtime behavior; [implementation status](implementation-status.md) describes the code.

## Sources

Observations come from the projects themselves, not from memory of them:

- Vulcan: `vulcan/docs/specs/realtime-sync-notifications.md`.
- Smart Todos: `todo.tionis.dev` (README and backend).
- Recipe site: `wikis/recipes/plans/multiplayer.md` and `src/scripts/s2.ts`.
- 2-Minute DJ: `2-minute-dj` (README, server layout).
- Embedding proxy: `embedding-proxy` (README, `cache.ts`).
- "Judged by AI" was not found on this machine and is not analysed.

## Primary use cases

### U1. Git-forge wake-up relay (Vulcan)

Vulcan advertises one HTTPS `subscribe_url` in a Git ref. A forge webhook POSTs to a separate publish URL. Every connected subscriber gets one wake-up; the body is ignored. Delivery is lossy on purpose because Vulcan reconciles through Git.

What it demands:

- Ephemeral fan-out with no retention. Any 2xx response to a plain GET is one wake-up, so long-poll is the required transport. SSE and WebSocket do not satisfy it.
- **Capability URLs.** The subscriber holds only a URL, with no `Authorization` header. The publish URL and the subscribe URL are different secrets, and the subscribe URL is safe to distribute to everyone who can read the repository.
- Forge webhooks with no signature to verify (only a secret URL) as well as signed ones.
- Many idle connections, one per wiki per device, so idle cost matters.
- Redirects are never followed; the URL is the whole contract.

### U2. Local-first app backends

| App | Today | What it needs from a backend |
| --- | --- | --- |
| Smart Todos | Own Node backend: Automerge files on disk, WebSocket broadcast, SQLite for users, groups, permissions, OIDC sessions, SCIM. Every document is validated against the list schema. | Automerge document sync with server-side validation; per-list read/write permissions kept outside the CRDT; ack-backed upload commands; account-scoped offline behavior. |
| Recipe site | Static site plus S2 (hosted stream). One Automerge document per "kitchen" stored as change records in one stream. The client hand-rolls two-document diffing, compaction (snapshot record plus trim command), and an encryption key carried in the invitation link. No accounts. | A document sync endpoint that does merging and compaction itself; link-as-capability access; optional encryption without the server having to understand documents; browser-direct CORS access. |
| 2-Minute DJ | Own Colyseus process. The server is authoritative: clients send commands with retry IDs, the server validates, timestamps and persists snapshots. Rooms expire after 24 hours; public summaries after 90 days. | Not a sync problem. Needs authoritative logic, so it stays a separate server unless Functions ever ships. It can still use Patchwork for expiring records, public summary links and idempotent command receipts. |

The recipe plan records a lesson that matters more than any schema: a generic sync server with built-in accounts "was tried before and failed on the auth part". Apps have three incompatible identity situations: none (link is the credential), the app's own OIDC provider, and per-user permissions inside the app. A backend that insists on owning identity loses. **Patchwork should verify scoped capabilities and let the app decide who gets one.**

### U3. Script composition

Several independent scripts publish and consume: a Discord watcher emits events; many jobs publish backup results; other scripts react. Requirements:

- Append from `curl` with a narrowly scoped token; read and follow from a shell pipe.
- Fan-in from many publishers and fan-out to many readers, with retained replay.
- A "latest status per key" view of a stream (last backup per host) without replaying the whole log.
- Absence detection: notice that a backup did not report. This is the classic dead-man's-switch and is a natural add-on to retained streams with timestamps.

### U4. Shared cache

`embedding-proxy` is a purpose-built cache: SHA-256 key, JSON value, batch lookup, per-key spend limits, hit counters, immich runner pool. The reusable part is small: keyed get and put, batch lookup, size- and TTL-bounded eviction, per-tenant scope and usage accounting.

The important observation is negative: a cache must not write through the stream log. Logging every put doubles storage and adds replay semantics nobody wants. **A cache is a different storage class from a durable log**, with eviction as a feature.

### U5. Multi-master database

Several scripts or machines write concurrently, possibly offline, and converge. The shape is not yet chosen. The candidates, cheapest first:

1. A last-writer-wins keyed map with hybrid logical clocks. Fits status boards, settings and small tables.
2. Automerge documents. Fits nested records and text, and is already needed for U2.
3. A replicated SQLite (cr-sqlite). Fits real relational scripts. The heaviest option, already deferred in the older design.

A document store that serves U2 gives option 2 for free, so U5 does not need a separate engine until a script proves it needs SQL.

## Ambitious use cases

### U6. File sharing and management

Files, directories and versions on prolly trees; share links with expiry and quotas; large uploads and range reads. This is the case that justifies content-addressed storage, chunking and graph garbage collection.

### U7. Git LFS server

Git LFS identifies objects by the SHA-256 of their raw bytes, and its batch API needs upload, download and verify actions plus optional locks. Consequences for the object design:

- A lookup by raw SHA-256 must be first class. The older design treated the raw digest as an optional side property; here it is the primary external key.
- Better deduplication than whole-file LFS means content-defined chunking, so CDC is required for this use case, not optional.
- Clients speak plain HTTP with forge-issued Basic or bearer credentials, so tokens must be accepted in the shapes LFS clients can send.

### U8. URL shortener

Public unauthenticated GET that answers with a redirect; authenticated create and edit; optional expiry; optional click counts. It needs neither streams nor content addressing, just a keyed record with a public read route. Counters must be batched and not written to the log.

## Additional use cases worth planning for

| ID | Use case | Why it matters |
| --- | --- | --- |
| U9 | Webhook relay for machines behind NAT, with request inspection and replay | The original patchbay idea; a forge can reach a laptop through Patchwork. Overlaps U1. |
| U10 | Push notifications to a phone (an ntfy-style topic) | Vulcan lists mobile push as a deferred extension; scripts in U3 want it as an output. |
| U11 | Durable job queue for scripts: lease, ack, retry, dead-letter | Scripts that compose usually end up wanting this. |
| U12 | Locks and leader election with TTL | Two cron jobs must not run the same task. A compare-and-swap record with expiry covers it. |
| U13 | Blob attachments for apps (todo photos, recipe images) | U2 apps will want them, and they are the smallest slice of U6. |
| U14 | Presence and awareness (who is online, cursors, timers) | Ephemeral, per document; uses an ephemeral stream like U1. |
| U15 | Scheduled triggers (cron as an event source) | Cheap to add once streams exist; removes a class of external cron scripts. |

## Storage classes these cases imply

The cases fall into four groups whose guarantees differ enough that one engine would fit none of them well.

| Class | Guarantee | Serves | Notes |
| --- | --- | --- | --- |
| Ephemeral channel | No retention, best effort, capability URLs, long-poll/SSE/WebSocket | U1, U9, U10, U14 | Exists in the current code as zero-retention streams; lacks capability URLs and long-poll. |
| Durable log | Ordered, retained, replayable, idempotent append | U3, U11, U15 | Exists. |
| Mutable state | Documents (CRDT), keyed records with CAS and TTL, and evicting caches | U2, U4, U5, U8, U12 | Only a stream-derived KV exists today; it is the wrong base for cache, short links and locks. |
| Immutable content | Chunked blobs, trees, references, raw-digest lookup | U6, U7, U13 | Designed, not built. |

Cross-cutting needs that every class shares: names and grants, narrow credentials that can ride in a URL, quotas and usage accounting, change hints so clients can watch any resource, and idempotent commands.

## Where the current design fits and where it does not

| Requirement | Status |
| --- | --- |
| Scoped, attenuable credentials | Fits well. An app backend holds a broad token for its own prefix and narrows it per user or per document offline; it never needs to run an identity provider. Revocation granularity is coarse (root credential plus short expiry), which needs an explicit decision for browser sessions. |
| Capability URLs for publish and subscribe | Gap. The old rule forbade query credentials (D15). Now: a narrow credential minted for URL transport, presented as `?token=`. |
| Long-poll delivery | Gap. Only SSE follow is built. |
| Automerge document sync | Gap. Older design routes it through streams and snapshots, which the recipe site's experience shows is fragile and expensive. |
| Cache with eviction | Gap and conflict: a stream-derived KV cannot evict. |
| Raw-digest object lookup and CDC | Conflict with staging: CDC is currently a stage-3 nice-to-have and would move earlier for U7. |
| Keyed compaction of a stream ("latest per key") | Gap. Useful for U3 and it makes a stream-backed KV cheaper. |
| Authoritative application logic | Deliberate non-goal. |

## Decisions

Settled 2026-09-29:

1. **Automerge:** Patchwork runs the Automerge Repo protocol itself. Clients that need encryption use streams and encrypt client-side; documents are server-readable.
2. **Multi-master database:** cr-sqlite is the intended engine. It starts as a spike because it must be a native extension whose maintenance and compatibility are unverified; a keyed last-writer-wins map is the fallback.
3. **Order:** Vulcan first (it is in active use); the other apps have working temporary solutions.
4. **Old design:** removed from the wiki and kept in git history only.

Also settled:

- **URL shape:** Vulcan only advertises arbitrary HTTPS endpoints, so Patchwork uses ordinary stream URLs with a `?token=` query parameter, carrying a narrow credential minted for URL transport. No patchbay-compatible route and no separate link prefix. The Vulcan spec needs no change beyond example URLs.
- **"Judged by AI":** not ready and partly server-side; ignored until it has requirements.
