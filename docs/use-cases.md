# Use cases

Revised 2026-10-01. This page lists what is actually being built or run and what each case needs from a backend. It is the input to every design decision; [design](design.md), [decisions](decisions.md) and [roadmap](roadmap.md) may lag it while the direction is under discussion (see the end). Nothing here changes runtime behavior; [implementation status](implementation-status.md) describes the code.

## Sources

Observations come from the projects themselves where they exist: Vulcan (`vulcan/docs/specs/realtime-sync-notifications.md`), Smart Todos (`todo.tionis.dev` README and backend), the recipe site (`wikis/recipes/plans/multiplayer.md`, `src/scripts/s2.ts`) and the deploy files of `2-minute-dj`. Cases marked *assumed* have no existing project to read.

## The list

| ID | Case | Status today |
| --- | --- | --- |
| U1 | Vulcan realtime git webhook proxying | In use; relay needed now |
| U2 | Backend for `todo.tionis.dev` | Own backend works |
| U3 | Backend for `rezepte.wendland.dev` | S2 stream plus Automerge, no accounts |
| U4 | Pen-and-paper character creator and manager, realtime, GM sees many characters | Not started (*assumed*) |
| U5 | Multi-master database for scripts on several nodes | Not started (*assumed*) |
| U6 | Shared local-first cache for scripts on several nodes | Replaces a single-purpose embedding cache |
| U7 | Backend (and possibly hosting) for scripts that emit events to react to, such as Discord joins | Streams cover it |
| U8 | File sharing and link shortening | Maybe |
| U9 | Git LFS backend | Later; Forgejo handles custom LFS servers badly |

Dropped from the earlier list: 2-Minute DJ (an authoritative game server, stays separate) and "judged by AI" (not ready).

## What each case needs

### U1. Vulcan wake-ups

Vulcan advertises one HTTPS `subscribe_url` in a Git ref. A forge webhook POSTs to a separate publish URL. Every connected subscriber gets one wake-up; the body is ignored; loss is acceptable because Vulcan reconciles.

- Ephemeral fan-out, no retention. Any 2xx response to a plain GET is one wake-up, so the subscribe call must block and return only on an event. An idle timeout must not return 2xx.
- The subscriber holds only a URL (no `Authorization` header). Publish and subscribe URLs are different secrets, and the subscribe URL may be seen by every repository reader.
- Unsigned secret-URL webhooks as well as signed ones; many idle connections, one per wiki per device.
- Redirects are never followed; Vulcan only advertises arbitrary URLs, so the URL shape is free.
- The producer is Forgejo. It sends `X-Forgejo-Signature` (HMAC-SHA256 of the payload; whether it carries a `sha256=` prefix is unconfirmed), `X-Forgejo-Event` and `X-Forgejo-Delivery` (plus GitHub, Gitea and Gogs aliases), and can add a configured `Authorization` header. Retry and timeout behavior is undocumented, so answer with a 2xx quickly. Source: the Forgejo webhook documentation.
- Vulcan pushes its own advertisement ref (`refs/vulcan/notifications`) to the same repository, so the pipeline should ignore pushes to refs under `refs/vulcan/` (whether Forgejo even fires hooks for such refs is unverified).
- The wake-up needs no payload, and a payload would expose commit messages and author emails to everyone holding the subscribe URL, so the default transform discards the body.
- General requirement: change the webhook data in flight at ingress (filter, validate, redact, reshape), written as CEL expressions. Per-subscriber shaping is not needed; a webhook splitter or several producer webhooks cover it.

### U2 and U3. Todo and recipes

Both are local-first Automerge apps with offline edits and realtime merge.

- **Smart Todos** has its own Node backend: Automerge files on disk, WebSocket broadcast, SQLite for users, directory groups, sessions, list permissions and pins, OIDC with SCIM, server-side schema validation of every document, acknowledged upload commands. Permissions live outside the CRDT.
- **Recipe site** stores one Automerge document per "kitchen" as change records in an S2 stream. The client hand-rolls two-document diffing, compaction (snapshot record plus trim command) and a link-carried encryption key. No accounts: the invitation link is the credential. The plan notes that a generic sync server with built-in auth "was tried before and failed on the auth part".

### U4. Character creator and manager (*assumed*)

A realtime character sheet app. A player edits their characters; a GM sees many characters, possibly across several players, at once. Inferred needs, to be checked against the real app:

- Many documents, one per character, plus a campaign grouping them.
- Per-document access: a player edits their own; a GM reads (and sometimes edits) every character in a campaign. A prefix or group scope per campaign matches this naturally.
- One connection carrying many documents, and a "what changed" signal across the set.
- Offline edits and merge, as in U2 and U3.

### U5. Multi-master database (*assumed*)

Several scripts on several nodes write concurrently, possibly offline, and converge. Candidate shapes, cheapest first: a last-writer-wins keyed map with hybrid logical clocks; Automerge documents; a replicated SQLite such as cr-sqlite (unverified maintenance, needs a native extension).

### U6. Shared local-first cache

Each node keeps a local cache and shares entries through a hub. The original single-purpose cache used SHA-256 keys, JSON values, batch lookup, per-key spend limits and hit counters. A cache needs eviction, TTL, batch lookup and per-tenant accounting, and must not write through a durable log.

### U7. Event-emitting scripts

Scripts publish events (Discord joins, backup results); other scripts react. Needs: append from `curl` with a narrow token, read and follow from a shell pipe, fan-in and fan-out with retained replay, a "latest status per key" view, and absence detection ("no backup reported"). Hosting these scripts is a hosting concern.

### U8 and U9

File sharing and link shortening need a public read route, a stable name, expiry and quotas. A shortener needs only a keyed record and a redirect; file sharing needs blob storage with range reads. LFS identifies objects by the SHA-256 of raw bytes, so a raw-digest lookup is the key and per-repository authorization decides access.

## Patterns across the cases

| Pattern | Cases |
| --- | --- |
| Realtime merging of shared documents with per-document access | U2, U3, U4 |
| Ephemeral wake-up delivery over plain HTTP | U1 |
| Retained event streams with fan-in and fan-out | U7, U1 |
| State shared between nodes with local copies (database, cache) | U5, U6 |
| Public or shared access to named things | U8, U9 |

The first pattern is the largest: three of nine cases. Apps in that group own their users (OIDC, SCIM, invitation links); the backend only needs to check scoped credentials per document or per prefix.

## Direction under discussion

Not settled; the design documents reflect earlier points on this path.

- Decided earlier and still holding: Automerge sync uses the Automerge Repo protocol; encrypted state is a client concern over streams; apps own their users; a narrow credential may travel in the URL for clients that cannot send headers; Vulcan comes first.
- Open: whether storage services (streams like S2, blobs like S3, documents, keyspaces) are built into Patchwork or hosted as existing services under a small self-hosted PaaS that provisions credentials, reverse proxy, authentication, backups and suspend. Patchwork's own scope may shrink to the stream and relay service it already is.
- Open: whether a node-sharing layer for U5 and U6 belongs to the same service or is separate libraries over S3-style storage.
