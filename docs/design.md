# Patchwork design (use-case-driven rework)

Draft 2026-09-29. This is the system overview for the rework described in [use cases](use-cases.md). It replaces the earlier primitive-first design (objects, references, snapshots, recovery requirements, Functions, hosted apps, P2P and media). Those documents were removed and live only in git history. [Implementation status](implementation-status.md) still records what the code does today; [roadmap](roadmap.md) sequences the work.

## Purpose

Patchwork is a single-node backend that scripts, web apps and tools use instead of each running their own small server. It supplies realtime delivery, durable logs, synced state and content storage, behind one identity, sharing and quota layer. The design test for every feature is a named use case: no use case, no feature.

## Principles

1. **Kinds, not one engine.** Different use cases need different guarantees, so each resource kind has its own storage and semantics. A cache that evicts, a log that never loses and a CRDT that merges cannot share one write path without making at least one of them worse.
2. **A thin shared control plane.** Kinds share only names, grants, credentials, URL-transport credentials, quotas, change hints and idempotency. Anything else stays inside the kind. This is the only "framework"; do not grow it.
3. **The app owns its users; Patchwork verifies scopes.** Apps have no identity, their own OIDC, or per-user permissions. Patchwork never runs an account system for them. It checks scoped, attenuable credentials that an app backend or a link creator hands out.
4. **One authoritative SQLite database** for control-plane state, logs, documents and keyed records, plus block files for large immutable content. One backup covers it.
5. **Ordinary HTTP first.** Every kind is usable from `curl`. Richer protocols (WebSocket sync, long-poll) are additions for clients that need them.
6. **Bounded everything.** Idle connections, request sizes, per-tenant storage and work per request have explicit limits.

## Resource kinds

| Kind | Guarantee | Serves | Protocol | Status |
| --- | --- | --- | --- | --- |
| Stream | Ordered and replayable when retained; with retention `none` it is an ephemeral best-effort channel. Idempotent append; retention by age or size | Script events, job results, audit, queues; Vulcan wake-ups, webhook relay, push, presence (retention `none`) | Append and read over HTTP; SSE follow and live; long-poll (planned); watch | Built, except long-poll and links |
| Keyspace | Mutable keyed records with per-key revision and CAS; optional TTL; optional eviction cap; optional public read | Cache, settings, locks, short links, "latest status" | REST per key and batch | Missing (stream-derived KV exists) |
| Document | Automerge document that merges concurrent edits | Todo, recipes, other local-first apps, awareness | Automerge Repo WebSocket protocol; plain HTTP export/import | Missing |
| Database | cr-sqlite replicated tables that merge by column | Multi-master scripts | Change-set push and pull | Missing; needs a spike |
| Blob store | Content-addressed chunks, trees and named references | File sharing, Git LFS, attachments | Upload, range read, references, share links | Missing |

The older design routed documents, KV, snapshots and files through streams and recovery snapshots. The use cases show that costs more than it saves: a document server keeps its own compacted state, a cache must not log, and a short link needs neither. Streams stay the right tool where ordered history is the point, and with retention `none` they are also the ephemeral channel.

## Shared control plane

**Names and identities.** Resources have a random stable ID and a canonical hierarchical name (existing grammar). Deleting and recreating a name gives a new ID; exact-ID grants never follow it.

**Principals and credentials (built).** SSH login yields a short session; sessions mint scoped Biscuit credentials; anyone can narrow a credential offline. Effective authority is current server grants, intersected with the frozen issuance scope, the attenuation checks and credential validity. See [authorization](authorization.md).

**URL-transport credentials (new).** Some clients cannot send an `Authorization` header: a Vulcan subscriber issuing a plain GET, a forge webhook, a browser WebSocket, a share URL. For them, an ordinary server-minted credential may be presented as a query parameter (`?token=…`) on any route. There is no separate link kind, table or route prefix. A "link" is a credential with a narrow issuance scope, an expiry and a revocation flag, which the credential system already has. Rules:

- The mint request must ask for URL transport (`url_transport`). Only such credentials are accepted in a query string, and the server refuses to mint one with administrative, mint, or principal-wide authority: it must be limited to explicit resources and non-administrative actions. A session or general API token pasted into a URL is rejected.
- A credential meant for a URL is minted for one purpose (publish or subscribe on one stream, read one keyspace key, and so on). A publish credential never implies read.
- Revocation, rotation, listing and expiry are the existing credential operations.
- The server never logs the query string of a request that carries a token (only a fingerprint), sends `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and rejects a token supplied both ways.
- A path secret would leak exactly as a query secret does (proxies, access logs, history), so the earlier path-only rule bought nothing and is dropped.

- Only the hash is stored; the secret is shown once.
- Each link has one narrow purpose (publish, subscribe, read, write). A publish link never implies read.
- Links are revocable and rotatable independently of any credential.
- Query-string secrets are still not accepted on the general API. Path secrets are accepted only on link routes, and those routes log only a fingerprint.
- The existing HMAC-verified hook becomes a publish link with a provider verifier and pipeline. It is not a separate mechanism.

**App delegation.** An app backend holds a token for its own name prefix (for example `apps/todo/`). For each user, list or session it narrows that token offline to specific resources, actions and an expiry, and passes the result to the browser. Patchwork checks it like any credential. Revocation is coarse (revoke the app token, or let short expiries lapse); per-user revocation belongs in the app, which simply stops issuing. Browsers cannot send headers on a WebSocket, so an app credential minted or attenuated for URL transport is passed as `?token=` there too.

**Change hints.** Any resource can publish "something changed" to a watcher, carrying no data. This exists for streams; other kinds reuse it so clients wake up and fetch under their own authority.

**Quotas and usage.** Per-tenant storage, request and connection budgets, with counters the operator can read. Cache spend limits (as in `embedding-proxy`) are usage counters on a keyspace, not a special feature.

**Idempotency.** Mutating commands accept a key; a saved receipt returns the original result for 24 hours (built for streams, extended per kind as needed).

## Kind designs

### Ephemeral streams and the Vulcan flow

There is no separate channel kind: an ephemeral channel is a stream with retention `none`, which already has live delivery, a process epoch and bounded subscriber queues. Vulcan needs two additions, both general.

**Long-poll delivery** for streams: a plain GET that waits for the next record and returns it. **An idle timeout must not return 2xx** (D34), because Vulcan treats any 2xx as a wake-up; return 408 and let the client reconnect. It works on retained streams too, resuming from a position.

**URL-transport credentials** (see [control plane](#shared-control-plane)) supply the access, on the ordinary stream routes:

- Publish: `POST` or `PUT /v1/streams/{id}/records?token=…` appends the body through the stream's normal pipeline and returns at once. Vulcan's forge webhook uses one.
- Subscribe: `GET /v1/streams/{id}/wait?token=…` (long-poll) or `…/live?token=…` (SSE) delivers live records.
- The same stream can carry many credentials with different purposes, so the publisher and every subscriber hold different secrets, each revocable and rotatable alone.

Consequences:

- A missed wake-up while a subscriber reconnects is acceptable to Vulcan, which reconciles on startup and periodically. A bounded ring of recent records (`?after=EPOCH.SEQ`) can close that gap later.
- One idle subscriber must cost close to nothing: no thread, no database connection, HTTP/2 multiplexing, and a per-stream subscriber cap.
- The subscribe URL is confidential but distributable; rotating it means publishing a new advertisement, which matches Vulcan's redirect policy.
- Signed forge hooks (GitHub HMAC) stay a publish credential plus a provider verifier, on the same stream.

### Stream

Kept as built: retained and live streams, bounded retention, creation rules, filters and validators, idempotent append, follow and watch. Additions driven by scripts:

- **Latest per key.** A stream may declare a key extractor; reads can ask for the newest record per key, and retention can keep only the newest per key (log compaction). This serves "last backup per host" without a separate store.
- **Absence detection.** A stream can declare "expect a record every N minutes" and append a record to a designated alert stream when it lapses.
- **Named cursors.** Optional server-stored consumer positions so a stateless script resumes where it left off.

Dropped from the earlier design: snapshots, recovery requirements, coverage lag budgets, consumers with materialized state, client-produced snapshots. Retention is simply age or size.

### Keyspace

A namespace of keys, each with bytes or JSON, a content type, a revision and an optional expiry. Operations: get, put with `If-Match` or `If-None-Match`, delete, batch get, prefix list, and optionally `increment` for counters. Modes:

- **Cache:** size cap with least-recently-used eviction, TTL, batch lookup, hit counters. Serves `embedding-proxy`.
- **Record:** durable, no eviction. Serves settings, locks (put-if-absent with TTL), leader election.
- **Public read:** an anonymous GET route bound to the keyspace, optionally answering with a redirect. Serves the URL shortener; click counts are batched increments.

A keyspace may emit a change feed into a stream; it is not built on one. The implemented stream-derived KV overlaps this and is superseded once keyspaces exist.

### Document (Automerge)

Patchwork runs an Automerge Repo-compatible WebSocket endpoint so existing JS clients connect unchanged. It is a sync peer that stores documents.

- **Storage:** per document, incremental change chunks plus a periodically compacted base, in SQLite. Compaction is a local rewrite; there are no trim commands or client-side snapshots.
- **Identity:** a document resource has a stable ID that is also its Automerge document ID mapping. Names follow the usual grammar.
- **Access:** connect with a scoped credential or link; read and write are separate actions. Read-only peers receive sync but their messages are dropped. Permission data lives in the app or in grants, never in the document.
- **Validation:** an optional per-document schema check (the Todo app validates every list). Runs on the server peer against the merged result; rejection stops applying and reports to that peer.
- **Ephemeral messages** (presence, cursors) are relayed over an ephemeral stream and never stored.
- **Encryption:** not offered as a document mode. Clients that need encryption use streams and encrypt client-side, as the recipe site does today.
- **Implementation:** evaluate the `automerge` Rust crate and existing Rust Automerge Repo implementations (for example `samod`) against a pinned client; adopt only after interoperability fixtures pass. Bound document size, change count and per-message work like any untrusted input.
- **HTTP:** `GET` returns the current document binary; `POST` merges a binary. This serves scripts and backups.

### Database (cr-sqlite)

A database resource holds a replicated schema in which every peer keeps a full SQLite file and exchanges change sets. The server role is a relay and archive: it accepts change sets from a site, stores them, and serves changes since a version to other sites.

Risks that gate this kind:

- cr-sqlite must be loaded as a native SQLite extension. Its maintenance state and compatibility with the SQLite version used here have to be checked before committing.
- Server-side compaction needs the same merge rules as the extension, either by loading it or by reimplementing them.
- Schema migrations across peers are the hard operational problem.

Therefore this kind starts as a **spike** with named exit criteria (compatibility, convergence with two offline peers, change-set size, compaction, crash recovery). If it fails, fall back to a keyed last-writer-wins map with hybrid logical clocks, which covers small script tables without an extension.

### Blob store

Deferred until the earlier kinds ship, but shaped now by U6 to U8:

- Content-addressed chunks with a **raw SHA-256 index**, since Git LFS identifies objects that way.
- **Content-defined chunking** from the start, because Git LFS deduplication requires it. A fixed-chunk profile is not an intermediate step.
- Trees (prolly maps and directories) come after byte objects, when file management needs them.
- Named references with compare-and-swap; share links are URL-transport credentials with expiry and byte limits.
- Garbage collection: reference counting from roots, with a mark and sweep fallback once trees exist. Enable only after race tests.
- Git LFS adapter: batch API, verify, optional locks, Basic or bearer credentials.

## Storage rules

- Control plane, streams, keyspaces, document chunks and change sets live in the one SQLite database (WAL, FULL synchronous, foreign keys).
- Large immutable content lives in local block files, installed by rename after hash verification, cataloged in SQLite before use.
- Online backup uses SQLite's backup API plus a block manifest. Restore goes to a fresh directory and verifies identity.
- Before the first public release, schema changes edit migration 0001 in place (D29).

## Non-goals

- Authoritative application logic (the 2-Minute DJ server), user-uploaded code execution, hosted app frontends, WebRTC and media, an identity provider, clustering, and cross-resource transactions. Any of these needs its own use case and design.

## Requirements carried over

The following earlier decisions still hold and are recorded where they are implemented: positions are half-open and never renumbered; failed writes allocate nothing; names are case-sensitive canonical paths; deletion and recreation never rebind old grants or cursors; revocation is rechecked at least every five seconds for active subscriptions; a slow client never grows memory without bound. See [architecture](architecture.md) and [authorization](authorization.md).
