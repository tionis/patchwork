# Patchwork design (use-case-driven rework)

Draft 2026-09-30. This is the system overview for the rework described in [use cases](use-cases.md). It replaces the earlier primitive-first design (objects, references, snapshots, recovery requirements, Functions, hosted apps, P2P and media) and the account-platform idea (users, groups, roles, OIDC and SCIM inside the core). Those live only in git history or as recorded alternatives. [Implementation status](implementation-status.md) records what the code does today; [roadmap](roadmap.md) sequences the work.

## Purpose

Patchwork is a self-hosted storage and stream service that scripts and apps use instead of each running their own small backend. It supplies durable and ephemeral streams, keyed state, Automerge documents and deduplicated object storage, with libraries for the common client work (hashing, prolly trees, sync). Compute hosting is a thin optional layer around existing runtimes, not something Patchwork reinvents. The design test for every feature is a named use case: no use case, no feature.

Self-hosting is for digital independence, not isolation, so nothing may require Patchwork to be the only place an app runs.

**Current scope (2026-10-01).** This repository is the new Patchwork: durable and ephemeral streams, URL-transport credentials, and a webhook proxy with a CEL pipeline, driven by Vulcan and event-emitting scripts. Everything else in this document (keyspaces, documents, the database kind, owned resources, the object store, hosting) is deliberately later and gets built only when a use case pulls it in; apps with their own auth may well run their own servers instead.

## Principles

1. **Services, not a platform.** Patchwork provides resource kinds behind plain HTTP. It does not sandbox code, run accounts for other people's users, or host frontends in the core.
2. **Bindings are scoped credentials over plain HTTPS.** An app gets a base URL and a narrow credential for specific resources, through environment variables or configuration. The same app works in a local container, on this node's hosting layer, or on an external edge such as bunny.net, because nothing beyond HTTPS and a token is required. SDKs may wrap this but never add capabilities the wire protocol lacks.
3. **Apps own their users.** Logins, sharing UIs, groups of end users and OIDC or SCIM integration are application or library concerns (D32). Patchwork checks scoped, attenuable credentials and knows only its own principals.
4. **Owned resources and explicit grants.** Every resource has an owner and is reached only through grants and credentials. There is no global namespace and no implicit access by name or hash.
5. **Kinds, not one engine.** A cache that evicts, a log that never loses and a CRDT that merges cannot share one write path without making at least one worse. Each kind has its own storage and semantics over a thin shared control plane.
6. **One authoritative SQLite database** for control-plane state, logs, documents and keyed records, plus block files for large immutable content. One backup covers it.
7. **Ordinary HTTP first.** Every kind is usable from `curl`. Richer protocols (WebSocket sync, long-poll) are additions for clients that need them.
8. **Bounded everything.** Idle connections, request sizes, per-owner storage and work per request have explicit limits.

## Resource kinds

| Kind | Guarantee | Serves | Protocol | Status |
| --- | --- | --- | --- | --- |
| Stream | Ordered and replayable when retained; with retention `none` it is an ephemeral best-effort channel. Idempotent append; retention by age or size | Script events, job results, audit, queues; Vulcan wake-ups, webhook relay, push, presence (retention `none`) | Append and read over HTTP; SSE follow and live; long-poll (planned); watch | Built, except long-poll |
| Keyspace | Mutable keyed records with per-key revision and CAS; optional TTL; optional eviction cap; optional public read | Cache, settings, locks, short links, "latest status" | REST per key and batch | Missing (stream-derived KV exists) |
| Document | Automerge document that merges concurrent edits | Todo, recipes, other local-first apps, awareness | Automerge Repo WebSocket protocol; plain HTTP export and import | Missing |
| Database | cr-sqlite replicated tables that merge by column | Multi-master scripts | Change-set push and pull | Missing; needs a spike |
| Object store | Content-addressed, deduplicated chunks, trees and pins | File sharing, Git LFS, attachments | Upload, range read, pins, references | Missing |

The older design routed documents, KV, snapshots and files through streams and recovery snapshots. The use cases show that costs more than it saves: a document server keeps its own compacted state, a cache must not log, and a short link needs neither. Streams stay the right tool where ordered history is the point, and with retention `none` they are also the ephemeral channel.

## Identity, ownership and grants

Deliberately small. Anything more arrives only when an app pulls it in.

**Principals.** Administrators, scripts and deployments: things that hold SSH keys or credentials. There are no end-user accounts. A **deployment** is a named owner for one app's resources (for example `todo.tionis.dev`), so quota, backup and deletion follow the app.

**Resources and owners.** Every resource has a random stable ID, a kind, an owner (a principal or deployment, transferable) and free-form metadata: a `type` (a DNS-style name such as `todo.tionis.dev/list`) and tags. Deleting a resource removes its grants and pins and releases its storage; an internal grace period lets an administrator recover it. Exact-ID grants never follow a deleted and recreated resource.

**Grants.** A grant is `(subject, capabilities, selector)`. Subjects are principals and deployments (and later groups). The selector is one resource ID or an owner scope ("everything owned by X"), nothing else. Capabilities are per kind (append, read, subscribe, write, pin, administer and so on), so a role is just a named bundle chosen by whoever creates the grant. Grants are allow-only. Public read or write is a grant to the `public` subject, charged to the resource owner.

**Credentials.** SSH login yields a short session; sessions mint scoped Biscuit credentials; anyone can narrow a credential offline. Effective authority is the principal's current grants, intersected with the credential's frozen issuance ceiling, its attenuation checks and its validity. The ceiling lists concrete grants, never groups, so membership changes take effect at once. See [authorization](authorization.md).

**URL-transport credentials (built).** Some clients cannot send an `Authorization` header: a Vulcan subscriber issuing a plain GET, a forge webhook, a browser WebSocket, a download URL. For them, an ordinary server-minted credential may be presented as `?token=…`. There is no separate link kind, table or route prefix. Rules:

- The mint request must ask for URL transport (`url_transport`). Only such credentials are accepted in a query string, and the server refuses to mint one with administrative, mint or owner-wide authority: it must be limited to explicit resources and non-administrative actions. A session or general API token pasted into a URL is rejected.
- A URL credential has one purpose (publish or subscribe on one stream, read one key, and so on). A publish credential never implies read.
- Revocation, rotation, listing and expiry are the existing credential operations.
- The server never logs the query string of a request that carries a token, sends `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and rejects a token supplied both ways.
- Usage is charged to the resource owner and audited against the credential.

**Bindings and delegation.** An app backend holds a credential for its deployment's resources and narrows it offline per user, document or session, then hands the result to a browser. Revocation is coarse (revoke the app credential or let short expiries lapse); per-user revocation is the app's job, which simply stops issuing. Browsers cannot send headers on a WebSocket, so a credential for that is a URL-transport credential.

**Naming.** No global namespace. Stream and document identity is the ID. A later, optional reference tree lets an owner map human names to targets (a resource, an object root or an external URL) for stable public URLs and rotatable endpoints. A reference has no authority of its own: access is always decided by the target's grants, and binding one requires authority over the target. Scripts that want `backups/host1` use an owner-scoped reference or a tag query until that exists.

**Queries and feeds.** Listing resources by owner, kind, `type` and tag equality or prefix, filtered to what the caller may see. A change-hint feed over such a query is planned; start with equality and prefix only.

**Change hints.** Any resource can publish "something changed" to a watcher, carrying no data. This exists for streams; other kinds reuse it so clients wake up and fetch under their own authority.

**Quotas and usage.** Logical bytes, requests and connections per owner, with counters the operator can read; a limit rejects writes and caches evict first. A deployment's quota can be independent. Cache spend limits (as in `embedding-proxy`) are usage counters on a keyspace, not a special feature.

**Idempotency.** Mutating commands accept a key; a saved receipt returns the original result for 24 hours (built for streams, extended per kind as needed).

## Hosting layer

Out of the core. The smallest useful layer is a deployment record plus binding injection: Patchwork creates the deployment's owner, mints the credentials for its resources and passes them as environment variables. Today that works with the existing podman and Caddy setup. A later step may wrap an existing runtime for scale-to-zero and nicer deploys (candidates: a JS runtime such as workerd or Deno, or WebAssembly through wasmtime or Spin; none evaluated). Functions are trusted code from you and your agents. Running other people's code would need real isolation and is explicitly later.

## Webhook pipeline

A hook is a publish endpoint (a stream plus a URL-transport credential) with a pipeline run at ingress, once per request, before anything is appended or broadcast. Per-subscriber shaping is out of scope.

1. **Authenticate the sender** on the original bytes: secret in the credential, `Authorization` header, or an HMAC signature header (GitHub's `X-Hub-Signature-256`, Forgejo's `X-Forgejo-Signature`, formats to be confirmed by fixtures).
2. **`accept`** (CEL, bool): false drops the event silently (successful ingestion, no delivery).
3. **`validate`** (CEL, bool or error string): failure rejects with the message returned to the producer.
4. **`transform`** (CEL): a map or list becomes the JSON body, a string becomes text, `null` an empty body.

Inputs: `headers` (lower-cased names), `body` (parsed JSON; `raw` for other types), `method`. Host functions fill CEL's gaps (`omit`, `pick`, `sha256`). Example for Vulcan: `accept: headers["x-forgejo-event"] in ["push","create","delete"] && !body.ref.startsWith("refs/vulcan/")`, `transform: null`.

Rules: compile and check variable references when the hook is saved; **fail closed** (any evaluation error drops or rejects per hook, default drop, and never forwards the original); atomic versioned config; a dry-run endpoint; counters for accepted, dropped, rejected and errored events without storing payloads; bounded body, output and time. Signatures are verified on the original bytes, so a transformed body cannot be verified downstream and consumers trust the proxy.

**Spike result (2026-10-01, `cel` 0.14.5, pure Rust, MIT).** Correct for the Forgejo expressions, `has()`, regex, list macros, map construction and custom host functions; `references()` lists the variables an expression uses. Not provided: a static type checker (type errors surface at evaluation) and any cost limit. Measured on a development host: a nested comprehension over 1,000 elements took 0.7 s and over 3,000 took 5.6 s; a cubic one over 200 took 5.4 s; `list.map(a, list)` took 60 ms at n=100, 4.2 s at n=400 and did not finish in 60 s at n=1,000. Because evaluation cannot be preempted in-process, the pipeline must run expressions where a deadline can be enforced, for example a short-lived or pooled child process killed on timeout with memory limits, together with a hard cap on body size. Alternatives if that proves clumsy: `cel-cxx` (bindings to the C++ reference, heavier toolchain) or a Go implementation with cost estimation.

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
- **Identity:** a document resource has a stable ID that is also its Automerge document ID mapping.
- **Access:** connect with a scoped credential (URL-transport for browsers); read and write are separate actions. Read-only peers receive sync but their messages are dropped. Permission data lives in the app or in grants, never in the document.
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

### Object store

Deferred until the earlier kinds ship, but shaped now by U6 to U8. Access is through grants and credentials on a pin or root, or a URL-transport credential; a root ID is not itself a capability by default, and the raw SHA-256 is an adapter-only key (Git LFS pointer files expose it), with digest-as-capability an explicit opt-in per object.

- Content-addressed chunks with a **raw SHA-256 index**, since Git LFS identifies objects that way.
- **Content-defined chunking** from the start, because Git LFS deduplication requires it. A fixed-chunk profile is not an intermediate step.
- Trees (prolly maps and directories) come after byte objects, when file management needs them.
- **Pins** are the retention roots. A pin belongs to an owner, prevents collection of the object and everything it references, and is charged to that owner as the logical size of the deduplicated set of chunks across all their pins (efficiency to be measured). A resource may carry a pin so deleting it releases the pin.
- Named references with compare-and-swap (the optional owner-scoped reference tree); sharing is a grant with an expiry or a URL-transport credential with byte limits.
- Libraries (Rust and TypeScript) carry the client work: chunking and hashing, prolly trees and sync, so servers and apps compute identically.
- Garbage collection: reference counting from roots, with a mark and sweep fallback once trees exist. Enable only after race tests.
- Git LFS adapter: batch API, verify, optional locks, Basic or bearer credentials.

## Storage rules

- Control plane, streams, keyspaces, document chunks and change sets live in the one SQLite database (WAL, FULL synchronous, foreign keys).
- Large immutable content lives in local block files, installed by rename after hash verification, cataloged in SQLite before use.
- Online backup uses SQLite's backup API plus a block manifest. Restore goes to a fresh directory and verifies identity.
- Before the first public release, schema changes edit migration 0001 in place (D29).

## Non-goals

End-user accounts, OIDC or SCIM in the core, sandboxed execution of other people's code, authoritative application logic (the 2-Minute DJ server), hosted frontends in the core, WebRTC and media, clustering, and cross-resource transactions. Any of these needs its own use case and design.

## Requirements carried over

The following earlier decisions still hold and are recorded where they are implemented: positions are half-open and never renumbered; failed writes allocate nothing; deletion and recreation never rebind old grants or cursors; revocation is rechecked at least every five seconds for active subscriptions; a slow client never grows memory without bound. See [architecture](architecture.md) and [authorization](authorization.md).
