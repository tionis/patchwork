# Requirements, decisions and gates

Rewritten 2026-09-29 from [use cases](use-cases.md). The C-series is a new register. D-series numbers that survive keep their earlier meaning; retired ones are listed at the end.

## Requirements

| ID | Requirement |
| --- | --- |
| C01 | Rust, single node |
| C02 | One authoritative SQLite database per instance; block files only for large immutable content |
| C03 | Scoped permissions over exact or prefix resources, with offline attenuation |
| C04 | Biscuit is the token format for identity and attenuation only; server policy is typed Rust |
| C05 | Retained acknowledgement covers pipeline and durable commit |
| C06 | Filters can transform, drop or reject before append |
| C07 | Every kind is usable with plain `curl` and no SDK envelope |
| C08 | A narrow, revocable credential can be carried in the URL for clients that cannot send headers |
| C09 | Apps keep their own identity; Patchwork verifies scoped credentials |
| C10 | Automerge documents sync through the Automerge Repo protocol |
| C11 | Ephemeral streams (retention `none`) support long-poll subscribers at low idle cost |
| C12 | Caches evict, and never write through a log |

## Defaults

| ID | Default | Rationale |
| --- | --- | --- |
| D01 | Half-open positions; readers resume at a tail | Simple replay |
| D04 | Explicit creation; opt-in create-on-append by prefix; no create-on-read | Reads cannot allocate |
| D05 | Longest matching prefix selects a complete creation template | No inherited dynamic config |
| D07 | A command appends zero or one record to one stream | No implicit fan-out transaction |
| D08 | Built-in stream KV materializes inside the append transaction (until superseded by D35) | Conditional writes stay correct |
| D10 | Issuance ceiling intersected with current server policy | Neither stale grants nor surprise widening |
| D11 | A fresh unattenuated SSH session is required for general credential minting | No attenuation laundering |
| D12 | API tokens cannot mint general credentials; offline narrowing remains available | Same |
| D15 | A query-string credential is accepted only if minted with `url_transport`, which requires explicit non-administrative scope; the server never logs such query strings | Plain-GET clients and WebSockets work; a session token in a URL is refused |
| D16 | Authorization changes apply on admission and commit; active delivery rechecks at most every five seconds | Bounded revocation |
| D17 | Backup is online: consistent database copy with a checksummed manifest; restore into a fresh directory | No write pause |
| D18 | SSE with JSON and base64 for follow; raw GET for exact bytes | Inspectable transport |
| D19 | Retry receipts last 24 hours by default | Explicit bounded idempotency |
| D20 | Default-limit stream KV values cap at 720 KiB so the canonical event fits the 1 MiB record | Envelope cannot exceed the record budget |
| D24 | Receipts are scoped to principal or delegated grant, not credential lineage | Scripts can re-authenticate and retry |
| D25 | Server authorization is a typed allow-only grant model | No user-authored policy language |
| D29 | Until the first release, schema changes edit migration 0001 and development data is recreated | No deployments to migrate |
| D30 | Kinds have separate storage and semantics; the control plane is the only shared layer | Use cases need different guarantees |
| D31 | Encrypted state is a client concern on streams; documents are server-readable | Server-side merge needs plaintext |
| D32 | App-issued attenuated tokens are the delegation model; per-user revocation belongs to the app | Avoids owning accounts |
| D33 | Blob storage uses content-defined chunking from its first profile and indexes raw SHA-256 | Git LFS and deduplication requirements |
| D34 | Idle long-poll timeouts never return 2xx | Vulcan treats every 2xx as a wake-up |
| D35 | The stream-derived KV is superseded by keyspaces once they exist; it may then be removed under D29 | Avoids two overlapping mutable stores |
| D36 | An ephemeral channel is a stream with retention `none`, not a separate kind; URL-transport credentials use the ordinary stream routes, with no link table or route prefix | Reuses the stream pipeline, grants and delivery |

## Gates

A gate is closed only by executed evidence. Failure blocks its dependent capability, not unrelated work.

| Gate | Evidence | Blocks |
| --- | --- | --- |
| G-AUTH | Adversarial delegation, budgets and benchmarks, fuzz campaign | Production credential policy |
| G-SSH | SSHSIG and ssh-agent interoperability | SSH login |
| G-PROVIDER | Official provider contract and original-byte signature fixtures | Provider compatibility claims |
| G-DURABILITY | Commit, trim and restart fault injection on the target filesystem | Durable release claims |
| G-LIMITS | Load, idle-connection, slow-client and restore measurements | Capacity guidance |
| G-URLCRED | Mint-time scope restriction, query-string redaction, referrer and cache headers, revocation and rotation | URL-transport credentials |
| G-AUTOMERGE | Interoperability with a pinned Automerge Repo client; size and work bounds | Document sync |
| G-CRSQL | Extension compatibility, two-peer offline convergence, compaction and crash recovery | Database kind |
| G-BLOB | Canonical chunking fixtures, durability, LFS client interoperability, GC race tests | Blob store and collection |

## Working rules

Implement one narrow real behavior with its tests and protocol. No empty traits, speculative crates, fake-success routes or bypass authorizers; unavailable operations stay unavailable. Every alternate route uses the same authorized command path. Inspect a dependency's source, license and executable behavior when adopting it. Update the roadmap and status with exact commands and results. Deployment, data deletion and schema migration need their own reviewed step.

## Retired

The earlier C-series (C06 to C19) and these defaults served designs that were removed: D02, D03, D06, D09, D13, D14, D21, D22, D23, D26, D27, D28. They cover snapshots, recovery requirements, consumer skip, the object graph, hosted apps and CRDT sidecars, and remain in git history.
