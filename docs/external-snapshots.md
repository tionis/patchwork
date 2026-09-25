# Client-produced snapshots

This contract defines client snapshot production and recovery trust (C19); endpoint availability is recorded in implementation status. Clients are first-class snapshot producers. Built-in or sandboxed adapters are optional producers, not a prerequisite for publishing a snapshot. This supports client-side encrypted state, Automerge checkpoints and offline materializations. See [unified design](unified-design.md) and [roadmap](roadmap.md), M2-06.

## Publication and recovery acceptance are separate

A snapshot is an immutable descriptor plus a durable object root: stable stream identity, format/type and version, boundary **P** (state after records `< P`, next replay record P), declared dependencies, producer identity and format/semantic-config provenance. Adapter identity/version applies only to adapter-produced snapshots; clients must not invent an adapter identity. Multiple producers, types and snapshots at the same boundary may coexist. Equal content does not imply equal position or compatibility.

An authorized client can upload content and publish a descriptor with `snapshot.publish`. Publication validates current authorization, stream lifecycle, `0 <= P <= tail`, descriptor shape, allowed links, budgets and durable dependency closure. It establishes roots atomically but does **not** certify semantic correctness or authorize history deletion. Ordinary append rights do not grant publication rights. Descriptor access and payload access remain separate permissions.

Published historical snapshots may be older than the current head: this does not promise an available replay suffix. A client must possess a compatible seed at Q and all records `[Q,P)` (or complete genesis history) to claim a complete state. The server cannot prove that claim for arbitrary opaque payloads. Listing/restore must distinguish a stored snapshot from a usable snapshot-plus-suffix; missing history is never interpreted as empty state.

Accepting a snapshot as a recovery anchor is a separate, explicit authorization decision under a revisioned per-stream recovery policy. Action: `snapshot.accept`, scoped to the recovery requirement; administering the trust policy requires config-write authority. Publishing, signing, accepting, and trimming are distinct operations/authorities. Acceptance records bind the immutable snapshot, requirement and policy revision, semantic compatibility and approving identity. Publication and acceptance may eventually share a command only when both permissions are checked independently.

Each requirement selects a format/config and either a server-managed producer or an external acceptance policy (for example, a designated client identity). Such an identity may publish and accept only when explicitly granted both rights. Signatures establish endorsement, not correctness. The initial policy authorizes named principals/service grants with explicit format/config constraints. Quorum endorsement is deferred; wire encoding is frozen in M2-06. An external snapshot cannot replace a built-in KV recovery anchor unless that adapter explicitly accepts its compatibility and semantics.

## External production workflow

1. Authorize a source read and, when needed, acquire a bounded renewable lease protecting a compatible seed and contiguous source range through captured P. Appends after P may continue. Leases have budgets/expiry and confer neither read permission nor permanent retention.
2. Read `[Q,P)` in order, reconstruct locally, and optionally encrypt the resulting state. An offline client may use its already-held complete history, but does not get an indefinite server lease.
3. Prepare immutable output objects under an upload lease. Declare all restore dependencies, including older incremental snapshots/objects; make the required closure durable before publication.
4. Publish atomically with stream lifecycle, current permissions/config, dependency protection and applicable lease checks. Use a scoped idempotency key for lost responses; retries recheck current authorization. Expired source protection requires revalidation or explicit failure, never a false server-backed completeness claim. Offline publication remains a privileged client assertion.
5. Separately request recovery acceptance. Recheck current policy and requirement revision, compatibility and durable closure. Acceptance does not itself trim anything. Restore uses this snapshot plus the available suffix from P.

Deleting/recreating a stream invalidates the old identity. Concurrent config changes, expired leases, missing objects or revocation must not produce a stale publication/acceptance or dangling recovery anchor.

A source-range lease protects the required history while the client pages through it; it is not a long-lived SQLite read transaction. Each page is separately authorized and bounded, and publication rechecks the lease/current policy. Expiry or revocation ends future admitted reads according to the normal authorization bound, even though bytes already delivered cannot be recalled.

## Retention with mixed producers

**All configured recovery requirements must be satisfied before trim.** Server-managed and external producers use the same requirement/acceptance records and retention checks; an absent server adapter never exempts an external requirement.

For a proposed new head H, each requirement needs a currently accepted compatible anchor at Q with `H <= Q <= tail` and a protected contiguous suffix `[Q,tail)`. Thus an external anchor at P can justify trimming only through P, not beyond it. Server-managed adapters can continue producing their exact-cutoff snapshots using the existing algorithm. Clients restoring from Q skip records below Q rather than applying them twice. Selecting a cutoff, accepting an anchor and trimming must never introduce a gap.

The trim transaction rechecks requirement set/config, current acceptance policy, lifecycle, anchor roots and source/output protection, then atomically updates head and record roots. A policy change cannot silently invalidate the last usable anchor after history was removed: require a compatible replacement or explicit authorized removal of that recovery guarantee. Revoking an uploader does not erase already committed data or automatically invalidate a previously accepted anchor; policy determines future acceptance.

An offline external producer stalls trimming beyond its accepted boundary. Its [coverage lag budget](storage.md#recovery-requirement-lag-budgets) reports it and then applies the configured action (by default, blocking writes to that stream); under instance disk pressure reject writes rather than bypass safety. Removing a requirement needs config authority and explicit acknowledgment of the lost guarantee. With no configured recovery requirements, ordinary retention can trim without a snapshot, under the same source-lease and lifecycle checks. Protect selected anchors and dependencies from deletion; acceptance alone does not imply unlimited retention of every historical snapshot.

## Client-side encryption

Patchwork stores ciphertext and does not need decryption keys. It can check ciphertext hashes, durability, declared references, identity, positions and authorization; it cannot check plaintext replay equivalence, recover missing keys or establish that every recipient can decrypt. Key distribution, rotation, backup and recovery are application/client responsibilities. Encryption format/key-epoch metadata must be versioned; never upload private keys as snapshot metadata.

Dependencies hidden in encrypted manifests must also be declared in an authorized server-visible dependency envelope, or packaged in a self-contained opaque object with no hidden external dependencies. Declared roots, sizes, timing and dependency edges leak metadata; encrypted payloads do not hide them. Deduplication applies to identical ciphertext only; randomized encryption generally reduces reuse. Do not introduce convergent encryption or server decryption merely to preserve deduplication. Clients authenticate the encrypted state and its binding to stream/type/boundary according to their chosen format; a server acceptance flag is not cryptographic proof of plaintext correctness.

## Acceptance cases

| ID | Scenario | Required result |
| --- | --- | --- |
| SNAP-01 | External producer, no server adapter; multiple types/producers at P | Immutable descriptors coexist; restore covers `<P` and replay starts at P |
| SNAP-02 | Append-only or publish-only credential attempts recovery acceptance/config changes | Denied; publishing never silently authorizes trim |
| SNAP-03 | Encrypted local reconstruction, upload, download and client restore | Byte-exact ciphertext; client verifies state/boundary; server has no plaintext/key requirement |
| SNAP-04 | Missing incremental dependency, unauthorized link or hidden reference | Declared missing/unauthorized closure rejected; opaque completeness remains explicit trusted assertion; declared closure survives GC |
| SNAP-05 | Lease expiry, stream deletion/recreation, config change or revocation races | Stale publication/acceptance/trim fails; no dangling root or false completeness claim |
| SNAP-06 | Mixed server/external requirements, different anchor boundaries, offline producer | Every requirement protected; no trim beyond external coverage; visible stall, lag-budget action (G22) and safe disk-pressure failure |
| SNAP-07 | Historical snapshot below head or missing suffix | Publication not confused with recoverability; restore reports unavailable history rather than fabricating state |
| SNAP-08 | Crash/lost response between upload, publication, acceptance and trim | Each committed phase recoverable; scoped retries do not duplicate publication; head and roots remain consistent |
| SNAP-09 | Delete last anchor, change trusted publisher/policy or revoke uploader | Protected anchor retained; unsafe policy transition rejected; committed data not erased by credential revocation |
| SNAP-10 | Wrong key/epoch, forged boundary binding or valid signature over incorrect state | Client integrity failures explicit; signature alone never advertised as semantic validation |

The shared source/object leases, receipts and jobs are reused; no client-specific upload store or collector is needed. M2-06 provides executable fixtures for these cases.
