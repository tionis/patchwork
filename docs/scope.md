# Motivation and scope

## Problem

Patchwork lets scripts and applications share data without rebuilding authentication, durable history, replay, object storage, recovery and hosting for every project. A shell script can append raw bytes; a webapp can publish a directory, maintain structured state and invoke scoped backend logic.

The service is single-node. It does not promise distributed consensus, global ordering across streams or exactly-once effects in external systems.

## Small core

Three data primitives cover the storage model:

- **Immutable objects:** bytes, ordered maps and directories over one content-addressed block graph.
- **Revisioned references:** stable named identities pointing to immutable state, updated with compare-and-swap.
- **Streams:** immutable ordered records, bounded replay and subscriptions; zero-retention mode provides best-effort live events.

Snapshots combine an object root, stream boundary and format/provenance descriptor. Clients or server adapters produce them. KV is a stream materialization. Directories are constrained maps. App releases are immutable deployment descriptors selected by references. Processing, authorization and jobs are shared services, not additional user data engines. See [composition rules](unified-design.md).

## Representative uses

| Use | Composition | Limit |
| --- | --- | --- |
| Script history and webhook ingestion | Validated stream append, replay, scoped credentials | No exactly-once external delivery |
| Mutable structured state | Stream-backed KV or immutable map + reference CAS | No generic cross-stream transaction |
| Files, releases and webapp assets | Byte objects, directories, references, grants | Content IDs do not grant access |
| Encrypted/local-first state | Opaque changes and client-produced typed snapshots | Server cannot validate plaintext semantics |
| Custom app commands and consumers | Approved Functions over the same command boundary | No ambient database/network authority |
| P2P files and calls | Existing signaling data primitives plus WebRTC/TURN | Server cannot meter or recall direct-peer copies |

## Boundaries

Snapshots belong to streams, not consumers. Multiple formats coexist. Every configured recovery requirement must have accepted coverage before history is trimmed. Tombstones and causal metadata belong to formats; generic retention cannot invent replacement state.

Retained append success means processing and durable commit completed, not that asynchronous consumers caught up. Filters run before publication, using immutable original ingress bytes for authentication. Configuration is server-owned; prefix rules are creation templates, not dynamic inherited configuration or authorization.

## Delivery scope

Work ships in stages so a usable service exists before the riskiest format decisions. The [roadmap](roadmap.md#release-stages) maps tasks to stages.

1. **Streams release.** Rust/single-node storage; authenticated retained and zero-retention streams; replay/follow/watch; metadata/config CAS; built-in pipeline; transactional KV; one verified webhook provider; creation templates; scoped SSH-based authentication; CLI; DB backup/restore; measured limits. Retention is infinite, or bounded on streams without recovery requirements. No object engine is needed.
2. **Objects and recovery release.** Byte objects with a fixed-chunk profile, references, pins, leases and online graph GC; server and client snapshots; recovery requirements and safe trim; KV snapshots; operational UI; backup with block closure.
3. **Structured objects.** CDC byte profile, ordered maps, directories, diff and compose, adopted as additional profiles after their gates.

The application-platform iteration adds hosted app deployments and scoped browser sessions, share redemption/accounting, and the gated Functions subsystem. Reference apps validate those capabilities incrementally. Built-ins do not depend on selecting a guest runtime.

Later, frozen integrations: Automerge, P2P file transfer, WebRTC media/recording, optional commit history, client-assisted block transfer and redirect-serving bindings ([later integrations](later-integrations.md)). Do not extend their specifications until the objects-and-recovery release ships. They reuse core storage and job machinery; TURN/media transport is a separate protocol integration because stream replay is not a media transport.

Deferred: clustering/replication, generic cross-stream transactions, arbitrary native servers, additional CRDT engines (including cr-sqlite), filesystem mounts, automatic merge/proof APIs, fine-grained directory ACLs, administrator-authored policy rules, and protocol compatibility layers. Compatibility must not constrain the core design. No existing deployment is migrated automatically.

## Success criteria

1. Curl producers and CLI readers work without SDK envelopes.
2. A retained acknowledgement survives tested abrupt-process restart.
3. KV and client-owned state restore from accepted snapshots plus retained suffixes (objects-and-recovery release).
4. Watch-only credentials cannot retrieve records, metadata or object bytes.
5. Alternate routes cannot bypass pipelines, authority or commit fences.
6. Revocation stops new work and bounds active delivery termination.
7. Disk exhaustion or unavailable snapshot producers fail visibly without discarding promised recovery state.
