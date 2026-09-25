# Implementation workflow

Read [design index](index.md), [requirements](decisions.md), [implementation status](implementation-status.md) and [roadmap](roadmap.md) before changing code. The roadmap is the sole detailed task/dependency list. Preserve existing user changes and data; deployment and schema migration need separate review.

## Working rules

Implement a narrow real behavior, then its tests and protocol. Do not introduce empty traits, speculative crates, fake-success routes or production-selectable bypass authorizers. Unavailable operations stay unavailable. Every alternate route uses the same authorized command path.

Use modules in the existing Rust package; split crates only for a demonstrated isolation/build benefit. Suggested responsibilities are `model`, `store`, `auth`, `pipeline`, `objects`, `retention`, `subscriptions`, `extensions`, `http` and `cli`. Add submodules when their implementation exists. Built-ins and Functions share logical command/host contracts, but trusted built-ins need not execute in a sandbox.

Keep one SQLite transaction domain, one object graph/collector, one revision/receipt model and one durable job lifecycle. Application features compose these rather than introduce their own storage, token, scheduler or retention engines. Untrusted code, compiler work and network waits remain outside database transactions.

Inspect pinned dependency source/APIs, licenses and executable behavior at adoption time. Keep the toolchain and lockfile reproducible. Numeric limits need measurements. Failed gates remain visible; independent safe work can continue.

## Delivery sequence

Milestones group related tasks; [release stages](roadmap.md#release-stages) decide what ships together.

| Milestone | Deliverable / exit evidence |
| --- | --- |
| M0 | Repository safety, Rust foundation, typed grant model, Biscuit attenuation/SSH prototypes and authorization budgets |
| M1 | Authorized retained streams, config/metadata/lifecycle, common pipeline, idempotency and hard-kill evidence |
| M3 | Built-in pipeline, transactional KV, signed webhook and creation templates (KV snapshots in stage 2) |
| M4 | Follow/live/watch and scoped CLI (operational UI in stage 2) |
| O + M2 | Fixed-profile byte objects, refs, leases, online GC, server/client snapshots and safe retention; CDC/maps/directories in stage 3 |
| M5 | Online backup/restore, runbook, measured limits, conformance per release stage |
| R + S | Hosted apps and approved Functions over the same primitives; reference fixtures before broad integration |

Dependencies, not numerical order, govern work: the pipeline precedes public append, and object/authorization gates precede publication. Stage 1 (streams) needs no object engine. Media/CRDT integrations do not block validation of Quotes or hosted shares.

## Required deliverables

Generate and validate OpenAPI 3.1 and SSE schemas for implemented APIs, including decimal-string counters, binary bodies, permissions, error codes, CAS, idempotency and pagination. Logical examples are not executable schemas until tested.

CLI families: login; credential create/list/revoke/attenuate/inspect; stream create/list/show/delete/config; append/read/follow/watch; metadata; object upload/download/pin; map/directory/ref operations; snapshot list/create/publish/accept/status; KV; hooks; jobs; local admin bootstrap/backup/restore. Introduce commands only when the corresponding authorized behavior exists. Binary stdin/stdout and structured `--json` output support scripts; diagnostics go to stderr. Do not place credentials in logged arguments/examples when files or stdin suffice.

Use isolated test directories and non-admin identities. Separate unit/reopen tests, hard-process-kill tests, filesystem faults and device power-loss assumptions. Update roadmap/status with exact commands/results, remaining gates, migrations and limitations. Interface existence is not feature completion. Developer commands live in [development](development.md).
