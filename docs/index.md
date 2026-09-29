# Patchwork design

Revision 2026-09-29. Patchwork is a single-node backend for scripts and web apps: durable and ephemeral streams, keyed state, Automerge documents and content storage behind one identity and sharing layer. The design is driven by named use cases, not by a fixed set of primitives.

This is the plan, not a claim that the service is complete. [Implementation status](implementation-status.md) records what runs; [development](development.md) has commands. Every acceptance criterion in the [roadmap](roadmap.md) is unmet until status records executed evidence.

## Reading order

1. [Use cases](use-cases.md): the projects and scripts the design serves.
2. [Design](design.md): resource kinds, the shared control plane and per-kind designs.
3. [Decisions and gates](decisions.md): requirements, defaults and the evidence needed before enabling a capability.
4. [Roadmap](roadmap.md): milestones, tasks and acceptance.

Specifications of built behavior:

- [Architecture](architecture.md): stream semantics, the append path and invariants.
- [Protocol](protocol.md): HTTP conventions and the operation inventory.
- [Authorization](authorization.md): identity, delegation, URL-transport credentials and revocation.
- [Storage](storage.md): SQLite rules, retention, backup.
- [Processing](processing.md): pipeline, stream KV and webhook ingress.
- [Dependencies](dependency-decisions.md).

Each subject has one owning document; others link to it. Correct inconsistencies in documents and affected tests before implementation. The earlier primitive-first design (objects, references, snapshots, recovery requirements, Functions, hosted apps, P2P and media) was removed in this revision and is in git history.

## Status vocabulary

- **Requirement:** a stable product or safety property (C-series in [decisions](decisions.md)).
- **Default:** a selected policy that may change with rationale and matching tests.
- **Gate:** evidence needed before choosing a library or enabling a capability.
- **Deferred or later:** not planned for the current milestone; no placeholder responses.

Deployment, data deletion and schema migration need their own reviewed step. Wiki maintenance follows [Vulcan agent guidance](AGENTS.md); generated skills are under `.agents/skills/`, with [summarize-note](AI/Prompts/summarize-note.md) and [daily-review](AI/Prompts/daily-review.md) prompt examples.
