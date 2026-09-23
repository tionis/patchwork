# Patchwork system design

Revision 2026-09-23. Patchwork is a single-node backend for scripts and applications, built from immutable objects, revisioned references and ordered streams. Shared authorization, processing, retention and execution services make those primitives safe to compose.

This is the implementation plan, not a claim that the service is complete. [Implementation status](implementation-status.md) records what actually runs; [development](development.md) contains commands. Schemas and signatures are logical contracts until frozen by their format/API gates.

## Reading order and document ownership

1. [Scope](scope.md) and [system overview](unified-design.md): product boundaries, primitives and composition rules.
2. [Architecture](architecture.md): stream semantics, command path and invariants.
3. [Protocol](protocol.md): HTTP conventions and operation inventory.
4. [Storage](storage.md): transactions, object graph, recovery and collection; [client-produced snapshots](external-snapshots.md) defines external production and encrypted-state trust.
5. [Authorization](authorization.md): identity, delegation, trusted facts and revocation.
6. [Processing](processing.md) and [Functions](functions-design.md): built-ins and scoped sandbox execution.
7. [Applications](reference-apps.md): hosting, sessions and end-to-end usage contracts.
8. [Acceptance plan](conformance.md), [object cases](object-conformance.md) and [function cases](function-conformance.md): required evidence.
9. [Decisions and gates](decisions.md), [implementation workflow](implementation-guide.md) and [roadmap](roadmap.md): stable requirements, unresolved choices and verifiable tasks.

Each subject has one owning specification; other documents link to it rather than define a competing contract. Correct inconsistencies in documents and affected tests before implementation. There is no separate combined design copy.

The [storage contract](storage.md) includes a cross-component data-lifetime table and the SQLite row/segment/trim cost model. Logical segments are internal planning summaries, not object chunks or public stream boundaries; physical layout alternatives remain measurement-driven.

## Status vocabulary

- **Requirement:** stable product or safety property, listed as C01–C19 and I01–I12.
- **Default:** selected implementation policy that may change with documented rationale and matching tests.
- **Gate:** evidence needed before choosing a format/library or enabling a capability.
- **Deferred:** outside the initial service release; no placeholder success responses.

Unresolved gates are explicit implementation work, not alternative architectures silently available to production. Runtime availability and verification results belong in implementation status.

Deployment, data deletion, and schema migration require their own reviewed implementation and verification. This design does not authorize them. Wiki maintenance follows [Vulcan agent guidance](AGENTS.md); its generated skills are under `.agents/skills/`, with [summarize-note](AI/Prompts/summarize-note.md) and [daily-review](AI/Prompts/daily-review.md) prompt examples.
