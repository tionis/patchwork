# Later integrations (frozen)

This document owns specifications for integrations that are **outside the first two releases** and are frozen: do not extend them until the objects-and-recovery release ships (see [roadmap](roadmap.md) release stages). They build on core primitives and must not change them. Other documents link here instead of restating these contracts.

## Redirect-serving bindings (G-REDIRECT, R-09)

A redirect binding serves a public short link from an approved reference. It is optional platform state, not a reference feature.

**Model**

- The target is a small typed immutable **redirect descriptor** object containing one HTTPS destination. URL bytes are not a graph edge: no retention, remote fetch or proxying follows from them.
- The descriptor is published under an ordinary [hierarchical reference](unified-design.md#publication-streams-and-snapshots) with revision CAS.
- The binding is host-owned platform state: public domain/path, permitted reference scope, destination policy, and optional expiry/admission/usage limits. None of these are trusted from the descriptor or inferred from a reference name.
- `ref.read`, `ref.publish` or control of a matching name never creates a public route. Binding administration is a separate platform grant.
- An exact binding follows the stable reference ID, never a recycled name. A prefix binding that admits future names needs separate explicit approval and current policy checks.

**Serving (`GET`/`HEAD` only)**

1. Check the binding is present, enabled and unexpired; otherwise fail closed.
2. Read the current descriptor under a short authorized view and apply the destination policy: scheme, parser-normalized authority, disallowed URL features.
3. Respond `302` with `Location` and conservative `Cache-Control`. Other methods fail rather than carrying bodies or credentials across origins.

It never proxies the destination, forwards Patchwork credentials/cookies/authorization headers, appends caller query data, or accepts a destination from the request. A redirect hit reveals only the approved URL; it grants no descriptor, sibling-name or object read permission.

**Caching and revocation.** Temporary redirects are the default. Mutable or expiring refs cannot claim instant revocation of redirects already cached by clients. Permanent/immutable redirects are a separate explicit mode with its own tests.

**Abuse.** Public arbitrary-destination shorteners require a dedicated untrusted origin, abuse budgets and URL-policy fixtures. A hosted Function may implement richer landing pages through the same approved bindings; the plain redirect runs no user code per hit.

Gate **G-REDIRECT**: domain/path ownership, destination URL policy, cache/expiry/revocation behavior, abuse budgets and credential-leak fixtures. Cases: [OBJ-27/28](object-conformance.md), APP-06. References: [HTTP redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html), [OWASP redirect guidance](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

## cr-sqlite derived consumer (G-CRSQL, deferred under F-05)

cr-sqlite is deferred with other additional CRDT engines (F-05); Automerge (R-06) is the planned CRDT integration. This section preserves the constraints any future cr-sqlite prototype must meet.

**Authority.** A prototype may materialize one approved, resource-scoped CRR schema in a trusted **derived** SQLite sidecar. The main database remains the sole mutable authority for records, policy, accepted snapshot descriptors and roots; the sidecar can be discarded and rebuilt (D22). Mode `none` cannot host it.

**Isolation.**

- Never load the extension into core database connections, allow user-selected extension loading, accept arbitrary SQL/schema changes, or expose its tables as a general collection API.
- Pin the extension, SQLite compatibility, schema and query surface. Decide process isolation and sidecar layout from fault/scale tests.
- Initial sync is whole-resource, not row-filtered multi-tenant replication. Grants, membership and quotas stay outside the CRR.
- A CRR site ID or row owner field is data, never authentication. Patchwork binds every accepted change to an authenticated principal and resource scope and validates permitted tables/columns.

**Replay and acknowledgement.**

- CRR site IDs, database versions and merge metadata are not stream positions. `crsql_changes` exposes current merge state, not complete history; a replayable record envelope and deduplication rules must be proven with the pinned library, including deletes, concurrent/offline edits and schema changes.
- Apply each accepted record and advance the derived applied position in **one sidecar transaction**, so crash retries are idempotent. A lag marker copied into the main database is observational, never the recovery checkpoint.
- Never claim atomic commit across the main WAL database and the sidecar. Acknowledge incorporation only after the sidecar commit.

**Snapshots.** A compatible accepted snapshot at P must reconstruct the complete CRR state, schema, site/merge metadata and applied position, not only visible rows. Protect a contiguous suffix from P until an independently restored sidecar reaches the required boundary; otherwise restoration fails visibly and trim stalls. The sidecar is excluded from authoritative backup only when the backup retains a usable accepted anchor plus suffix.

Gate **G-CRSQL**: pinned extension/SQLite, whole-resource merge and replay, sidecar crash/restore/trim/backup, schema constraints and migrations, native-extension isolation and budgets. References: [crsql_changes](https://vlcn.io/docs/cr-sqlite/api-methods/crsql_changes), [constraints](https://vlcn.io/docs/cr-sqlite/constraints), [migrations](https://vlcn.io/docs/cr-sqlite/migrations), [SQLite multi-file WAL atomicity](https://www.sqlite.org/lang_attach.html).

### Deferred cr-sqlite cases

| ID | Scenario | Required result |
| --- | --- | --- |
| E18 | Two offline peers edit/delete concurrently, reconnect, duplicate changes and cross resource IDs | Pinned-library merge converges; accepted envelope and CRR site/db versions stay distinct from stream positions; replay/dedup and whole-resource isolation hold |
| E19 | Hard-kill after main record commit, during sidecar apply, and after sidecar commit before status propagation | Replay yields exactly one derived effect per accepted position; sidecar state and applied position never diverge; no false incorporation acknowledgement |
| E20 | Snapshot complete CRR database at P, trim, discard sidecar, restore backup, reconnect an old peer | Schema/site/merge metadata, tombstones and applied position survive; snapshot plus protected suffix rebuilds, or recovery fails visibly; no unsafe trim |
| E21 | Malicious SQL/schema/extension path, forged site/owner identity, unsupported uniqueness/foreign-key invariant, schema migration or oversized sync batch | No user SQL or core extension loading; identity comes from Patchwork admission; invariant failures explicit; native failure cannot corrupt authoritative data; work bounded |
