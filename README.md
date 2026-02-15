# Patchwork Sync Server (Working Folder: `skald`)

This directory is currently named `skald`, but the planned external/project name is `patchwork` with `patch.tionis.dev` as primary domain.

## Design Document

Canonical design and migration notes live in:

- `projects/skald/DESIGN.md`
- `projects/skald/FUTURE_CONSIDERATIONS.md` (deferred decisions/checklist)

That document includes:

- architecture decisions and scope
- capability model (query, reactive query watch/SSE, pubsub/fencing/hooks/blob control plane)
- compatibility strategy for legacy Patchwork endpoints
- auth/token/ACL model (service-local for now)
- migration and rollout phases
