# Handoff prompts

Prompts for the agent that works in the Ansible repository (Gandalf), written 2026-10-02 when this branch was archived. See the [retrospective](retrospective.md) for the reasoning. Each prompt is self-contained. Prompts 3 and 5 depend on projects that do not have releases yet; run them once those exist.

## 1. Patchwork image channel after the branch rename

```text
The Patchwork repository (github.com/tionis/patchwork) renamed its `legacy` branch to `main` and made it the default branch. The Go relay that Citadel runs is unchanged; only the branch name changed. CI publishes an image tag named after the branch, so `ghcr.io/tionis/patchwork:legacy` no longer receives updates. New builds are published as `:main` and `:sha-<short>`.

1. Check which image digest Citadel's `patchwork` Quadlet is running and which commit it was built from (`podman inspect`, image labels). Compare it with the head of `main`. Since b182622 the relay uses a local SQLite identity store and an admin API instead of the Forgejo repo-file token lookup, and 233c41e persists that auth state. The role README still describes a stateless service with a Forgejo token. Find out whether the running container predates that change or whether the role has drifted.
2. Switch `patchwork_version` from `legacy` to `main` (or to a semver tag if one exists by then), and update the role README's "Updates and autonomy" row.
3. If the running image is at or after b182622, bring the role in line: a persistent state directory under `/srv/patchwork` with `restic_backup` coverage, removal of the Forgejo token if it is no longer read, and a README that describes the real state and secrets. If it predates b182622, do not let auto-update move it across that change silently. Pin the current digest first, then plan the migration as a separate, reviewed step: bootstrap the local identity store, re-issue tokens, and confirm the Vulcan webhook URLs still work.
4. Run the usual checks (`scripts/gandalf-check`, `--check` run with `--tags patchwork`). Do not deploy without Eric's approval.

Vulcan depends on this relay for real-time wiki sync. Pushes to a wiki repository on forge.tionis.dev must still wake connected Vulcan clients after any change.
```

## 2. S3 object storage for scripts and apps

```text
Add a self-hosted S3-compatible object store on Citadel for personal scripts and app servers. Requirements:

- An existing, maintained server with native access keys and per-bucket permissions. Garage is the first candidate; compare it briefly with alternatives (SeaweedFS, Versity) on maintenance, single-node operation, key and permission model, and backup story. Do not write a custom server.
- Key management happens through the server's own CLI or admin API, run with standard tools on the host. A web UI is optional and only if it costs little.
- One bucket and one scoped key per consumer, created declaratively from inventory where the server allows it. Keys go into Ansible Vault.
- Public S3 endpoint through Caddy at a hostname in `infrastructure.services`; the admin API stays on the private network.
- Data under `/srv/<service>` with `restic_backup` coverage, and a documented restore.
- Follow the repository rules: Quadlet via `roles/quadlet`, dedicated Podman network, role README with the operational profile table, wiki note in the same change.

Start with a short written proposal (choice, layout, backup, exposure) for Eric to approve before implementing.
```

## 3. S2 streams through s2-lite and s2-token-proxy

```text
Prerequisite: the `s2-token-proxy` project (github.com/tionis/s2-token-proxy, if published under that name) has a tagged image. Ask Eric if it does not.

Deploy s2-lite (github.com/s2-streamstore/s2) with local disk storage on Citadel, reachable only on a private Podman network. Put s2-token-proxy in front of it as the only public entry point. s2-lite has no access control, so it must never be exposed directly.

- s2-lite data and the proxy's token database under `/srv/<service>` with `restic_backup` coverage. s2-lite's SlateDB files need a consistent snapshot; check its documentation for safe backup and use a quiesced recovery profile if needed.
- The proxy's admin interface stays private, or is protected by Authentik if it gets a web UI.
- Public hostname through Caddy, declared in `infrastructure.services`. Long-lived streaming reads must not be cut by Caddy timeouts.
- Afterwards, evaluate moving `roles/event_publish` from hosted S2 to this instance. Only do it if the proxy supports the scoped writer tokens and the record format event_publish needs.

Write a short proposal first and get Eric's approval before deploying.
```

## 4. App server convention

```text
Several self-owned app servers already run on Citadel with the same shape: Smart Todos (`roles/todo`) and BlobForge (`roles/blobforge`). Each has a Quadlet, Caddy with WebSocket support, a managed confidential Authentik OIDC application, native SCIM over the private `authentik` network with `/scim/v2` blocked publicly, state under `/srv/<app>` with an application-scoped Restic recovery profile, and an image-native health probe. More apps of this kind are planned (a recipe site with Automerge sync, a pen-and-paper character manager, a small hooks server).

Goal: adding the next app should take one small role plus inventory entries, not a copy of an existing role.

1. Compare roles/todo and roles/blobforge and list what is duplicated: Quadlet setup, Caddy site, Authentik OIDC and SCIM provisioning, backup profile, health check.
2. Propose the smallest way to share it. Options: a documented recipe in the wiki, role defaults plus `include_role` of shared pieces, or one parameterized `app_server` role. Respect the complexity budget in AGENTS.md: the change must remove duplication, not add a layer next to it.
3. Also write down what an app needs to provide to fit (health endpoint, SCIM path, data directory, how to quiesce for backup) as a short contract in the wiki, so app repositories can follow it.

Propose before implementing. Migrating todo and blobforge onto the shared pieces is part of the work only if it is low-risk; otherwise leave them and use the convention for new apps.
```

## 5. Hooks server

```text
Prerequisite: the `hooks-server` project has a tagged image. Ask Eric if it does not.

Deploy hooks-server on Citadel following the app server convention (prompt 4, if it exists by then). It is a small custom app server that hosts single-purpose webhook handlers and misc jobs that do not justify their own service. Each handler has its own route, its own secrets and its own outbound credentials.

- Public hostname through Caddy, declared in `infrastructure.services`.
- Handler secrets (webhook HMAC secrets, outbound API tokens) in Ansible Vault, rendered as environment variables or files the way the project README specifies.
- State under `/srv/hooks-server` with backup only if the project says it keeps durable state.
- Health probe and metrics as the project provides.

It does not replace the Patchwork relay. The relay keeps serving Vulcan.
```
