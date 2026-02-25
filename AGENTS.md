# AGENTS.md

Repository-specific instructions for LLM/coding agents working in `projects/skald` (Patchwork).

## 1. Mission and Scope

- Build and maintain Patchwork as a DB-scoped SQLite service.
- Preserve the core product focus:
  - SQLite DBs as document units
  - DB-scoped service endpoints
  - built-in sync boundaries
  - OIDC for web auth
  - machine tokens for service auth

## 2. Source-of-Truth Documents

Before substantial implementation work, read the relevant sections of:

- `README.md` (implemented behavior and operator-facing docs)
- `LLM_API.md` (machine/LLM integration contract)
- `DESIGN.md` (architecture and intent)
- `TODO.md` (delivery plan and phase status)
- `FUTURE_CONSIDERATIONS.md` (explicitly deferred items)

## 3. Working Rules

- Keep changes minimal, testable, and scoped to the request.
- Prefer modifying existing patterns over introducing new abstractions unless needed.
- Do not silently change API semantics.
- Never use destructive git commands (`reset --hard`, `checkout --`) unless explicitly requested.
- If unexpected unrelated local changes appear, stop and ask the user how to proceed.

## 4. Go Development Standards

- Run `gofmt` on changed Go files.
- Run relevant tests after code changes:
  - minimum: targeted package tests
  - preferred before handoff: `go test ./...`
- Keep server limits and auth checks explicit in handlers.
- Preserve DB-scoped authorization (`db_id`, `action`, `resource_prefix`) behavior.

## 4.1 Third-Party Extensions

- SQLite extension source trees under `third_party/` are subtree-vendored upstream code.
- Do not hand-edit vendored extension source unless the task explicitly requires patching upstream code.
- Prefer updating vendored trees via `git subtree pull` and document the source ref in commit messages.

## 5. API Guardrails

When changing endpoint behavior, verify all of the following:

- route and method correctness
- required auth scope/action/resource
- request validation and size limits
- response shape/status code
- SSE event names and payload structure (if applicable)

## 6. Mandatory Documentation Updates

If you change anything user-visible in API, auth, limits, or workflows, you **must** update docs in the same change set.

Minimum required docs update:

1. `README.md`
2. `LLM_API.md`

Update these whenever there is any change to:

- endpoints/routes/methods
- request or response schemas
- auth scopes or token behavior
- size/time/rate limits
- blob/public URL behavior
- SSE event contracts
- error semantics and status codes

Also update as needed:

- `TODO.md` when phase items are completed or scope shifts
- `FUTURE_CONSIDERATIONS.md` when deferring newly identified work

## 7. Handoff Checklist (include in final response)

- What changed (files and behavior)
- What was validated (tests/commands run)
- Any known gaps or follow-up items

If tests were not run, state that explicitly.
