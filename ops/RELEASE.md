# Patchwork Release Process

This process is designed to satisfy release-cut discipline from `TODO.md`.

## 1. Prepare changelog

Update `CHANGELOG.md`:

- keep `[Unreleased]` current during development
- add a new version section before release (for example `## [0.1.0] - 2026-03-08`)
- move release-ready items from `[Unreleased]` into the version section

## 2. Run release checks

```bash
ops/scripts/release-check.sh
```

This runs:

- `make build-all`
- `make test-sqlitedriver-ext`
- `go test ./...`
- `make smoke-first-deploy`
- `make smoke-first-deploy-oidc`
- `make edge-hardening-check`

## 3. Create tag

```bash
ops/scripts/release-tag.sh 0.1.0
```

This script validates:

- clean git working tree
- `CHANGELOG.md` contains `## [0.1.0]`
- `v0.1.0` tag does not already exist

Then it creates an annotated tag `v0.1.0`.

## 4. Push release

```bash
git push origin main
git push origin v0.1.0
```

Publish release notes from the matching `CHANGELOG.md` section.
