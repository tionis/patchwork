# Repository Guidelines

Patchwork is a Go HTTP relay service with vendored dependencies. Keep changes
small and behavior-focused; the codebase currently has some duplicated
implementation paths, so verify which package is actually wired into the binary
before refactoring.

## Development

- Use Go `1.26.2`; `go.mod` pins `go 1.26.0` with `toolchain go1.26.2`.
- Dependencies are vendored. Avoid network dependency updates unless the task
  explicitly requires them.
- Prefer `rg` for code search.
- Run formatting before finishing Go changes:
  `gofmt -w <changed .go files>`.
- Run tests with a writable cache:
  `GOCACHE=/tmp/patchwork-go-cache /home/eric/.local/share/mise/installs/go/1.26.2/bin/go test -timeout 90s ./...`

## Project Notes

- `main.go` contains the production server wiring and several implementations
  that overlap with `internal/*` packages.
- Some main-package tests exercise real blocking channel behavior and include
  timeout-path coverage, so the suite needs more than the default short timeout.
- Do not remove or rewrite vendored files as part of ordinary cleanup.
- Preserve user changes in the worktree; do not reset or checkout files unless
  explicitly asked.
