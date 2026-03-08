# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- CI workflow enforcing release-gate build/test checks (`make build-all`, `make test-sqlitedriver-ext`, `go test ./...`).
- First-deploy smoke script for core API flows (`ops/scripts/smoke-first-deploy.sh`).
- OIDC login/token smoke script (`ops/scripts/smoke-oidc-login.sh`).
- Backup/restore/drill scripts with systemd timer units.
- Production profile template, monitoring baseline rules, and Nginx TLS reverse-proxy example.

### Changed

- Query-watch SSE responses now flush immediately through the HTTP status wrapper.

### Fixed

- SSE snapshot/update events could be delayed by middleware response wrapping that did not forward `Flush()`.
