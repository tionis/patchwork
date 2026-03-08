# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [0.1.0] - 2026-03-08

### Added

- CI workflow enforcing release-gate build/test checks (`make build-all`, `make test-sqlitedriver-ext`, `go test ./...`).
- First-deploy smoke script for core API flows (`ops/scripts/smoke-first-deploy.sh`).
- OIDC login/token smoke script (`ops/scripts/smoke-oidc-login.sh`).
- Backup/restore/drill scripts with systemd timer units.
- Production profile template, monitoring baseline rules, and Nginx TLS reverse-proxy example.
- Edge hardening validation script (`make edge-hardening-check`) and hardened systemd defaults for loopback bind + service sandboxing.

### Changed

- Query-watch SSE responses now flush immediately through the HTTP status wrapper.
- Ops env default bind address now targets loopback (`127.0.0.1:8080`) for reverse-proxy-first deployments.

### Fixed

- SSE snapshot/update events could be delayed by middleware response wrapping that did not forward `Flush()`.
