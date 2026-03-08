#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/patchwork/patchwork.env}"
NGINX_CONF="${2:-ops/nginx/patchwork.conf}"
RUNTIME_CHECK="${PATCHWORK_EDGE_RUNTIME_CHECK:-false}"

warn() {
  printf '[edge-check] WARN: %s\n' "$*" >&2
}

fail() {
  printf '[edge-check] ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '[edge-check] %s\n' "$*"
}

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
  info "loaded env file: ${ENV_FILE}"
else
  warn "env file not found: ${ENV_FILE} (using process env/defaults)"
fi

BIND_ADDR="${PATCHWORK_BIND_ADDR:-:8080}"
OIDC_REDIRECT_URL="${PATCHWORK_OIDC_REDIRECT_URL:-}"

host_part="${BIND_ADDR}"
if [[ "${host_part}" == *:* ]]; then
  host_part="${BIND_ADDR%:*}"
fi

# allow localhost-only binds; reject wildcard/public binds.
case "${host_part}" in
  "127.0.0.1"|"localhost"|"[::1]"|"::1")
    info "bind address is loopback-safe: ${BIND_ADDR}"
    ;;
  "")
    fail "PATCHWORK_BIND_ADDR=${BIND_ADDR} binds wildcard interfaces; use 127.0.0.1:8080 behind TLS proxy"
    ;;
  "0.0.0.0"|"[::]"|"::")
    fail "PATCHWORK_BIND_ADDR=${BIND_ADDR} exposes all interfaces; bind to loopback behind TLS proxy"
    ;;
  *)
    fail "PATCHWORK_BIND_ADDR=${BIND_ADDR} is not loopback-only"
    ;;
esac

if [[ -n "${OIDC_REDIRECT_URL}" ]]; then
  if [[ "${OIDC_REDIRECT_URL}" != https://* ]]; then
    fail "PATCHWORK_OIDC_REDIRECT_URL must use https in edge deployments: ${OIDC_REDIRECT_URL}"
  fi
  info "oidc redirect url is https: ${OIDC_REDIRECT_URL}"
fi

[[ -f "${NGINX_CONF}" ]] || fail "nginx config not found: ${NGINX_CONF}"
grep -q 'listen 443' "${NGINX_CONF}" || fail "nginx config missing TLS listen (443)"
grep -q 'proxy_set_header X-Forwarded-Proto https' "${NGINX_CONF}" || fail "nginx config missing forwarded proto https header"
grep -q 'proxy_pass http://127.0.0.1:8080' "${NGINX_CONF}" || warn "nginx proxy_pass is not loopback:8080; verify private upstream routing"
info "nginx tls proxy config checks passed: ${NGINX_CONF}"

if [[ "${RUNTIME_CHECK}" == "true" ]]; then
  if command -v ss >/dev/null 2>&1; then
    sockets="$(ss -ltnp 2>/dev/null || true)"
    patchwork_sockets="$(grep 'patchwork' <<<"${sockets}" || true)"
    if grep -Eq '(^|[[:space:]])(0\.0\.0\.0:8080|\*:8080|\[::\]:8080|:::8080)($|[[:space:]])' <<<"${patchwork_sockets}"; then
      fail "runtime socket check found wildcard patchwork listener on :8080"
    fi
    if [[ -n "${patchwork_sockets}" ]]; then
      info "runtime socket check passed for patchwork listeners"
    else
      warn "runtime check enabled but no patchwork listener was detected"
    fi
  else
    warn "runtime check requested but ss is not installed"
  fi
else
  info "runtime socket check skipped (set PATCHWORK_EDGE_RUNTIME_CHECK=true to enable)"
fi

firewall_checked=0
if command -v ufw >/dev/null 2>&1; then
  firewall_checked=1
  if ! ufw status 2>/dev/null | grep -q 'Status: active'; then
    warn "ufw is installed but not active"
  else
    info "ufw is active"
  fi
fi
if command -v nft >/dev/null 2>&1; then
  firewall_checked=1
  if ! nft list ruleset >/dev/null 2>&1; then
    warn "nft command available but ruleset check failed"
  else
    info "nftables ruleset detected"
  fi
fi
if [[ "${firewall_checked}" -eq 0 ]]; then
  warn "no firewall tool detected (ufw/nft); verify network exposure restrictions manually"
fi

info "edge hardening checks passed"
