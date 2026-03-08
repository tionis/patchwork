#!/usr/bin/env bash
set -euo pipefail

PATCHWORK_SMOKE_BIND_ADDR="${PATCHWORK_SMOKE_BIND_ADDR:-127.0.0.1:18080}"
BASE_URL="${PATCHWORK_SMOKE_BASE_URL:-http://${PATCHWORK_SMOKE_BIND_ADDR}}"
DB_ID="${PATCHWORK_SMOKE_DB_ID:-smoke}"
BINARY="${PATCHWORK_SMOKE_BINARY:-./build/patchwork}"
START_SERVER="${PATCHWORK_SMOKE_START_SERVER:-1}"
ADMIN_TOKEN="${PATCHWORK_SMOKE_ADMIN_TOKEN:-ptk_smoke_admin_token}"
CHECK_OIDC_LOGIN="${PATCHWORK_SMOKE_CHECK_OIDC_LOGIN:-0}"

SERVER_PID=""
SERVER_LOG=""
SERVER_DATA_DIR=""
TEMP_DIRS=()

log() {
  printf '[smoke] %s\n' "$*"
}

fail() {
  printf '[smoke] ERROR: %s\n' "$*" >&2
  if [[ -n "${SERVER_LOG}" && -f "${SERVER_LOG}" ]]; then
    printf '[smoke] --- server log tail ---\n' >&2
    tail -n 120 "${SERVER_LOG}" >&2 || true
    printf '[smoke] --- end server log tail ---\n' >&2
  fi
  exit 1
}

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  for d in "${TEMP_DIRS[@]}"; do
    rm -rf "${d}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

new_tmp() {
  local d
  d="$(mktemp -d)"
  TEMP_DIRS+=("${d}")
  printf '%s' "${d}"
}

http_json() {
  local expected="$1"
  local method="$2"
  local path="$3"
  local body="${4:-}"
  local token="${5:-}"
  local content_type="${6:-application/json}"
  local out_file
  local code

  out_file="$(mktemp)"
  TEMP_DIRS+=("${out_file}")

  local -a args
  args=(-sS -o "${out_file}" -w '%{http_code}' -X "${method}" "${BASE_URL}${path}")
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "${content_type}" ]]; then
    args+=(-H "Content-Type: ${content_type}")
  fi
  if [[ -n "${body}" ]]; then
    args+=(--data "${body}")
  fi

  code="$(curl "${args[@]}")"

  if [[ "${code}" != "${expected}" ]]; then
    printf '[smoke] unexpected status for %s %s: got %s expected %s\n' "${method}" "${path}" "${code}" "${expected}" >&2
    cat "${out_file}" >&2 || true
    return 1
  fi

  cat "${out_file}"
}

http_file_upload() {
  local expected="$1"
  local method="$2"
  local path="$3"
  local file_path="$4"
  local token="${5:-}"
  local content_type="${6:-application/octet-stream}"
  local out_file
  local code

  out_file="$(mktemp)"
  TEMP_DIRS+=("${out_file}")

  local -a args
  args=(-sS -o "${out_file}" -w '%{http_code}' -X "${method}" "${BASE_URL}${path}")
  if [[ -n "${token}" ]]; then
    args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "${content_type}" ]]; then
    args+=(-H "Content-Type: ${content_type}")
  fi
  args+=(--data-binary "@${file_path}")

  code="$(curl "${args[@]}")"

  if [[ "${code}" != "${expected}" ]]; then
    printf '[smoke] unexpected status for %s %s: got %s expected %s\n' "${method}" "${path}" "${code}" "${expected}" >&2
    cat "${out_file}" >&2 || true
    return 1
  fi

  cat "${out_file}"
}

wait_for_health() {
  local attempts=60
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -sS "${BASE_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_pattern() {
  local file="$1"
  local pattern="$2"
  local attempts="${3:-60}"
  local sleep_seconds="${4:-0.25}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if grep -q "${pattern}" "${file}"; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  return 1
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
    return 0
  fi
  fail "no sha256 tool found (sha256sum or shasum)"
}

start_local_server() {
  [[ "${START_SERVER}" == "1" ]] || return 0

  [[ -x "${BINARY}" ]] || fail "patchwork binary not found/executable: ${BINARY} (run: make build-patchwork)"
  SERVER_DATA_DIR="$(new_tmp)"
  SERVER_LOG="$(mktemp)"
  TEMP_DIRS+=("${SERVER_LOG}")

  log "starting local patchwork server on ${PATCHWORK_SMOKE_BIND_ADDR}"
  PATCHWORK_BIND_ADDR="${PATCHWORK_SMOKE_BIND_ADDR}" \
  PATCHWORK_DATA_DIR="${SERVER_DATA_DIR}" \
  PATCHWORK_BOOTSTRAP_ADMIN_TOKEN="${ADMIN_TOKEN}" \
  "${BINARY}" >"${SERVER_LOG}" 2>&1 &
  SERVER_PID="$!"

  if ! wait_for_health; then
    fail "server failed health check at ${BASE_URL}/healthz"
  fi
}

require_cmd curl
require_cmd jq
require_cmd awk
require_cmd grep
require_cmd sed

start_local_server

log "checking public probes"
http_json "200" "GET" "/healthz" "" "" ""
http_json "200" "GET" "/status" "" "" ""
http_json "200" "GET" "/metrics" "" "" "" >/dev/null

if [[ "${CHECK_OIDC_LOGIN}" == "1" ]]; then
  log "checking OIDC login endpoint redirect"
  oidc_headers_file="$(mktemp)"
  TEMP_DIRS+=("${oidc_headers_file}")
  oidc_status="$(curl -sS -o /dev/null -D "${oidc_headers_file}" -w '%{http_code}' "${BASE_URL}/auth/oidc/login?next=/ui")"
  if [[ "${oidc_status}" != "302" ]]; then
    fail "expected OIDC login redirect (302), got ${oidc_status}"
  fi
  grep -qi '^Location:' "${oidc_headers_file}" || fail "OIDC login redirect missing Location header"
fi

log "minting scoped machine token via admin API"
token_body="$(
  cat <<JSON
{
  "label": "smoke-client",
  "is_admin": false,
  "scopes": [
    {"db_id":"${DB_ID}","action":"query.read"},
    {"db_id":"${DB_ID}","action":"query.write"},
    {"db_id":"${DB_ID}","action":"query.admin"},
    {"db_id":"${DB_ID}","action":"pub.publish"},
    {"db_id":"${DB_ID}","action":"pub.subscribe"},
    {"db_id":"${DB_ID}","action":"stream.read"},
    {"db_id":"${DB_ID}","action":"stream.write"},
    {"db_id":"${DB_ID}","action":"webhook.ingest"},
    {"db_id":"${DB_ID}","action":"lease.acquire"},
    {"db_id":"${DB_ID}","action":"lease.renew"},
    {"db_id":"${DB_ID}","action":"lease.release"},
    {"db_id":"${DB_ID}","action":"blob.upload"},
    {"db_id":"${DB_ID}","action":"blob.read"},
    {"db_id":"${DB_ID}","action":"blob.claim"},
    {"db_id":"${DB_ID}","action":"blob.release"},
    {"db_id":"${DB_ID}","action":"blob.publish"}
  ]
}
JSON
)"
issued_json="$(http_json "201" "POST" "/api/v1/admin/tokens" "${token_body}" "${ADMIN_TOKEN}")" || fail "failed to issue scoped token"
SCOPED_TOKEN="$(printf '%s' "${issued_json}" | jq -r '.token')"
[[ -n "${SCOPED_TOKEN}" && "${SCOPED_TOKEN}" != "null" ]] || fail "issued token response did not include plaintext token"

log "opening db runtime and executing query flows"
http_json "200" "POST" "/api/v1/db/${DB_ID}/_open" "" "${SCOPED_TOKEN}" ""
http_json "200" "POST" "/api/v1/db/${DB_ID}/query/exec" '{"sql":"CREATE TABLE IF NOT EXISTS smoke_items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)","args":[]}' "${SCOPED_TOKEN}" >/dev/null
http_json "200" "POST" "/api/v1/db/${DB_ID}/query/exec" '{"sql":"INSERT INTO smoke_items(value) VALUES (?)","args":["alpha"]}' "${SCOPED_TOKEN}" >/dev/null
query_select_json="$(http_json "200" "POST" "/api/v1/db/${DB_ID}/query/exec" '{"sql":"SELECT value FROM smoke_items ORDER BY id","args":[]}' "${SCOPED_TOKEN}")" || fail "query select failed"
if [[ "$(printf '%s' "${query_select_json}" | jq -r '.rows[0][0]')" != "alpha" ]]; then
  fail "unexpected query result payload"
fi

log "checking reactive query watch snapshot/update"
watch_out_file="$(mktemp)"
TEMP_DIRS+=("${watch_out_file}")
curl -sS -N --max-time 15 \
  -X POST "${BASE_URL}/api/v1/db/${DB_ID}/query/watch" \
  -H "Authorization: Bearer ${SCOPED_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{"sql":"SELECT COUNT(*) AS n FROM smoke_items","args":[],"options":{"heartbeat_seconds":1}}' \
  >"${watch_out_file}" 2>&1 &
watch_pid="$!"
if ! wait_for_pattern "${watch_out_file}" "event: snapshot" 80 0.1; then
  kill "${watch_pid}" >/dev/null 2>&1 || true
  fail "query watch did not emit snapshot event"
fi
http_json "200" "POST" "/api/v1/db/${DB_ID}/query/exec" '{"sql":"INSERT INTO smoke_items(value) VALUES (?)","args":["beta"]}' "${SCOPED_TOKEN}" >/dev/null
if ! wait_for_pattern "${watch_out_file}" "event: update" 80 0.1; then
  kill "${watch_pid}" >/dev/null 2>&1 || true
  fail "query watch did not emit update event after write"
fi
kill "${watch_pid}" >/dev/null 2>&1 || true
wait "${watch_pid}" >/dev/null 2>&1 || true

log "checking durable message publish + replay subscribe"
publish_json="$(http_json "201" "POST" "/api/v1/db/${DB_ID}/messages" '{"topic":"smoke/events","payload_text":"hello-events"}' "${SCOPED_TOKEN}")" || fail "message publish failed"
msg_id="$(printf '%s' "${publish_json}" | jq -r '.id')"
[[ "${msg_id}" =~ ^[0-9]+$ ]] || fail "message publish response missing id"
since_id=$((msg_id - 1))
events_out_file="$(mktemp)"
TEMP_DIRS+=("${events_out_file}")
curl -sS -N --max-time 8 \
  "${BASE_URL}/api/v1/db/${DB_ID}/events/stream?topic=smoke/%23&since_id=${since_id}" \
  -H "Authorization: Bearer ${SCOPED_TOKEN}" \
  >"${events_out_file}" 2>&1 || true
grep -q "event: message" "${events_out_file}" || fail "message replay stream missing message event"
grep -q '"topic":"smoke/events"' "${events_out_file}" || fail "message replay payload missing expected topic"

log "checking stream queue rendezvous"
queue_recv_file="$(mktemp)"
TEMP_DIRS+=("${queue_recv_file}")
curl -sS --max-time 8 \
  "${BASE_URL}/api/v1/db/${DB_ID}/streams/queue/jobs/next" \
  -H "Authorization: Bearer ${SCOPED_TOKEN}" \
  >"${queue_recv_file}" 2>&1 &
queue_recv_pid="$!"
sleep 0.3
http_json "200" "POST" "/api/v1/db/${DB_ID}/streams/queue/jobs" "queue-payload" "${SCOPED_TOKEN}" "text/plain" >/dev/null
wait "${queue_recv_pid}" >/dev/null 2>&1 || fail "queue receive request failed"
if [[ "$(cat "${queue_recv_file}")" != "queue-payload" ]]; then
  fail "queue receive payload mismatch"
fi

log "checking stream req/res flow"
responder_file="$(mktemp)"
TEMP_DIRS+=("${responder_file}")
curl -sS --max-time 8 \
  -X POST "${BASE_URL}/api/v1/db/${DB_ID}/streams/res/echo" \
  -H "Authorization: Bearer ${SCOPED_TOKEN}" \
  -H "Content-Type: text/plain" \
  --data "pong" \
  >"${responder_file}" 2>&1 &
responder_pid="$!"
sleep 0.3
req_file="$(mktemp)"
TEMP_DIRS+=("${req_file}")
req_status="$(
  curl -sS -o "${req_file}" -w '%{http_code}' \
    -X POST "${BASE_URL}/api/v1/db/${DB_ID}/streams/req/echo" \
    -H "Authorization: Bearer ${SCOPED_TOKEN}" \
    -H "Content-Type: text/plain" \
    --data "ping"
)"
[[ "${req_status}" == "200" ]] || fail "stream requester failed with status ${req_status}"
wait "${responder_pid}" >/dev/null 2>&1 || fail "stream responder request failed"
if [[ "$(cat "${req_file}")" != "pong" ]]; then
  fail "stream requester did not receive responder payload"
fi

log "checking webhook ingest persistence"
http_json "201" "POST" "/api/v1/db/${DB_ID}/webhooks/inbound" '{"event":"smoke"}' "${SCOPED_TOKEN}" >/dev/null
webhook_count_json="$(http_json "200" "POST" "/api/v1/db/${DB_ID}/query/exec" '{"sql":"SELECT COUNT(*) AS c FROM webhook_inbox WHERE endpoint = ?","args":["inbound"]}' "${SCOPED_TOKEN}")" || fail "webhook count query failed"
webhook_count="$(printf '%s' "${webhook_count_json}" | jq -r '.rows[0][0]')"
[[ "${webhook_count}" =~ ^[0-9]+$ ]] || fail "invalid webhook count value"
(( webhook_count >= 1 )) || fail "webhook row was not persisted"

log "checking lease acquire/renew/release"
lease_acquire_json="$(http_json "200" "POST" "/api/v1/db/${DB_ID}/leases/acquire" '{"resource":"smoke/lease","owner":"smoke-owner","ttl_seconds":30}' "${SCOPED_TOKEN}")" || fail "lease acquire failed"
lease_token="$(printf '%s' "${lease_acquire_json}" | jq -r '.token')"
lease_fence="$(printf '%s' "${lease_acquire_json}" | jq -r '.fence')"
[[ -n "${lease_token}" && "${lease_token}" != "null" ]] || fail "lease acquire missing token"
[[ "${lease_fence}" =~ ^[0-9]+$ ]] || fail "lease acquire missing fence"
http_json "200" "POST" "/api/v1/db/${DB_ID}/leases/renew" "{\"resource\":\"smoke/lease\",\"owner\":\"smoke-owner\",\"token\":\"${lease_token}\",\"ttl_seconds\":30}" "${SCOPED_TOKEN}" >/dev/null
http_json "200" "POST" "/api/v1/db/${DB_ID}/leases/release" "{\"resource\":\"smoke/lease\",\"owner\":\"smoke-owner\",\"token\":\"${lease_token}\"}" "${SCOPED_TOKEN}" >/dev/null

log "checking blob upload/finalize/publish/public read"
blob_src_dir="$(new_tmp)"
blob_src_path="${blob_src_dir}/archive.txt"
printf 'patchwork smoke blob %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"${blob_src_path}"
blob_hash="$(sha256_file "${blob_src_path}")"
blob_init_json="$(http_json "200" "POST" "/api/v1/db/${DB_ID}/blobs/init-upload" "{\"hash\":\"${blob_hash}\",\"content_type\":\"text/plain\"}" "${SCOPED_TOKEN}")" || fail "blob init-upload failed"
upload_url="$(printf '%s' "${blob_init_json}" | jq -r '.upload_url')"
[[ -n "${upload_url}" && "${upload_url}" != "null" ]] || fail "blob init-upload missing upload_url"
http_file_upload "200" "PUT" "${upload_url}" "${blob_src_path}" "${SCOPED_TOKEN}" "text/plain" >/dev/null
http_json "200" "POST" "/api/v1/db/${DB_ID}/blobs/complete-upload" "{\"hash\":\"${blob_hash}\"}" "${SCOPED_TOKEN}" >/dev/null
http_json "200" "POST" "/api/v1/db/${DB_ID}/blobs/${blob_hash}/publish" '{}' "${SCOPED_TOKEN}" >/dev/null
public_blob_file="$(mktemp)"
TEMP_DIRS+=("${public_blob_file}")
public_status="$(curl -sS -o "${public_blob_file}" -w '%{http_code}' "${BASE_URL}/o/${blob_hash}.txt")"
[[ "${public_status}" == "200" ]] || fail "public blob read failed with status ${public_status}"
cmp -s "${blob_src_path}" "${public_blob_file}" || fail "public blob content mismatch"

log "smoke suite completed successfully"
