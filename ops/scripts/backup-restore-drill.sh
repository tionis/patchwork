#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DATA_DIR="${1:-${PATCHWORK_DATA_DIR:-}}"
BACKUP_ROOT="${2:-${PATCHWORK_BACKUP_DIR:-./backups}}"
RESTORE_DIR="${3:-}"

if [[ -z "${DATA_DIR}" ]]; then
  echo "usage: $0 <data-dir> [backup-root] [restore-dir]" >&2
  echo "or set PATCHWORK_DATA_DIR/PATCHWORK_BACKUP_DIR" >&2
  exit 1
fi

if [[ -z "${RESTORE_DIR}" ]]; then
  RESTORE_DIR="$(mktemp -d)"
  cleanup_restore_dir=1
else
  cleanup_restore_dir=0
fi

cleanup() {
  if [[ "${cleanup_restore_dir}" == "1" ]]; then
    rm -rf "${RESTORE_DIR}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

drill_started_epoch="$(date +%s)"

backup_output="$("${SCRIPT_DIR}/backup.sh" "${DATA_DIR}" "${BACKUP_ROOT}")"
snapshot_dir="$(printf '%s\n' "${backup_output}" | sed -n 's/^backup_created=//p')"
backup_duration="$(printf '%s\n' "${backup_output}" | sed -n 's/^backup_duration_seconds=//p')"

if [[ -z "${snapshot_dir}" || ! -d "${snapshot_dir}" ]]; then
  echo "failed to discover backup snapshot from backup output" >&2
  echo "${backup_output}" >&2
  exit 1
fi

restore_output="$("${SCRIPT_DIR}/restore.sh" "${snapshot_dir}" "${RESTORE_DIR}")"
restore_duration="$(printf '%s\n' "${restore_output}" | sed -n 's/^restore_duration_seconds=//p')"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 CLI is required for integrity verification" >&2
  exit 1
fi

integrity_result="$(sqlite3 "${RESTORE_DIR}/service.db" "PRAGMA integrity_check;")"
if [[ "${integrity_result}" != "ok" ]]; then
  echo "restore integrity check failed for service.db: ${integrity_result}" >&2
  exit 1
fi

if [[ -d "${RESTORE_DIR}/documents" ]]; then
  while IFS= read -r -d '' db_file; do
    result="$(sqlite3 "${db_file}" "PRAGMA integrity_check;")"
    if [[ "${result}" != "ok" ]]; then
      echo "restore integrity check failed for ${db_file}: ${result}" >&2
      exit 1
    fi
  done < <(find "${RESTORE_DIR}/documents" -maxdepth 1 -type f -name '*.sqlite3' -print0)
fi

drill_finished_epoch="$(date +%s)"
drill_duration="$((drill_finished_epoch - drill_started_epoch))"

# For a quiesced drill snapshot, effective RPO is 0 by construction.
cat <<EOF
drill_snapshot=${snapshot_dir}
drill_restore_dir=${RESTORE_DIR}
drill_total_duration_seconds=${drill_duration}
drill_backup_duration_seconds=${backup_duration}
drill_restore_duration_seconds=${restore_duration}
drill_measured_rto_seconds=${restore_duration}
drill_estimated_rpo_seconds=0
EOF
