#!/usr/bin/env bash
# Isolated end-to-end demonstration. Leaves data and logs for inspection.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --bins
patchwork_demo_dir=$(mktemp -d /tmp/patchwork-demo.XXXXXX)
patchwork_demo_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)
patchwork_demo_url="http://127.0.0.1:$patchwork_demo_port"
patchwork_cli=./target/debug/patchwork
ssh-keygen -q -t ed25519 -N '' -f "$patchwork_demo_dir/key"
"$patchwork_cli" admin bootstrap --data-dir "$patchwork_demo_dir/data" \
    --ssh-public-key "$patchwork_demo_dir/key.pub" --origin "$patchwork_demo_url"
./target/debug/patchwork-server --data-dir "$patchwork_demo_dir/data" \
    --listen "127.0.0.1:$patchwork_demo_port" --data-api \
    >"$patchwork_demo_dir/server.stdout" 2>"$patchwork_demo_dir/server.log" &
patchwork_demo_pid=$!
trap 'kill "$patchwork_demo_pid" 2>/dev/null || true; wait "$patchwork_demo_pid" 2>/dev/null || true' EXIT
for _ in {1..100}; do
    if "$patchwork_cli" health --url "$patchwork_demo_url" >/dev/null 2>&1; then break; fi
    kill -0 "$patchwork_demo_pid"
    sleep 0.1
done
"$patchwork_cli" health --url "$patchwork_demo_url"
"$patchwork_cli" login --url "$patchwork_demo_url" --ssh-key "$patchwork_demo_dir/key" \
    --ssh-public-key "$patchwork_demo_dir/key.pub" --output "$patchwork_demo_dir/session"
"$patchwork_cli" stream --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/session" \
    create events/demo >"$patchwork_demo_dir/stream.json"
patchwork_demo_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <"$patchwork_demo_dir/stream.json")
printf '\000\377hello Patchwork\n' >"$patchwork_demo_dir/input.bin"
"$patchwork_cli" append --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/session" \
    "$patchwork_demo_id" <"$patchwork_demo_dir/input.bin"
cat >"$patchwork_demo_dir/read-scope.json" <<'JSON'
[{"actions":["record.read"],"selector":{"kind":"prefix","value":"events/"}}]
JSON
"$patchwork_cli" token --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/session" mint \
    --scope-file "$patchwork_demo_dir/read-scope.json" --output "$patchwork_demo_dir/reader"
"$patchwork_cli" get --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/reader" \
    "$patchwork_demo_id" 0 >"$patchwork_demo_dir/output.bin"
cmp "$patchwork_demo_dir/input.bin" "$patchwork_demo_dir/output.bin"
if "$patchwork_cli" append --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/reader" \
    "$patchwork_demo_id" <"$patchwork_demo_dir/input.bin" 2>"$patchwork_demo_dir/denied.log"; then
    echo 'Read-only credential unexpectedly appended a record' >&2
    exit 1
fi
"$patchwork_cli" read --url "$patchwork_demo_url" --token-file "$patchwork_demo_dir/reader" "$patchwork_demo_id"
printf 'Prototype passed: binary round trip and read-only enforcement. Data and logs: %s\n' "$patchwork_demo_dir"
