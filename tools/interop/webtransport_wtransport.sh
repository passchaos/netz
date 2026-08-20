#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
client_manifest="$repo_root/tools/interop/webtransport_wtransport/Cargo.toml"
work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 && -s "$work/server.log" ]]; then
    cat "$work/server.log" >&2
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

port=$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'WebTransport interop server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'WebTransport interop server listening' "$work/server.log"; then
  echo 'timed out waiting for netz WebTransport server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

timeout 180s cargo run --quiet --release --locked \
  --manifest-path "$client_manifest" -- "$port"
wait "$server_pid"
server_pid=
cat "$work/server.log"
