#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz RFC 8441 client executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
server="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-websocket-server"
work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-websocket-server

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper RFC 8441 server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'Hyper RFC 8441 server listening' "$work/server.log"; then
  echo 'timed out waiting for Hyper RFC 8441 server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

if ! timeout 10s "$client" "$port" >"$work/client.log" 2>&1; then
  cat "$work/client.log" >&2
  cat "$work/server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/client.log"
cat "$work/server.log"
grep -Fq \
  'netz RFC 8441 client interoperated with Hyper: fragmented-text ping pong bounded-close' \
  "$work/client.log"
grep -Fq \
  'Hyper RFC 8441 server interoperated with netz: fragmented-text ping pong bounded-close' \
  "$work/server.log"
