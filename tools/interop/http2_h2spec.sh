#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
h2spec=${H2SPEC:-h2spec}
if ! command -v "$h2spec" >/dev/null 2>&1 && [[ ! -x "$h2spec" ]]; then
  echo "h2spec not found; install it or set H2SPEC=/absolute/path/to/h2spec" >&2
  exit 127
fi

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
  if grep -q 'h2spec server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'h2spec server listening' "$work/server.log"; then
  echo 'timed out waiting for netz h2spec server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

"$h2spec" --host 127.0.0.1 --port "$port" --timeout 2 "$@"
