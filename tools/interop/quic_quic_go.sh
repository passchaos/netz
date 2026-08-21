#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz client executable path}
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
go_server_dir="$quicz_root/examples/interop/go_echo_client"
if [[ ! -f "$go_server_dir/echo_server/main.go" ]]; then
  echo "quicz quic-go fixture not found under $go_server_dir" >&2
  exit 127
fi
if ! command -v go >/dev/null 2>&1; then
  echo "go not found; install it to build the quic-go interop fixture" >&2
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

(cd "$go_server_dir" && go build \
  -o "$work/quic-go-server" ./echo_server)
port=$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$work/quic-go-server" \
  -addr "127.0.0.1:$port" \
  -ca-out "$work/ca.pem" \
  >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/ca.pem" ]] && grep -q 'listening=' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/ca.pem" ]] || ! grep -q 'listening=' "$work/server.log"; then
  echo 'timed out waiting for quic-go server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

timeout 20s "$client" "$port" "$work/ca.pem"
echo 'quic-go server -> netz client interop passed'
