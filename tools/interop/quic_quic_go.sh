#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz client executable path}
server=${2:?netz server executable path}
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
(cd "$go_server_dir" && go build \
  -o "$work/quic-go-client" .)
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
if [[ ! -s "$work/ca.pem" ]] || ! grep -q 'listening=' \
    "$work/server.log"; then
  echo 'timed out waiting for quic-go server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

timeout 20s "$client" "$port" "$work/ca.pem"
echo 'quic-go server -> netz client interop passed'
wait "$server_pid"
server_pid=
grep -q 'handshake_done=true echo_streams=2 echo_bytes=10' \
  "$work/server.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
port=$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz QUIC interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz QUIC interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz QUIC server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi

timeout 20s "$work/quic-go-client" \
  -addr "127.0.0.1:$port" \
  -ca "$work/netz-ca.pem" \
  -server-name localhost
wait "$server_pid"
server_pid=
grep -q 'alpn=hq-interop streams=2 bytes=10' "$work/netz-server.log"
echo 'quic-go client -> netz server interop passed'
