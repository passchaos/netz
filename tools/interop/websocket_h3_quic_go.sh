#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz RFC 9220 client executable path}
server=${2:?netz RFC 9220 server executable path}
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
fixture_dir="$quicz_root/examples/interop/go_echo_client"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
version=${NETZ_WEBSOCKET_H3_INTEROP_VERSION:-1}
if [[ "$version" != 1 && "$version" != 2 ]]; then
  echo "invalid WebSocket-over-H3 QUIC version: $version" >&2
  exit 2
fi
go_version_args=()
netz_version_args=()
if [[ "$version" == 2 ]]; then
  go_version_args=(-v2-only)
  netz_version_args=(--version=2)
fi
if [[ ! -f "$fixture_dir/go.mod" ]]; then
  echo "audited quic-go fixture module not found under $fixture_dir" >&2
  exit 127
fi
if ! command -v go >/dev/null 2>&1; then
  echo 'go not found; install it to build the quic-go RFC 9220 peer' >&2
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

# Build inside the external module so its pinned quic-go version supplies the
# HTTP/3 implementation, without modifying that checkout.
(cd "$fixture_dir" && go build \
  -o "$work/quic-go-rfc9220-peer" \
  "$repo_root/tools/interop/websocket_h3_quic_go.go")

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port=$(free_udp_port)
"$work/quic-go-rfc9220-peer" \
  -mode server -addr "127.0.0.1:$port" \
  -ca-out "$work/quic-go-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-ca.pem" ]] &&
      grep -q 'quic-go RFC 9220 server listening=' \
        "$work/quic-go-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/quic-go-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/quic-go-ca.pem" ]] || ! \
    grep -q 'quic-go RFC 9220 server listening=' \
      "$work/quic-go-server.log"; then
  echo 'timed out waiting for quic-go RFC 9220 server' >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" "$work/quic-go-ca.pem" \
    "${netz_version_args[@]}" >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "netz RFC 9220 client interoperated with quic-go: version=$version extended_connect=true tls_verified=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/netz-client.log"
grep -Fq \
  "quic-go RFC 9220 server interoperated with netz: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/quic-go-server.log"
cat "$work/netz-client.log"
cat "$work/quic-go-server.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

port=$(free_udp_port)
"$server" "$port" "${netz_version_args[@]}" \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz RFC 9220 quic-go interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz RFC 9220 quic-go interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz RFC 9220 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-rfc9220-peer" \
    -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
    "${go_version_args[@]}" >"$work/quic-go-client.log" 2>&1; then
  cat "$work/quic-go-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "quic-go RFC 9220 client interoperated with netz: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/quic-go-client.log"
grep -Fq \
  "netz RFC 9220 server interoperated with quic-go: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/netz-server.log"
cat "$work/quic-go-client.log"
cat "$work/netz-server.log"

if [[ "$version" == 1 ]]; then
  NETZ_WEBSOCKET_H3_INTEROP_VERSION=2 "$0" "$client" "$server"
fi
