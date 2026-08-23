#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz HTTP/3 client executable path}
server=${2:?netz HTTP/3 server executable path}
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
fixture_dir="$quicz_root/examples/interop/go_echo_client"
netz_root=$(cd "$(dirname "$0")/../.." && pwd)
version=${NETZ_HTTP3_INTEROP_VERSION:-1}
if [[ "$version" != 1 && "$version" != 2 ]]; then
  echo "invalid HTTP/3 QUIC version: $version" >&2
  exit 2
fi
go_version_args=()
netz_version_args=()
if [[ "$version" == 2 ]]; then
  go_version_args=(-v2-only)
  netz_version_args=(--version=2)
fi
if [[ ! -f "$fixture_dir/http3_peer/main.go" ]]; then
  echo "quic-go HTTP/3 fixture not found under $fixture_dir" >&2
  exit 127
fi
if ! command -v go >/dev/null 2>&1; then
  echo "go not found; install it to build the quic-go HTTP/3 fixture" >&2
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

(cd "$fixture_dir" && go build \
  -o "$work/quic-go-http3-peer" ./http3_peer)
(cd "$fixture_dir" && go build \
  -o "$work/quic-go-http3-informational-peer" \
  "$netz_root/tools/interop/http3_quic_go_informational.go")

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port=$(free_udp_port)
"$work/quic-go-http3-peer" \
  -mode server -addr "127.0.0.1:$port" -ca-out "$work/quic-go-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-ca.pem" ]] && \
      grep -q 'quic-go HTTP/3 interop server listening=' \
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
    grep -q 'quic-go HTTP/3 interop server listening=' \
      "$work/quic-go-server.log"; then
  echo 'timed out waiting for quic-go HTTP/3 server' >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" "$work/quic-go-ca.pem" \
    "${netz_version_args[@]}" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 concurrent_sibling=true stream_window=8192 read_before_cancel>=12288 large_response=131072 request_body=12 request_trailers=1 response_body=16 response_trailers=1" \
  "$work/netz-client.log"
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED concurrent_sibling=true stream_window=8192 large_response=131072 request_body=12 request_trailers=1 response_body=16 response_trailers=1" \
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
  if grep -q 'netz HTTP/3 quic-go interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/3 quic-go interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz HTTP/3 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-http3-peer" \
    -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
    "${go_version_args[@]}" \
    >"$work/quic-go-client.log" 2>&1; then
  cat "$work/quic-go-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 stop_sending_transmissions>=2 concurrent_sibling=true connection_reused=true stream_window=8192 read_before_cancel=12288 large_response=131072 request_body=15 request_trailers=1 response_body=13 response_trailers=1" \
  "$work/quic-go-client.log"
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED concurrent_sibling=true connection_reused=true stream_window=8192 read_before_cancel=12288 large_response=131072 request_body=15 request_trailers=1 response_body=13 response_trailers=1" \
  "$work/netz-server.log"
cat "$work/quic-go-client.log"
cat "$work/netz-server.log"

port=$(free_udp_port)
"$work/quic-go-http3-informational-peer" \
  -mode server -addr "127.0.0.1:$port" \
  -ca-out "$work/quic-go-informational-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-informational-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-informational-ca.pem" ]] && \
      grep -q 'quic-go HTTP/3 informational server listening=' \
        "$work/quic-go-informational-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/quic-go-informational-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/quic-go-informational-ca.pem" ]] || ! \
    grep -q 'quic-go HTTP/3 informational server listening=' \
      "$work/quic-go-informational-server.log"; then
  echo 'timed out waiting for quic-go HTTP/3 informational server' >&2
  cat "$work/quic-go-informational-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" \
  "$work/quic-go-informational-ca.pem" --informational \
  "${netz_version_args[@]}" \
  >"$work/netz-informational-client.log" 2>&1; then
  cat "$work/netz-informational-client.log" >&2
  cat "$work/quic-go-informational-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "netz HTTP/3 client observed quic-go informational responses: version=$version statuses=103,102 final=200 body=5" \
  "$work/netz-informational-client.log"
grep -Fq \
  "quic-go HTTP/3 server sent informational responses to netz: version=$version statuses=103,102 final=200 body=5" \
  "$work/quic-go-informational-server.log"
cat "$work/netz-informational-client.log"
cat "$work/quic-go-informational-server.log"

port=$(free_udp_port)
"$server" "$port" --informational "${netz_version_args[@]}" \
  >"$work/netz-informational-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/3 quic-go interop server listening' \
      "$work/netz-informational-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-informational-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/3 quic-go interop server listening' \
    "$work/netz-informational-server.log"; then
  echo 'timed out waiting for netz HTTP/3 informational server' >&2
  cat "$work/netz-informational-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-http3-informational-peer" \
  -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-informational-client.log" 2>&1; then
  cat "$work/quic-go-informational-client.log" >&2
  cat "$work/netz-informational-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "quic-go HTTP/3 client received netz informational responses: version=$version statuses=103,102 final=200 body=5" \
  "$work/quic-go-informational-client.log"
grep -Fq \
  "netz HTTP/3 server sent informational responses to quic-go: version=$version statuses=103,102 final=200 body=5" \
  "$work/netz-informational-server.log"
cat "$work/quic-go-informational-client.log"
cat "$work/netz-informational-server.log"

if [[ "$version" == 1 ]]; then
  NETZ_HTTP3_INTEROP_VERSION=2 "$0" "$client" "$server"
fi
