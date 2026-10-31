#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz RFC 8441 client executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
server="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-websocket-server"
proxy="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http-connect-proxy"
work=$(mktemp -d)
server_pid=
proxy_pid=
cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-websocket-server \
  --bin netz-hyper-http-connect-proxy

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
grep -Fq 'netz RFC 8441 Ping tolerated unsolicited Pong and preserved interleaved data: transport=h2c' "$work/client.log"
grep -Fq 'Hyper RFC 8441 Ping fixture sent unsolicited Pong and interleaved application data' "$work/server.log"
grep -Fq \
  'netz RFC 8441 client interoperated with Hyper: transport=h2c fragmented-text ping pong bounded-close tls_metadata=n/a key_update=n/a client_io=zio-std-io server_io=hyper-tokio' \
  "$work/client.log"
grep -Fq \
  'Hyper RFC 8441 server interoperated with netz: fragmented-text ping pong bounded-close client_io=zio-std-io server_io=hyper-tokio' \
  "$work/server.log"

cat >"$work/cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
cat >"$work/key.pem" <<'EOF'
-----BEGIN EC PRIVATE KEY-----
MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI0oAoGCCqGSM49AwEH
-----END EC PRIVATE KEY-----
EOF

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" "$work/cert.pem" "$work/key.pem" \
  >"$work/tls-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper RFC 8441 server listening' "$work/tls-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/tls-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! timeout 10s "$client" "$port" "$work/cert.pem" \
    >"$work/tls-client.log" 2>&1; then
  cat "$work/tls-client.log" >&2
  cat "$work/tls-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/tls-client.log"
cat "$work/tls-server.log"
grep -Fq 'netz RFC 8441 Ping tolerated unsolicited Pong and preserved interleaved data: transport=tls' "$work/tls-client.log"
grep -Fq 'Hyper RFC 8441 Ping fixture sent unsolicited Pong and interleaved application data' "$work/tls-server.log"
grep -Fq \
  'netz RFC 8441 client interoperated with Hyper: transport=tls fragmented-text ping pong bounded-close tls_metadata=verified key_update=verified client_io=zio-std-io server_io=hyper-tokio' \
  "$work/tls-client.log"
grep -Fq \
  'rustls RFC 8441 server sent TLS KeyUpdate request' \
  "$work/tls-server.log"
grep -Fq \
  'Hyper RFC 8441 server interoperated with netz: fragmented-text ping pong bounded-close client_io=zio-std-io server_io=hyper-tokio' \
  "$work/tls-server.log"

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
proxy_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" "$work/cert.pem" "$work/key.pem" \
  >"$work/proxy-origin.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper RFC 8441 server listening' "$work/proxy-origin.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/proxy-origin.log" >&2
    exit 1
  fi
  sleep 0.05
done
"$proxy" "$proxy_port" >"$work/proxy.log" 2>&1 &
proxy_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper CONNECT proxy listening' "$work/proxy.log"; then
    break
  fi
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    cat "$work/proxy.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! timeout 10s "$client" "$port" "$work/cert.pem" \
    --proxy "$proxy_port" >"$work/proxy-client.log" 2>&1; then
  cat "$work/proxy-client.log" >&2
  cat "$work/proxy.log" >&2
  cat "$work/proxy-origin.log" >&2
  exit 1
fi
if ! wait "$server_pid"; then
  server_pid=
  cat "$work/proxy-client.log" >&2
  cat "$work/proxy.log" >&2
  cat "$work/proxy-origin.log" >&2
  exit 1
fi
server_pid=
if ! wait "$proxy_pid"; then
  proxy_pid=
  cat "$work/proxy-client.log" >&2
  cat "$work/proxy.log" >&2
  cat "$work/proxy-origin.log" >&2
  exit 1
fi
proxy_pid=
grep -Fq \
  "netz RFC 8441 client tunneled Hyper TLS through Hyper CONNECT proxy: origin=localhost:$port scheme=https authority=exact proxy_authorization=isolated client_io=zio-std-io proxy_io=hyper-tokio server_io=hyper-tokio" \
  "$work/proxy-client.log"
grep -Fq \
  "Hyper CONNECT proxy tunneled netz TLS HTTP/2: authority=localhost:$port proxy_authorization=true client_io=zio-std-io proxy_io=hyper-tokio" \
  "$work/proxy.log"
grep -Fq \
  'Hyper RFC 8441 server interoperated with netz: fragmented-text ping pong bounded-close client_io=zio-std-io server_io=hyper-tokio' \
  "$work/proxy-origin.log"
cat "$work/proxy-client.log"
cat "$work/proxy.log"
echo 'netz RFC 8441 -> Hyper CONNECT proxy -> Hyper TLS/h2 server interop passed'
