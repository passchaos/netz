#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz client executable path}
server=${2:?netz server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http1_body/Cargo.toml"
hyper="$repo_root/tools/hyper_http1_body/target/release/netz-hyper-http1-interop"
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

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http1-interop

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port=$(free_tcp_port)
"$hyper" server "$port" >"$work/hyper-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper HTTP/1 interop server listening' \
      "$work/hyper-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/hyper-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'Hyper HTTP/1 interop server listening' \
    "$work/hyper-server.log"; then
  echo 'timed out waiting for Hyper HTTP/1 server' >&2
  cat "$work/hyper-server.log" >&2
  exit 1
fi
if ! timeout 10s "$client" "$port" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/hyper-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/netz-client.log"
grep -Fq \
  'netz HTTP/1 client observed Hyper 100 Continue: transport=cleartext interim=1 body=11 response_body=15' \
  "$work/netz-client.log"
grep -Fq \
  'netz HTTP/1 client handled Hyper/Tokio Expect boundaries: transport=cleartext informational=103,100 early_final=417 body_sent=0 connection_reusable=false' \
  "$work/netz-client.log"
grep -Fq \
  'netz HTTP/1 client interoperated with Hyper CONNECT tunnel: transport=cleartext buffered_server_bytes=18 client_bytes=17 reply_bytes=18' \
  "$work/netz-client.log"
grep -Fq \
  'Hyper/Tokio HTTP/1 fixture verified netz Expect boundaries and CONNECT tunnel: informational=103,100 early_final=417 body_sent=0 tunnel_bytes=17/18' \
  "$work/hyper-server.log"
echo 'Hyper HTTP/1 server -> netz client interop passed'

port=$(free_tcp_port)
"$server" "$port" >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/1 Hyper interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/1 Hyper interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz HTTP/1 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
if ! timeout 10s "$hyper" client "$port" \
    >"$work/hyper-client.log" 2>&1; then
  cat "$work/hyper-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
cat "$work/hyper-client.log"
wait "$server_pid"
server_pid=
grep -Fq \
  'Hyper HTTP/1 client interoperated with netz: status=201 body=13 trailers=1' \
  "$work/hyper-client.log"
grep -Fq \
  'Hyper HTTP/1 client observed netz 100 Continue: interim=1 body=12 response_body=14' \
  "$work/hyper-client.log"
grep -Fq \
  'transport=cleartext method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1' \
  "$work/netz-server.log"
grep -Fq \
  'netz HTTP/1 server completed Hyper Expect exchange: transport=cleartext interim=1 body=12 response_body=14' \
  "$work/netz-server.log"
grep -Fq \
  'Hyper HTTP/1 client interoperated with netz CONNECT tunnel: server_preface=17 client_bytes=18 reply_bytes=17' \
  "$work/hyper-client.log"
grep -Fq \
  'netz HTTP/1 server interoperated with Hyper CONNECT tunnel: transport=cleartext server_preface=17 client_bytes=18 reply_bytes=17' \
  "$work/netz-server.log"
echo 'Hyper HTTP/1 client -> netz server interop passed'

port=$(free_tcp_port)
"$hyper" server "$port" "$work/cert.pem" "$work/key.pem" \
  >"$work/tls-hyper-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper HTTP/1 interop server listening' \
      "$work/tls-hyper-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/tls-hyper-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! timeout 10s "$client" "$port" "$work/cert.pem" \
    >"$work/tls-netz-client.log" 2>&1; then
  cat "$work/tls-netz-client.log" >&2
  cat "$work/tls-hyper-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  'netz HTTP/1 client interoperated with Hyper: transport=tls status=201 body=14 trailers=1' \
  "$work/tls-netz-client.log"
grep -Fq \
  'netz HTTP/1 client handled Hyper/Tokio Expect boundaries: transport=tls informational=103,100 early_final=417 body_sent=0 connection_reusable=false' \
  "$work/tls-netz-client.log"
grep -Fq \
  'netz HTTP/1 client interoperated with Hyper CONNECT tunnel: transport=tls buffered_server_bytes=18 client_bytes=17 reply_bytes=18' \
  "$work/tls-netz-client.log"
grep -Fq \
  'Hyper/Tokio HTTP/1 fixture verified netz Expect boundaries and CONNECT tunnel: informational=103,100 early_final=417 body_sent=0 tunnel_bytes=17/18' \
  "$work/tls-hyper-server.log"
cat "$work/tls-netz-client.log"
echo 'Hyper HTTPS server -> netz client interop passed'

port=$(free_tcp_port)
"$server" "$port" --tls >"$work/tls-netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/1 Hyper interop server listening' \
      "$work/tls-netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/tls-netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! timeout 10s "$hyper" client "$port" "$work/cert.pem" \
    >"$work/tls-hyper-client.log" 2>&1; then
  cat "$work/tls-hyper-client.log" >&2
  cat "$work/tls-netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  'netz HTTP/1 server interoperated with Hyper: transport=tls method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1' \
  "$work/tls-netz-server.log"
grep -Fq \
  'netz HTTP/1 server completed Hyper Expect exchange: transport=tls interim=1 body=12 response_body=14' \
  "$work/tls-netz-server.log"
grep -Fq \
  'Hyper HTTP/1 client interoperated with netz CONNECT tunnel: server_preface=17 client_bytes=18 reply_bytes=17' \
  "$work/tls-hyper-client.log"
grep -Fq \
  'netz HTTP/1 server interoperated with Hyper CONNECT tunnel: transport=tls server_preface=17 client_bytes=18 reply_bytes=17' \
  "$work/tls-netz-server.log"
cat "$work/tls-hyper-client.log"
cat "$work/tls-netz-server.log"
echo 'Hyper HTTP/1 client -> netz TLS server interop passed'
