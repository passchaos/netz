#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz client executable path}
server=${2:?netz server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
server_binary="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-interop-server"
hyper_client_binary="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-interop-client"
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

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_server() {
  local log=$1
  local marker=$2
  for _ in $(seq 1 200); do
    if grep -q "$marker" "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for $marker" >&2
  cat "$log" >&2
  exit 1
}

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
  --bin netz-hyper-http2-interop-server \
  --bin netz-hyper-http2-interop-client

port=$(free_tcp_port)

"$server_binary" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper HTTP/2 interop server listening' "$work/server.log" \
      2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'Hyper HTTP/2 interop server listening' "$work/server.log" \
    2>/dev/null; then
  echo 'timed out waiting for Hyper HTTP/2 server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

if ! timeout 10s "$client" "$port" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/netz-client.log"
grep -Fq \
  'netz HTTP/2 client canceled flow-blocked Hyper stream and completed concurrent sibling: transport=h2c rst=CANCEL window=8192 received=8192 sibling=16384' \
  "$work/netz-client.log"
grep -Fq \
  'netz HTTP/2 keep-alive interoperated with Hyper: transport=h2c ack=true next_request=true' \
  "$work/netz-client.log"
grep -Fq \
  'netz HTTP/2 client drained Hyper GOAWAY: transport=h2c active_stream=9 new_request_refused=true' \
  "$work/netz-client.log"
grep -Fq \
  'Hyper HTTP/2 server gracefully drained netz client: active_stream=9 new_request_refused=true' \
  "$work/server.log"
echo 'Hyper HTTP/2 server -> netz client interop passed'

port=$(free_tcp_port)

"$server" "$port" >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/2 Hyper interop server listening' \
      "$work/netz-server.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/2 Hyper interop server listening' \
    "$work/netz-server.log" 2>/dev/null; then
  echo 'timed out waiting for netz HTTP/2 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi

if ! timeout 10s "$hyper_client_binary" "$port" \
    >"$work/hyper-client.log" 2>&1; then
  cat "$work/hyper-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
cat "$work/hyper-client.log"
wait "$server_pid"
server_pid=
grep -Fq \
  'Hyper HTTP/2 client interoperated with netz: status=201 body=13 trailers=1' \
  "$work/hyper-client.log"
grep -Fq \
  'Hyper HTTP/2 keep-alive interoperated with netz: ack=true next_request=true' \
  "$work/hyper-client.log"
grep -Fq \
  'Hyper HTTP/2 client canceled flow-blocked netz stream and completed concurrent sibling: rst=CANCEL window=8192 received=8192 sibling=16384' \
  "$work/hyper-client.log"
grep -Fq \
  'Hyper HTTP/2 client drained netz GOAWAY: active_stream=9 new_request_refused=true' \
  "$work/hyper-client.log"
grep -Fq \
  'transport=h2c alpn=n/a method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1' \
  "$work/netz-server.log"
grep -Fq \
  'netz HTTP/2 server observed flow-blocked Hyper cancellation and completed concurrent sibling: transport=h2c rst=CANCEL window=8192 offered=131072 sibling=16384' \
  "$work/netz-server.log"
grep -Fq \
  'netz HTTP/2 server remained usable after Hyper keep-alive: transport=h2c next_request=true' \
  "$work/netz-server.log"
grep -Fq \
  'netz HTTP/2 server gracefully drained Hyper client: transport=h2c last_stream=9 new_request_refused=true' \
  "$work/netz-server.log"
echo 'Hyper HTTP/2 client -> netz server interop passed'

port=$(free_tcp_port)
"$server_binary" "$port" "$work/cert.pem" "$work/key.pem" \
  >"$work/tls-hyper-server.log" 2>&1 &
server_pid=$!
wait_for_server "$work/tls-hyper-server.log" 'Hyper HTTP/2 interop server listening'
if ! timeout 10s "$client" "$port" "$work/cert.pem" \
    >"$work/tls-netz-client.log" 2>&1; then
  cat "$work/tls-netz-client.log" >&2
  cat "$work/tls-hyper-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  'transport=tls alpn=h2 status=201 body=14 trailers=1' \
  "$work/tls-netz-client.log"
grep -Fq \
  'transport=tls rst=CANCEL window=8192 received=8192 sibling=16384' \
  "$work/tls-netz-client.log"
grep -Fq \
  'netz HTTP/2 keep-alive interoperated with Hyper: transport=tls ack=true next_request=true' \
  "$work/tls-netz-client.log"
grep -Fq \
  'netz HTTP/2 client drained Hyper GOAWAY: transport=tls active_stream=9 new_request_refused=true' \
  "$work/tls-netz-client.log"
grep -Fq \
  'Hyper HTTP/2 server gracefully drained netz client: active_stream=9 new_request_refused=true' \
  "$work/tls-hyper-server.log"
cat "$work/tls-netz-client.log"
echo 'Hyper TLS HTTP/2 server -> netz client interop passed'

port=$(free_tcp_port)
"$server" "$port" --tls >"$work/tls-netz-server.log" 2>&1 &
server_pid=$!
wait_for_server "$work/tls-netz-server.log" \
  'netz HTTP/2 Hyper interop server listening'
if ! timeout 10s "$hyper_client_binary" "$port" "$work/cert.pem" \
    >"$work/tls-hyper-client.log" 2>&1; then
  cat "$work/tls-hyper-client.log" >&2
  cat "$work/tls-netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  'transport=tls alpn=h2 method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1' \
  "$work/tls-netz-server.log"
grep -Fq \
  'transport=tls rst=CANCEL window=8192 offered=131072 sibling=16384' \
  "$work/tls-netz-server.log"
grep -Fq \
  'Hyper HTTP/2 keep-alive interoperated with netz: ack=true next_request=true' \
  "$work/tls-hyper-client.log"
grep -Fq \
  'Hyper HTTP/2 client drained netz GOAWAY: active_stream=9 new_request_refused=true' \
  "$work/tls-hyper-client.log"
grep -Fq \
  'netz HTTP/2 server remained usable after Hyper keep-alive: transport=tls next_request=true' \
  "$work/tls-netz-server.log"
grep -Fq \
  'netz HTTP/2 server gracefully drained Hyper client: transport=tls last_stream=9 new_request_refused=true' \
  "$work/tls-netz-server.log"
cat "$work/tls-hyper-client.log"
cat "$work/tls-netz-server.log"
echo 'Hyper HTTP/2 client -> netz TLS server interop passed'
