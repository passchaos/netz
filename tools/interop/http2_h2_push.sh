#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz HTTP/2 push client executable path}
netz_server=${2:?netz HTTP/2 push server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
peer="$repo_root/tools/hyper_http2_flow/target/release/netz-h2-push-peer"
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
  --manifest-path "$manifest" --bin netz-h2-push-peer

run_netz_client_case() {
  local transport=$1
  local port
  port=$(free_tcp_port)
  local peer_args=(server "$port")
  local client_args=("$port")
  if [[ "$transport" == tls ]]; then
    peer_args+=("$work/cert.pem" "$work/key.pem")
    client_args+=("$work/cert.pem")
  fi
  "$peer" "${peer_args[@]}" >"$work/h2-server-$transport.log" 2>&1 &
  server_pid=$!
  wait_for_server "$work/h2-server-$transport.log" \
    "h2 push interop server listening"
  timeout 10s "$netz_client" "${client_args[@]}" \
    >"$work/netz-client-$transport.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "netz HTTP/2 client accepted h2 server push: transport=$transport parent_stream=1 promised_stream=2 path=/style.css body=16 client_io=zio-std-io server_io=rust-h2-tokio" \
    "$work/netz-client-$transport.log"
  grep -Fq "h2 server pushed to netz: parent_stream=1 promised_stream=2 path=/style.css body=16 client_io=zio-std-io server_io=rust-h2-tokio" \
    "$work/h2-server-$transport.log"
  cat "$work/netz-client-$transport.log"
  cat "$work/h2-server-$transport.log"
}

run_h2_client_case() {
  local transport=$1
  local port
  port=$(free_tcp_port)
  local server_args=("$port")
  local client_args=(client "$port")
  if [[ "$transport" == tls ]]; then
    server_args+=(--tls)
    client_args+=("$work/cert.pem")
  fi
  "$netz_server" "${server_args[@]}" >"$work/netz-server-$transport.log" 2>&1 &
  server_pid=$!
  wait_for_server "$work/netz-server-$transport.log" \
    "netz HTTP/2 push interop server listening"
  timeout 10s "$peer" "${client_args[@]}" \
    >"$work/h2-client-$transport.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "h2 client disabled netz push: request_stream=1 promise_rejected=true parent_status=204 client_io=rust-h2-tokio server_io=zio-std-io" \
    "$work/h2-client-$transport.log"
  grep -Fq "netz HTTP/2 server honored h2 push opt-out: transport=$transport request_stream=1 promise_rejected=true parent_status=204 client_io=rust-h2-tokio server_io=zio-std-io" \
    "$work/netz-server-$transport.log"
  cat "$work/h2-client-$transport.log"
  cat "$work/netz-server-$transport.log"
}

run_netz_informational_client_case() {
  local transport=$1
  local port
  port=$(free_tcp_port)
  local peer_args=(informational-server "$port")
  local client_args=("$port")
  if [[ "$transport" == tls ]]; then
    peer_args+=("$work/cert.pem" "$work/key.pem")
    client_args+=("$work/cert.pem")
  fi
  "$peer" "${peer_args[@]}" \
    >"$work/h2-informational-server-$transport.log" 2>&1 &
  server_pid=$!
  wait_for_server "$work/h2-informational-server-$transport.log" \
    "h2 informational interop server listening"
  timeout 10s "$netz_client" "${client_args[@]}" --informational \
    >"$work/netz-informational-client-$transport.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "netz HTTP/2 client observed h2 informational responses: transport=$transport statuses=103,102 final=200 body=5 client_io=zio-std-io server_io=rust-h2-tokio" \
    "$work/netz-informational-client-$transport.log"
  grep -Fq "h2 server sent informational responses to netz: statuses=103,102 final=200 body=5 client_io=zio-std-io server_io=rust-h2-tokio" \
    "$work/h2-informational-server-$transport.log"
  cat "$work/netz-informational-client-$transport.log"
  cat "$work/h2-informational-server-$transport.log"
}

run_h2_informational_client_case() {
  local transport=$1
  local port
  port=$(free_tcp_port)
  local server_args=("$port" --informational)
  local client_args=(informational-client "$port")
  if [[ "$transport" == tls ]]; then
    server_args+=(--tls)
    client_args+=("$work/cert.pem")
  fi
  "$netz_server" "${server_args[@]}" \
    >"$work/netz-informational-server-$transport.log" 2>&1 &
  server_pid=$!
  wait_for_server "$work/netz-informational-server-$transport.log" \
    "netz HTTP/2 informational interop server listening"
  timeout 10s "$peer" "${client_args[@]}" \
    >"$work/h2-informational-client-$transport.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "h2 client received netz informational responses: statuses=103,102 final=200 body=5 client_io=rust-h2-tokio server_io=zio-std-io" \
    "$work/h2-informational-client-$transport.log"
  grep -Fq "netz HTTP/2 server sent informational responses to h2: transport=$transport statuses=103,102 final=200 body=5 client_io=rust-h2-tokio server_io=zio-std-io" \
    "$work/netz-informational-server-$transport.log"
  cat "$work/h2-informational-client-$transport.log"
  cat "$work/netz-informational-server-$transport.log"
}

run_netz_client_case h2c
run_netz_client_case tls
run_h2_client_case h2c
run_h2_client_case tls
run_netz_informational_client_case h2c
run_netz_informational_client_case tls
run_h2_informational_client_case h2c
run_h2_informational_client_case tls
