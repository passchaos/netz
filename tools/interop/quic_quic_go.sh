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

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

require_log() {
  local expected=$1
  local log=$2
  if ! grep -Fq "$expected" "$log"; then
    echo "missing expected output '$expected' in $log" >&2
    cat "$log" >&2
    return 1
  fi
}

run_quic_go_client_scenario() {
  local mode=$1
  local client_flag=$2
  local client_result=$3
  local server_result=$4
  local port
  port=$(free_udp_port)
  local server_log="$work/netz-server-$mode.log"
  local client_log="$work/quic-go-client-$mode.log"

  "$server" "$port" "$mode" >"$server_log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if [[ -f "$server_log" ]] &&
        grep -q 'netz QUIC interop server listening' "$server_log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$server_log" >&2
      return 1
    fi
    sleep 0.05
  done
  if [[ ! -f "$server_log" ]] ||
      ! grep -q 'netz QUIC interop server listening' "$server_log"; then
    echo "timed out waiting for netz QUIC $mode server" >&2
    cat "$server_log" >&2
    return 1
  fi

  local client_args=(
    -addr "127.0.0.1:$port"
    -ca "$work/netz-ca.pem"
    -server-name localhost
  )
  if [[ -n "$client_flag" ]]; then
    client_args+=("$client_flag")
  fi
  if ! timeout 20s "$work/quic-go-client" \
      "${client_args[@]}" >"$client_log" 2>&1; then
    cat "$client_log" >&2
    cat "$server_log" >&2
    return 1
  fi
  cat "$client_log"

  if wait "$server_pid"; then
    server_pid=
  else
    local status=$?
    server_pid=
    cat "$server_log" >&2
    return "$status"
  fi
  require_log "$client_result" "$client_log"
  require_log "$server_result" "$server_log"
  echo "quic-go client -> netz server $mode interop passed"
}

run_quic_go_client_scenario \
  echo \
  '' \
  'go_quic_echo_client: handshake_done=true echo_streams=2 echo_bytes=10' \
  'alpn=hq-interop streams=2 bytes=10'
run_quic_go_client_scenario \
  reset \
  -expect-reset \
  'go_quic_reset_client: handshake_done=true reset_error=41 echo_stream=4 echo_bytes=5' \
  'alpn=hq-interop reset_error=41 echo_stream=4 echo_bytes=5'
run_quic_go_client_scenario \
  stop \
  -expect-stop-sending \
  'go_quic_stop_sending_client: handshake_done=true stop_error=42 reset_error=42 echo_stream=4 echo_bytes=5' \
  'alpn=hq-interop stop_error=42 reset_error=42 echo_stream=4 echo_bytes=5'
run_quic_go_client_scenario \
  flow \
  -expect-flow-control \
  'go_quic_flow_control_client: handshake_done=true stream_bytes=12288 echo_bytes=12288' \
  'alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 stream_bytes=12288 echo_bytes=12288'
