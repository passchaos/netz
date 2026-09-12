#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz QUIC client executable path}
netz_server=${2:?netz QUIC server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
fixture_dir="$quicz_root/examples/interop/go_echo_client"
if [[ ! -f $fixture_dir/go.mod ]]; then
  echo "audited quic-go fixture not found under $fixture_dir" >&2
  exit 127
fi
if ! command -v go >/dev/null 2>&1; then
  echo 'go not found' >&2
  exit 127
fi

work=$(mktemp -d)
server_pid=
proxy_pid=
proxy_control_fd=
cleanup() {
  if [[ -n ${proxy_control_fd:-} ]]; then
    exec {proxy_control_fd}>&- 2>/dev/null || true
    proxy_control_fd=
  fi
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n $proxy_pid ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local exit_status=$?
  if [[ $exit_status -ne 0 ]]; then
    find "$work" -type f -name '*.log' -size +0c -print0 | sort -z |
      while IFS= read -r -d '' log_file; do
        echo "===== $log_file =====" >&2
        sed -n '1,260p' "$log_file" >&2
      done
  fi
  cleanup
  exit "$exit_status"
}
trap on_exit EXIT

(cd "$fixture_dir" && go build -mod=readonly \
  -o "$work/quic-go-server" ./echo_server)
(cd "$fixture_dir" && go build -mod=readonly \
  -o "$work/quic-go-client" .)

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

wait_for_line() {
  local pid=$1 log=$2 prefix=$3
  local value=
  for _ in $(seq 1 600); do
    if [[ -f $log ]]; then
      value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
    fi
    if [[ -n $value ]]; then printf '%s\n' "$value"; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then return 1; fi
    sleep 0.05
  done
  return 1
}

wait_for_text() {
  local pid=$1 log=$2 expected=$3
  for _ in $(seq 1 600); do
    if [[ -f $log ]] && grep -Fq "$expected" "$log"; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then return 1; fi
    sleep 0.05
  done
  return 1
}

start_proxy() {
  local server_port=$1 direction=$2 scope=$3 fault=$4 log=$5
  python3 "$repo_root/tools/interop/udp_fault_proxy.py" \
    "--server-port=$server_port" "--fault=$fault" \
    "--direction=$direction" "--scope=$scope" >"$log" 2>&1 &
  proxy_pid=$!
  proxy_port=$(wait_for_line "$proxy_pid" "$log" UDP_FAULT_PROXY_PORT)
  proxy_control_port=$(wait_for_line \
    "$proxy_pid" "$log" UDP_FAULT_CONTROL_PORT)
  exec {proxy_control_fd}<>"/dev/tcp/127.0.0.1/$proxy_control_port"
  printf 'arm-once\n' >&"$proxy_control_fd"
  local response=
  IFS= read -r -u "$proxy_control_fd" response
  [[ $response == armed ]]
}

stop_proxy() {
  printf 'stop\n' >&"$proxy_control_fd"
  local response=
  IFS= read -r -u "$proxy_control_fd" response
  [[ $response == stopped* ]]
  exec {proxy_control_fd}>&-
  proxy_control_fd=
  wait "$proxy_pid"
  proxy_pid=
}

verify_case() {
  python3 "$repo_root/tools/interop/quic_handshake_fault_check.py" \
    "--role-pair=$1" "--direction=$2" "--fault=$3" "--version=$4" \
    "--client-log=$5" "--server-log=$6" "--proxy-log=$7"
}

process_timeout=${NETZ_QUIC_HANDSHAKE_FAULT_TIMEOUT_SECONDS:-30}
for version in 1 2; do
  for fault in loss corrupt; do
    for direction in client server; do
    case_dir="$work/netz-client-v$version-$fault-$direction"
    mkdir -p "$case_dir"
    server_port=$(free_udp_port)
    go_server_version=(-v1-only)
    netz_client_version=()
    netz_server_mode=peer_close
    go_client_version=()
    if (( version == 2 )); then
      go_server_version=(-v2-only)
      netz_client_version=(--version=2)
      netz_server_mode=peer_close_v2
      go_client_version=(-v2-only)
    fi
    "$work/quic-go-server" -addr "127.0.0.1:$server_port" \
      -ca-out "$case_dir/ca.pem" "${go_server_version[@]}" \
      >"$case_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_text "$server_pid" "$case_dir/server.log" \
      'go_quic_echo_server: listening='
    scope=$([[ $direction == client ]] && \
      echo netz-client-handshake-outbound || \
      echo quic-go-server-handshake-outbound)
    start_proxy "$server_port" "$direction" "$scope" "$fault" \
      "$case_dir/proxy.log"
    timeout "${process_timeout}s" "$netz_client" "$proxy_port" \
      "$case_dir/ca.pem" "${netz_client_version[@]}" \
      >"$case_dir/client.log" 2>&1
    wait "$server_pid"; server_pid=
    stop_proxy
    verify_case netz-client+quic-go-server "$direction" "$fault" "$version" \
      "$case_dir/client.log" "$case_dir/server.log" "$case_dir/proxy.log"

    case_dir="$work/quic-go-client-v$version-$fault-$direction"
    mkdir -p "$case_dir"
    server_port=$(free_udp_port)
    "$netz_server" "$server_port" "$netz_server_mode" \
      >"$case_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_text "$server_pid" "$case_dir/server.log" \
      'netz QUIC interop server listening'
    scope=$([[ $direction == client ]] && \
      echo quic-go-client-handshake-outbound || \
      echo netz-server-handshake-outbound)
    start_proxy "$server_port" "$direction" "$scope" "$fault" \
      "$case_dir/proxy.log"
    timeout "${process_timeout}s" "$work/quic-go-client" \
      -addr "127.0.0.1:$proxy_port" -ca "$work/netz-ca.pem" \
      -server-name localhost -expect-peer-close "${go_client_version[@]}" \
      >"$case_dir/client.log" 2>&1
    wait "$server_pid"; server_pid=
    stop_proxy
    verify_case quic-go-client+netz-server "$direction" "$fault" "$version" \
      "$case_dir/client.log" "$case_dir/server.log" "$case_dir/proxy.log"
    done
  done
done
