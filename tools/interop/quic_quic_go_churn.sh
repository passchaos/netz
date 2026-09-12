#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz raw QUIC churn client executable path}
netz_server=${2:?netz raw QUIC churn server executable path}
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
cleanup() {
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
  local status=$?
  if [[ $status -ne 0 ]]; then
    find "$work" -type f -name '*.log' -size +0c -print0 | sort -z |
      while IFS= read -r -d '' log_file; do
        echo "===== $log_file =====" >&2
        sed -n '1,260p' "$log_file" >&2
      done
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

(cd "$fixture_dir" && go test -mod=readonly \
  "$repo_root/tools/interop/quic_quic_go_bench.go" \
  "$repo_root/tools/interop/quic_quic_go_churn.go" \
  "$repo_root/tools/interop/quic_quic_go_churn_test.go")
(cd "$fixture_dir" && go build -mod=readonly \
  -o "$work/quic-go-raw-churn" \
  "$repo_root/tools/interop/quic_quic_go_bench.go" \
  "$repo_root/tools/interop/quic_quic_go_churn.go")

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

runs=${NETZ_QUIC_EXTERNAL_CHURN_RUNS:-2}
stream_values=${NETZ_QUIC_EXTERNAL_CHURN_STREAMS:-"32 64"}
bytes_per_stream=${NETZ_QUIC_EXTERNAL_CHURN_BYTES:-16384}
reset_after_bytes=${NETZ_QUIC_EXTERNAL_CHURN_RESET_BYTES:-256}
reset_every=${NETZ_QUIC_EXTERNAL_CHURN_RESET_EVERY:-2}
timeout_ms=${NETZ_QUIC_EXTERNAL_CHURN_TIMEOUT_MS:-30000}
process_timeout=${NETZ_QUIC_EXTERNAL_CHURN_PROCESS_TIMEOUT_SECONDS:-45}
if (( runs < 1 || bytes_per_stream < reset_after_bytes || reset_every < 1 )); then
  echo 'invalid raw QUIC churn configuration' >&2
  exit 2
fi

start_proxy() {
  local server_port=$1 direction=$2 scope=$3 log=$4
  python3 "$repo_root/tools/interop/udp_fault_proxy.py" \
    "--server-port=$server_port" "--fault=$fault" \
    "--direction=$direction" "--scope=$scope-outbound" >"$log" 2>&1 &
  proxy_pid=$!
  proxy_port=$(wait_for_line "$proxy_pid" "$log" UDP_FAULT_PROXY_PORT)
  proxy_control_port=$(wait_for_line \
    "$proxy_pid" "$log" UDP_FAULT_CONTROL_PORT)
}

check_case() {
  python3 "$repo_root/tools/interop/quic_quic_go_churn_check.py" \
    "--role-pair=$1" "--sender=$sender" "--fault=$fault" \
    "--streams=$streams" "--bytes-per-stream=$bytes_per_stream" \
    "--reset-after-bytes=$reset_after_bytes" "--reset-every=$reset_every" \
    "--client-log=$2" "--server-log=$3" "--proxy-log=$4"
}

for streams in $stream_values; do
  for fault in loss reorder; do
    for sender in client server; do
      for ((run = 1; run <= runs; run++)); do
        args=("--sender=$sender" "--fault=$fault" "--streams=$streams"
          "--bytes-per-stream=$bytes_per_stream"
          "--reset-after-bytes=$reset_after_bytes" "--reset-every=$reset_every"
          "--timeout-ms=$timeout_ms" "--stream-window=$bytes_per_stream")

        case_dir="$work/netz-client-${streams}-${fault}-${sender}-${run}"
        mkdir -p "$case_dir"
        server_port=$(free_udp_port)
        QUIC_GO_DISABLE_GSO=true timeout "${process_timeout}s" \
          "$work/quic-go-raw-churn" \
          -role=server -addr="127.0.0.1:$server_port" \
          -ca-out="$case_dir/quic-go-ca.pem" -churn="$fault" \
          -sender="$sender" -streams="$streams" \
          -bytes-per-stream="$bytes_per_stream" \
          -reset-after-bytes="$reset_after_bytes" -reset-every="$reset_every" \
          -timeout-ms="$timeout_ms" -stream-window="$bytes_per_stream" \
          >"$case_dir/server.log" 2>&1 &
        server_pid=$!
        wait_for_line "$server_pid" "$case_dir/server.log" QUIC_GO_RAW_CHURN_ADDR >/dev/null
        scope=$([[ $sender == client ]] && echo netz-client || echo quic-go-server)
        start_proxy "$server_port" "$sender" "$scope" "$case_dir/proxy.log"
        timeout "${process_timeout}s" "$netz_client" churn-client \
          "$proxy_port" "$case_dir/quic-go-ca.pem" "$proxy_control_port" \
          "${args[@]}" >"$case_dir/client.log" 2>&1
        wait "$server_pid"; server_pid=
        wait "$proxy_pid"; proxy_pid=
        check_case netz-client+quic-go-server "$case_dir/client.log" \
          "$case_dir/server.log" "$case_dir/proxy.log"
        printf 'raw QUIC churn passed: role_pair=netz-client+quic-go-server streams=%d fault=%s sender=%s run=%d/%d\n' \
          "$streams" "$fault" "$sender" "$run" "$runs"

        case_dir="$work/quic-go-client-${streams}-${fault}-${sender}-${run}"
        mkdir -p "$case_dir"
        server_port=$(free_udp_port)
        timeout "$((process_timeout + 5))s" "$netz_server" churn-server \
          "$server_port" "${args[@]}" >"$case_dir/server.log" 2>&1 &
        server_pid=$!
        wait_for_line "$server_pid" "$case_dir/server.log" NETZ_QUIC_CHURN_PORT >/dev/null
        scope=$([[ $sender == client ]] && echo quic-go-client || echo netz-server)
        start_proxy "$server_port" "$sender" "$scope" "$case_dir/proxy.log"
        QUIC_GO_DISABLE_GSO=true timeout "${process_timeout}s" \
          "$work/quic-go-raw-churn" \
          -role=client -addr="127.0.0.1:$proxy_port" -ca="$work/netz-ca.pem" \
          -proxy-control-port="$proxy_control_port" -churn="$fault" \
          -sender="$sender" -streams="$streams" \
          -bytes-per-stream="$bytes_per_stream" \
          -reset-after-bytes="$reset_after_bytes" -reset-every="$reset_every" \
          -timeout-ms="$timeout_ms" -stream-window="$bytes_per_stream" \
          >"$case_dir/client.log" 2>&1
        wait "$server_pid"; server_pid=
        wait "$proxy_pid"; proxy_pid=
        check_case quic-go-client+netz-server "$case_dir/client.log" \
          "$case_dir/server.log" "$case_dir/proxy.log"
        printf 'raw QUIC churn passed: role_pair=quic-go-client+netz-server streams=%d fault=%s sender=%s run=%d/%d\n' \
          "$streams" "$fault" "$sender" "$run" "$runs"
      done
    done
  done
done
