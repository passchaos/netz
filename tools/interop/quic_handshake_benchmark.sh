#!/usr/bin/env bash
set -euo pipefail

netz_bench=${1:?netz handshake benchmark executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
fixture_dir=${QUICZ_ROOT:-"$HOME/Work/quicz"}/examples/interop/go_echo_client
if [[ ! -f $fixture_dir/go.mod ]]; then
  echo "audited quic-go fixture not found under $fixture_dir" >&2
  exit 127
fi

samples=${NETZ_QUIC_HANDSHAKE_SAMPLES:-5}
warmup=${NETZ_QUIC_HANDSHAKE_WARMUP:-10}
iterations=${NETZ_QUIC_HANDSHAKE_ITERATIONS:-100}
timeout_ms=${NETZ_QUIC_HANDSHAKE_TIMEOUT_MS:-10000}
if (( samples < 1 || samples % 2 == 0 || warmup < 0 || iterations < 1 )); then
  echo 'invalid handshake benchmark configuration' >&2
  exit 2
fi

mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
)
if [[ ${#bench_cpus[@]} -lt 2 ]]; then
  echo 'handshake benchmark requires two available CPUs' >&2
  exit 2
fi
client_cpu=${NETZ_QUIC_HANDSHAKE_CLIENT_CPU:-${bench_cpus[0]}}
server_cpu=${NETZ_QUIC_HANDSHAKE_SERVER_CPU:-${bench_cpus[1]}}
if [[ ! $client_cpu =~ ^[0-9]+$ || ! $server_cpu =~ ^[0-9]+$ ||
      $client_cpu == "$server_cpu" ]]; then
  echo 'handshake benchmark requires distinct numeric client/server CPUs' >&2
  exit 2
fi

work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
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

(cd "$fixture_dir" && go test -mod=readonly \
  "$repo_root/tools/interop/quic_handshake_bench.go" \
  "$repo_root/tools/interop/quic_handshake_bench_test.go")
(cd "$fixture_dir" && go build -mod=readonly \
  -o "$work/quic-go-handshake-bench" \
  "$repo_root/tools/interop/quic_handshake_bench.go")

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
    value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
    if [[ -n $value ]]; then printf '%s\n' "$value"; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then return 1; fi
    sleep 0.05
  done
  return 1
}

run_pair() {
  local role_pair=$1 client_impl=$2 server_impl=$3 outer_run=$4
  local pair_dir="$work/$role_pair-$outer_run"
  mkdir -p "$pair_dir"
  local server_port
  server_port=$(free_udp_port)
  local common=("--role-pair=$role_pair" "--warmup=$warmup"
    "--iterations=$iterations" "--run=$outer_run" "--timeout-ms=$timeout_ms")
  if [[ $server_impl == netz ]]; then
    timeout 300s taskset -c "$server_cpu" "$netz_bench" server "$server_port" \
      "${common[@]}" >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/server.log" NETZ_HANDSHAKE_BENCH_PORT >/dev/null
    ca="$work/netz-ca.pem"
  else
    timeout 300s taskset -c "$server_cpu" "$work/quic-go-handshake-bench" \
      -role=server -addr="127.0.0.1:$server_port" -ca-out="$pair_dir/ca.pem" \
      -role-pair="$role_pair" -warmup="$warmup" -iterations="$iterations" \
      -run="$outer_run" -timeout-ms="$timeout_ms" >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/server.log" QUIC_GO_HANDSHAKE_BENCH_PORT >/dev/null
    ca="$pair_dir/ca.pem"
  fi

  if [[ $client_impl == netz ]]; then
    timeout 300s taskset -c "$client_cpu" "$netz_bench" client "$server_port" "$ca" \
      "${common[@]}" >"$pair_dir/client.log" 2>&1
  else
    timeout 300s taskset -c "$client_cpu" "$work/quic-go-handshake-bench" \
      -role=client -addr="127.0.0.1:$server_port" -ca="$ca" \
      -role-pair="$role_pair" -warmup="$warmup" -iterations="$iterations" \
      -run="$outer_run" -timeout-ms="$timeout_ms" >"$pair_dir/client.log" 2>&1
  fi
  wait "$server_pid"; server_pid=
  cat "$pair_dir/client.log" >>"$work/$role_pair-client.log"
  cat "$pair_dir/server.log" >>"$work/$role_pair-server.log"
}

echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu samples=$samples warmup=$warmup iterations=$iterations"
pairs=(
  'netz-client+quic-go-server:netz:quic-go'
  'quic-go-client+quic-go-server:quic-go:quic-go'
  'quic-go-client+netz-server:quic-go:netz'
  'netz-client+netz-server:netz:netz'
)
for ((outer_run = 1; outer_run <= samples; outer_run += 1)); do
  if (( outer_run % 2 == 1 )); then
    order=(0 1 2 3)
  else
    order=(3 2 1 0)
  fi
  for index in "${order[@]}"; do
    IFS=: read -r role_pair client_impl server_impl <<<"${pairs[index]}"
    run_pair "$role_pair" "$client_impl" "$server_impl" "$outer_run"
  done
done

for entry in "${pairs[@]}"; do
  IFS=: read -r role_pair _ _ <<<"$entry"
  grep '^record=result ' "$work/$role_pair-client.log"
  grep '^record=server-complete ' "$work/$role_pair-server.log"
  python3 "$repo_root/tools/interop/quic_handshake_benchmark_check.py" \
    "--role-pair=$role_pair" "--samples=$samples" "--warmup=$warmup" \
    "--iterations=$iterations" "--client-log=$work/$role_pair-client.log" \
    "--server-log=$work/$role_pair-server.log"
done

