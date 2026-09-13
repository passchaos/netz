#!/usr/bin/env bash
set -euo pipefail

netz_bench=${1:?netz persistent QUIC benchmark executable path}
shift
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
fixture_dir=${QUICZ_ROOT:-"$HOME/Work/quicz"}/examples/interop/go_echo_client

modes=both
samples=${NETZ_QUIC_PERSISTENT_SAMPLES:-5}
connections=${NETZ_QUIC_PERSISTENT_CONNECTIONS:-4}
echo_warmup=${NETZ_QUIC_PERSISTENT_ECHO_WARMUP:-200}
echo_iterations=${NETZ_QUIC_PERSISTENT_ECHO_ITERATIONS:-5000}
payload_bytes=${NETZ_QUIC_PERSISTENT_PAYLOAD_BYTES:-1024}
aggregate_bytes=${NETZ_QUIC_PERSISTENT_BYTES_PER_STREAM:-1048576}
streams=${NETZ_QUIC_PERSISTENT_STREAMS:-1}
chunk_bytes=${NETZ_QUIC_PERSISTENT_CHUNK_BYTES:-16384}
stream_window=${NETZ_QUIC_PERSISTENT_STREAM_WINDOW:-1048576}
timeout_ms=${NETZ_QUIC_PERSISTENT_TIMEOUT_MS:-30000}
server_topology=independent
shared_receive_batch=${NETZ_QUIC_PERSISTENT_SHARED_RECEIVE_BATCH:-32}
server_ack_every=${NETZ_QUIC_PERSISTENT_SERVER_ACK_EVERY:-2}
server_ack_delay_us=${NETZ_QUIC_PERSISTENT_SERVER_ACK_DELAY_US:-25000}
for arg in "$@"; do
  case $arg in
    --mode=*) modes=${arg#--mode=} ;;
    --samples=*) samples=${arg#--samples=} ;;
    --connections=*) connections=${arg#--connections=} ;;
    --warmup=*) echo_warmup=${arg#--warmup=} ;;
    --iterations=*) echo_iterations=${arg#--iterations=} ;;
    --payload-bytes=*) payload_bytes=${arg#--payload-bytes=} ;;
    --bytes-per-stream=*) aggregate_bytes=${arg#--bytes-per-stream=} ;;
    --streams=*) streams=${arg#--streams=} ;;
    --chunk-bytes=*) chunk_bytes=${arg#--chunk-bytes=} ;;
    --stream-window=*) stream_window=${arg#--stream-window=} ;;
    --timeout-ms=*) timeout_ms=${arg#--timeout-ms=} ;;
    --server-topology=*) server_topology=${arg#--server-topology=} ;;
    --shared-receive-batch=*) shared_receive_batch=${arg#--shared-receive-batch=} ;;
    --server-ack-every=*) server_ack_every=${arg#--server-ack-every=} ;;
    --server-ack-delay-us=*) server_ack_delay_us=${arg#--server-ack-delay-us=} ;;
    *) echo "unknown persistent benchmark option: $arg" >&2; exit 2 ;;
  esac
done
if [[ $modes != echo && $modes != aggregate && $modes != both ]]; then
  echo 'mode must be echo, aggregate, or both' >&2
  exit 2
fi
if [[ $server_topology != independent && $server_topology != shared ]]; then
  echo 'server topology must be independent or shared' >&2
  exit 2
fi
if [[ $server_topology == shared && $modes != aggregate ]]; then
  echo 'shared server topology requires aggregate mode' >&2
  exit 2
fi
if [[ $server_topology == independent ]]; then
  if [[ ! -f $fixture_dir/go.mod ]]; then
    echo "audited quic-go fixture not found under $fixture_dir" >&2
    exit 127
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo 'go not found' >&2
    exit 127
  fi
fi
if (( samples < 1 || samples % 2 == 0 || connections < 1 || connections > 16 ||
      echo_warmup < 0 || echo_iterations < 1 || payload_bytes < 1 ||
      aggregate_bytes < 1 || chunk_bytes < 1 || chunk_bytes > aggregate_bytes ||
      stream_window < 1 || timeout_ms < 1 )); then
  echo 'invalid persistent QUIC benchmark configuration' >&2
  exit 2
fi
if [[ $streams != 1 && $streams != 4 ]]; then
  echo 'persistent aggregate streams must be 1 or 4' >&2
  exit 2
fi
if (( shared_receive_batch < 1 || shared_receive_batch > 64 )); then
  echo 'shared receive batch must be between 1 and 64' >&2
  exit 2
fi
if (( server_ack_every < 1 || server_ack_every > 64 ||
      server_ack_delay_us < 0 || server_ack_delay_us > 25000 )); then
  echo 'server ACK policy must use ack-every 1..64 and delay 0..25000 us' >&2
  exit 2
fi
if [[ $server_topology != shared ]] &&
   (( server_ack_every != 2 || server_ack_delay_us != 25000 )); then
  echo 'custom server ACK policy requires shared server topology' >&2
  exit 2
fi

mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
)
if [[ ${#bench_cpus[@]} -lt 2 ]]; then
  echo 'persistent QUIC comparison requires two available CPUs' >&2
  exit 2
fi
client_cpu=${NETZ_QUIC_PERSISTENT_CLIENT_CPU:-${bench_cpus[0]}}
server_cpu=${NETZ_QUIC_PERSISTENT_SERVER_CPU:-${bench_cpus[1]}}
if [[ ! $client_cpu =~ ^[0-9]+$ || ! $server_cpu =~ ^[0-9]+$ ||
      $client_cpu == "$server_cpu" ]]; then
  echo 'persistent QUIC comparison requires distinct numeric CPUs' >&2
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

if [[ $server_topology == independent ]]; then
  (cd "$fixture_dir" && go test -mod=readonly \
    "$repo_root/tools/interop/quic_quic_go_bench.go" \
    "$repo_root/tools/interop/quic_quic_go_churn.go" \
    "$repo_root/tools/interop/quic_persistent_bench_test.go")
  (cd "$fixture_dir" && go build -mod=readonly \
    -o "$work/quic-go-persistent-bench" \
    "$repo_root/tools/interop/quic_quic_go_bench.go" \
    "$repo_root/tools/interop/quic_quic_go_churn.go")
fi
python3 "$repo_root/tools/interop/quic_persistent_benchmark_check_test.py"
python3 "$repo_root/tools/interop/quic_persistent_benchmark_summary_test.py"
: >"$work/results.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

wait_for_ports() {
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
  local mode=$1 role_pair=$2 client_impl=$3 server_impl=$4 sender=$5 outer_run=$6
  local pair_dir="$work/$mode-$role_pair-$sender-$outer_run"
  mkdir -p "$pair_dir"
  local mode_connections=$connections mode_streams=$streams warmup=0 iterations=1
  if [[ $mode == echo ]]; then
    mode_connections=1; mode_streams=1
    warmup=$echo_warmup; iterations=$echo_iterations
  fi
  local common=(
    "--mode=$mode" "--role-pair=$role_pair" "--sender=$sender"
    "--run=$outer_run" "--connections=$mode_connections"
    "--warmup=$warmup" "--iterations=$iterations" "--streams=$mode_streams"
    "--bytes-per-stream=$aggregate_bytes" "--payload-bytes=$payload_bytes"
    "--chunk-bytes=$chunk_bytes" "--stream-window=$stream_window"
    "--timeout-ms=$timeout_ms"
  )
  if [[ $server_impl == netz ]]; then
    common+=("--server-topology=$server_topology")
    if [[ $server_topology == shared ]]; then
      common+=("--shared-receive-batch=$shared_receive_batch")
      common+=("--server-ack-every=$server_ack_every")
      common+=("--server-ack-delay-us=$server_ack_delay_us")
    fi
  fi
  local go_common=()
  for argument in "${common[@]}"; do
    [[ $argument == --server-topology=* ||
       $argument == --shared-receive-batch=* ||
       $argument == --server-ack-every=* ||
       $argument == --server-ack-delay-us=* ]] ||
      go_common+=("-${argument#--}")
  done

  if [[ $server_impl == netz ]]; then
    timeout 300s taskset -c "$server_cpu" "$netz_bench" server \
      "${common[@]}" >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    ports=$(wait_for_ports "$server_pid" "$pair_dir/server.log" NETZ_QUIC_PERSISTENT_PORTS)
    ca=$work/netz-ca.pem
  else
    QUIC_GO_DISABLE_GSO=true timeout 300s taskset -c "$server_cpu" \
      "$work/quic-go-persistent-bench" \
      -role=server -addr=127.0.0.1:0 -ca-out="$pair_dir/ca.pem" \
      "${go_common[@]}" >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    ports=$(wait_for_ports "$server_pid" "$pair_dir/server.log" QUIC_GO_PERSISTENT_PORTS)
    ca=$pair_dir/ca.pem
  fi

  if [[ $client_impl == netz ]]; then
    timeout 300s taskset -c "$client_cpu" "$netz_bench" client \
      "--ports=$ports" "--ca=$ca" "${common[@]}" \
      >"$pair_dir/client.log" 2>&1
  else
    QUIC_GO_DISABLE_GSO=true timeout 300s taskset -c "$client_cpu" \
      "$work/quic-go-persistent-bench" \
      -role=client -ports="$ports" -ca="$ca" "${go_common[@]}" \
      >"$pair_dir/client.log" 2>&1
  fi
  wait "$server_pid"; server_pid=
  python3 "$repo_root/tools/interop/quic_persistent_benchmark_check.py" \
    "--mode=$mode" "--role-pair=$role_pair" "--run=$outer_run" \
    "--connections=$mode_connections" "--warmup=$warmup" \
    "--iterations=$iterations" "--streams=$mode_streams" \
    "--bytes-per-stream=$aggregate_bytes" "--payload-bytes=$payload_bytes" \
    "--sender=$sender" "--server-topology=$server_topology" \
    "--shared-receive-batch=$shared_receive_batch" \
    "--server-ack-every=$server_ack_every" \
    "--server-ack-delay-us=$server_ack_delay_us" \
    "--client-log=$pair_dir/client.log" \
    "--server-log=$pair_dir/server.log"
  grep '^record=result ' "$pair_dir/client.log" >>"$work/results.log"
  cat "$pair_dir/client.log"
  cat "$pair_dir/server.log"
}

echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu samples=$samples"
pairs=(
  'netz-client+quic-go-server:netz:quic-go'
  'quic-go-client+quic-go-server:quic-go:quic-go'
  'quic-go-client+netz-server:quic-go:netz'
  'netz-client+netz-server:netz:netz'
)
if [[ $server_topology == shared ]]; then
  pairs=('netz-client+netz-server:netz:netz')
fi
for ((outer_run = 1; outer_run <= samples; outer_run += 1)); do
  if [[ $server_topology == shared ]]; then
    order=(0)
  elif (( outer_run % 2 == 1 )); then
    order=(0 1 2 3)
  else
    order=(3 2 1 0)
  fi
  for index in "${order[@]}"; do
    IFS=: read -r role_pair client_impl server_impl <<<"${pairs[index]}"
    if [[ $modes == echo || $modes == both ]]; then
      run_pair echo "$role_pair" "$client_impl" "$server_impl" client "$outer_run"
    fi
    if [[ $modes == aggregate || $modes == both ]]; then
      if (( outer_run % 2 == 1 )); then
        sender_order=(client server)
      else
        sender_order=(server client)
      fi
      for sender_role in "${sender_order[@]}"; do
        if [[ $server_topology == shared && $sender_role != client ]]; then
          continue
        fi
        run_pair aggregate "$role_pair" "$client_impl" "$server_impl" \
          "$sender_role" "$outer_run"
      done
    fi
  done
done
if [[ $modes == echo || $modes == both ]]; then
  python3 "$repo_root/tools/interop/quic_persistent_benchmark_summary.py" \
    --mode=echo "--samples=$samples" "--log=$work/results.log"
fi
if [[ $modes == aggregate || $modes == both ]]; then
  python3 "$repo_root/tools/interop/quic_persistent_benchmark_summary.py" \
    --mode=aggregate "--samples=$samples" "--log=$work/results.log" \
    "--server-topology=$server_topology" \
    "--shared-receive-batch=$shared_receive_batch" \
    "--server-ack-every=$server_ack_every" \
    "--server-ack-delay-us=$server_ack_delay_us"
fi
