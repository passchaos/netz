#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz RFC 8441 benchmark client path}
netz_server=${2:?netz RFC 8441 benchmark server path}
shift 2
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
peer="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-websocket-bench"
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
    while IFS= read -r log_file; do
      echo "===== $log_file =====" >&2
      cat "$log_file" >&2
    done < <(find "$work" -type f \
      \( -name '*.log' -o -name '*.rss' \) -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

stats=false
warmup=20
iterations=1000
payload_bytes=4096
timeout_ms=30000
for arg in "$@"; do
  case "$arg" in
    --stats) stats=true ;;
    --warmup=*) warmup=${arg#--warmup=} ;;
    --iterations=*) iterations=${arg#--iterations=} ;;
    --payload-bytes=*) payload_bytes=${arg#--payload-bytes=} ;;
    --timeout-ms=*) timeout_ms=${arg#--timeout-ms=} ;;
  esac
done
time_command=()
rss_source=gnu-time-maxrss
if [[ -n ${TIME_BIN:-} ]]; then
  if [[ ! -x $TIME_BIN ]]; then
    echo "time executable not found at $TIME_BIN" >&2
    exit 127
  fi
  time_command=("$TIME_BIN")
elif [[ -x /usr/bin/time ]]; then
  time_command=(/usr/bin/time)
elif command -v busybox >/dev/null 2>&1; then
  time_command=("$(command -v busybox)" time)
  rss_source=busybox-time-maxrss
fi
if [[ $stats == true && ${#time_command[@]} -eq 0 ]]; then
  echo 'GNU or BusyBox time not found' >&2
  exit 127
fi
cargo_args=(build --quiet --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-websocket-bench)
if [[ $stats == true ]]; then
  cargo_args+=(--features allocation-stats)
fi
cargo "${cargo_args[@]}"

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
wait_for_line() {
  local pid=$1 log=$2 prefix=$3
  for _ in $(seq 1 600); do
    if grep -q "^${prefix}=" "$log"; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; return 1; fi
    sleep 0.05
  done
  echo "timed out waiting for $prefix" >&2
  return 1
}
mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]: print(cpu)
PY
)
if [[ ${#bench_cpus[@]} -lt 2 ]]; then
  echo 'WebSocket-over-H2 comparison requires two available CPUs' >&2
  exit 1
fi
client_cpu=${bench_cpus[0]}
server_cpu=${bench_cpus[1]}
echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu"

check_result() {
  local check_args=(python3 \
    "$repo_root/tools/interop/websocket_h2_benchmark_check.py" \
    --role-pair="$1" --warmup="$warmup" --iterations="$iterations" \
    --payload-bytes="$payload_bytes" --timeout-ms="$timeout_ms" \
    --client-log="$2" --server-log="$3")
  if [[ -n ${4:-} ]]; then
    check_args+=(--client-rss="$4" --server-rss="$5" \
      --rss-source="$rss_source")
  fi
  "${check_args[@]}"
}

port=$(free_tcp_port)
if [[ $stats == true ]]; then
  timeout 180s "${time_command[@]}" -f '%M' -o "$work/hyper-server.rss" \
    taskset -c "$server_cpu" "$peer" server "$port" "$@" \
    >"$work/hyper-server.log" 2>&1 &
else
  timeout 180s taskset -c "$server_cpu" "$peer" server "$port" "$@" \
    >"$work/hyper-server.log" 2>&1 &
fi
server_pid=$!
wait_for_line "$server_pid" "$work/hyper-server.log" HYPER_WEBSOCKET_H2_BENCH_PORT
if [[ $stats == true ]]; then
  timeout 180s "${time_command[@]}" -f '%M' -o "$work/netz-client.rss" \
    taskset -c "$client_cpu" "$netz_client" bench-client "$port" "$@" \
    >"$work/netz-client.log" 2>&1
else
  timeout 180s taskset -c "$client_cpu" "$netz_client" \
    bench-client "$port" "$@" >"$work/netz-client.log" 2>&1
fi
wait "$server_pid"
server_pid=
if [[ $stats == true ]]; then
  check_result netz-client+hyper-server "$work/netz-client.log" \
    "$work/hyper-server.log" "$work/netz-client.rss" "$work/hyper-server.rss"
else
  check_result netz-client+hyper-server "$work/netz-client.log" \
    "$work/hyper-server.log"
fi
cat "$work/hyper-server.log"
cat "$work/netz-client.log"

port=$(free_tcp_port)
if [[ $stats == true ]]; then
  timeout 180s "${time_command[@]}" -f '%M' -o "$work/netz-server.rss" \
    taskset -c "$server_cpu" "$netz_server" bench-server "$port" "$@" \
    >"$work/netz-server.log" 2>&1 &
else
  timeout 180s taskset -c "$server_cpu" "$netz_server" \
    bench-server "$port" "$@" >"$work/netz-server.log" 2>&1 &
fi
server_pid=$!
wait_for_line "$server_pid" "$work/netz-server.log" NETZ_WEBSOCKET_H2_BENCH_PORT
if [[ $stats == true ]]; then
  timeout 180s "${time_command[@]}" -f '%M' -o "$work/hyper-client.rss" \
    taskset -c "$client_cpu" "$peer" client "$port" "$@" \
    >"$work/hyper-client.log" 2>&1
else
  timeout 180s taskset -c "$client_cpu" "$peer" client "$port" "$@" \
    >"$work/hyper-client.log" 2>&1
fi
wait "$server_pid"
server_pid=
if [[ $stats == true ]]; then
  check_result hyper-client+netz-server "$work/hyper-client.log" \
    "$work/netz-server.log" "$work/hyper-client.rss" "$work/netz-server.rss"
else
  check_result hyper-client+netz-server "$work/hyper-client.log" \
    "$work/netz-server.log"
fi
cat "$work/netz-server.log"
cat "$work/hyper-client.log"
