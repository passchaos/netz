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
    done < <(find "$work" -type f -name '*.log' -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

cargo build --quiet --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-websocket-bench

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

port=$(free_tcp_port)
timeout 180s taskset -c "$server_cpu" "$peer" server "$port" "$@" \
  >"$work/hyper-server.log" 2>&1 &
server_pid=$!
wait_for_line "$server_pid" "$work/hyper-server.log" HYPER_WEBSOCKET_H2_BENCH_PORT
timeout 180s taskset -c "$client_cpu" "$netz_client" \
  bench-client "$port" "$@" >"$work/netz-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq 'role_pair=netz-client+hyper-server' "$work/netz-client.log"
grep -Fq 'complete=true' "$work/netz-client.log"
grep -Fq 'server_complete=true' "$work/hyper-server.log"
cat "$work/hyper-server.log"
cat "$work/netz-client.log"

port=$(free_tcp_port)
timeout 180s taskset -c "$server_cpu" "$netz_server" \
  bench-server "$port" "$@" >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_line "$server_pid" "$work/netz-server.log" NETZ_WEBSOCKET_H2_BENCH_PORT
timeout 180s taskset -c "$client_cpu" "$peer" client "$port" "$@" \
  >"$work/hyper-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq 'role_pair=hyper-client+netz-server' "$work/hyper-client.log"
grep -Fq 'complete=true' "$work/hyper-client.log"
grep -Fq 'server_complete=true' "$work/netz-server.log"
cat "$work/netz-server.log"
cat "$work/hyper-client.log"
