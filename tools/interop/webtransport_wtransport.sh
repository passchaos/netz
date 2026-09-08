#!/usr/bin/env bash
set -euo pipefail

netz_server=${1:?netz server executable path}
netz_client=${2:?netz client executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
client_manifest="$repo_root/tools/interop/webtransport_wtransport/Cargo.toml"
work=$(mktemp -d)
server_pid=
rust_log=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    while IFS= read -r log; do
      echo "===== $log =====" >&2
      cat "$log" >&2
    done < <(find "$work" -type f -name '*.log' -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if [[ ${3:-} == --bench ]]; then
  shift 3
  cargo build --quiet --release --locked --manifest-path "$client_manifest"
  rust_bench="$repo_root/tools/interop/webtransport_wtransport/target/release/netz-webtransport-wtransport"
  mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
  )
  if [[ ${#bench_cpus[@]} -lt 2 ]]; then
    echo 'WebTransport comparison requires two available CPUs' >&2
    exit 1
  fi
  client_cpu=${bench_cpus[0]}
  server_cpu=${bench_cpus[1]}
  requested_modes=(stream datagram-pingpong)
  common_args=()
  for arg in "$@"; do
    if [[ $arg == --mode=* ]]; then
      requested_modes=("${arg#--mode=}")
    else
      common_args+=("$arg")
    fi
  done

  wait_for_port() {
    local pid=$1
    local log=$2
    local prefix=$3
    local value=
    for _ in $(seq 1 600); do
      value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
      if [[ -n $value ]]; then
        printf '%s\n' "$value"
        return 0
      fi
      if ! kill -0 "$pid" 2>/dev/null; then
        cat "$log" >&2
        return 1
      fi
      sleep 0.05
    done
    echo "timed out waiting for ${prefix}" >&2
    cat "$log" >&2
    return 1
  }

  run_benchmark_pair() {
    local benchmark_mode=$1
    local pair_dir="$work/$benchmark_mode"
    mkdir -p "$pair_dir"
    local mode_args=("--mode=$benchmark_mode" "${common_args[@]}")

    timeout 180s taskset -c "$server_cpu" "$netz_server" \
      bench-server 0 "${mode_args[@]}" \
      >"$pair_dir/netz-server.log" 2>&1 &
    server_pid=$!
    local netz_port
    netz_port=$(wait_for_port "$server_pid" \
      "$pair_dir/netz-server.log" NETZ_BENCH_PORT)
    timeout 180s taskset -c "$client_cpu" "$rust_bench" \
      bench-client "$netz_port" "${mode_args[@]}" \
      >"$pair_dir/wtransport-client.log" 2>&1
    wait "$server_pid"
    server_pid=
    grep -Fq 'role_pair=wtransport-client+netz-server' \
      "$pair_dir/wtransport-client.log"
    grep -Fq 'complete=true' "$pair_dir/wtransport-client.log"
    cat "$pair_dir/netz-server.log"
    cat "$pair_dir/wtransport-client.log"

    rust_log="$pair_dir/wtransport-server.log"
    timeout 180s taskset -c "$server_cpu" "$rust_bench" \
      bench-server 0 "${mode_args[@]}" >"$rust_log" 2>&1 &
    server_pid=$!
    local rust_port
    rust_port=$(wait_for_port "$server_pid" "$rust_log" \
      WTRANSPORT_BENCH_PORT)
    timeout 180s taskset -c "$client_cpu" "$netz_client" \
      bench-client "$rust_port" "${mode_args[@]}" \
      >"$pair_dir/netz-client.log" 2>&1
    wait "$server_pid"
    server_pid=
    grep -Fq 'role_pair=netz-client+wtransport-server' \
      "$pair_dir/netz-client.log"
    grep -Fq 'complete=true' "$pair_dir/netz-client.log"
    cat "$rust_log"
    cat "$pair_dir/netz-client.log"
  }

  echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu"
  for benchmark_mode in "${requested_modes[@]}"; do
    if [[ $benchmark_mode != stream && \
          $benchmark_mode != datagram-pingpong ]]; then
      echo "unsupported benchmark mode: $benchmark_mode" >&2
      exit 1
    fi
    run_benchmark_pair "$benchmark_mode"
  done
  exit 0
fi

port=$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$netz_server" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'WebTransport interop server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'WebTransport interop server listening' "$work/server.log"; then
  echo 'timed out waiting for netz WebTransport server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

if ! timeout 180s cargo run --quiet --release --locked \
    --manifest-path "$client_manifest" -- client "$port" \
    >"$work/wtransport-client.log" 2>&1; then
  cat "$work/wtransport-client.log" >&2
  cat "$work/server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/wtransport-client.log"
cat "$work/server.log"
grep -Fq \
  'wtransport client interop passed: CONNECT admission-headers=true DATAGRAM max_datagram_size=' \
  "$work/wtransport-client.log"
grep -Fq 'oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-close=true close' \
  "$work/wtransport-client.log"
grep -Fq \
  'netz WebTransport server interop passed: CONNECT DATAGRAM max_datagram_size=' \
  "$work/server.log"
grep -Fq \
  'netz WebTransport interop accepted CONNECT with admission metadata' \
  "$work/server.log"
grep -Fq 'oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-connection-close=true close' \
  "$work/server.log"

rust_log="$work/wtransport-server.log"
: >"$rust_log"
timeout 30s cargo run --quiet --release --locked \
  --manifest-path "$client_manifest" -- server \
  >"$rust_log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  rust_port=$(sed -n 's/^WTRANSPORT_PORT=//p' \
    "$rust_log" | head -1)
  if [[ -n "$rust_port" ]]; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$rust_log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ -z "${rust_port:-}" ]]; then
  echo 'timed out waiting for wtransport server' >&2
  cat "$rust_log" >&2
  exit 1
fi
if ! timeout 30s "$netz_client" "$rust_port" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$rust_log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/netz-client.log"
cat "$rust_log"
grep -Fq \
  'netz WebTransport client interop passed: CONNECT uri=true rejection=404 admission-headers=true DATAGRAM max_datagram_size=' \
  "$work/netz-client.log"
grep -Fq 'oversized_rejected=true bidi uni reset=73 stop=74 dropped_stop_sending=1 concurrent_sibling=true reuse=true peer-close' \
  "$work/netz-client.log"
grep -Fq \
  'wtransport server interop passed: CONNECT admission-headers=true DATAGRAM max_datagram_size=' \
  "$rust_log"
grep -Fq 'wtransport server rejected CONNECT with 404' "$rust_log"
grep -Fq 'oversized_rejected=true bidi uni reset=73 stop=74 reuse=true' \
  "$rust_log"
