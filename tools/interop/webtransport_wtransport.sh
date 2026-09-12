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
    done < <(find "$work" -type f \
      \( -name '*.log' -o -name '*.rss' \) -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if [[ ${3:-} == --bench ]]; then
  shift 3
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
  stats=false
  traffic=false
  warmup_override=
  iterations_override=
  streams=1
  bytes_per_stream=4194304
  payload_bytes=32
  chunk_bytes=16384
  stream_window=1048576
  timeout_ms=30000
  netz_ack_every=2
  netz_max_ack_delay_us=25000
  for arg in "$@"; do
    if [[ $arg == --mode=* ]]; then
      requested_modes=("${arg#--mode=}")
    else
      common_args+=("$arg")
      case "$arg" in
        --stats) stats=true ;;
        --traffic) traffic=true ;;
        --warmup=*) warmup_override=${arg#--warmup=} ;;
        --iterations=*) iterations_override=${arg#--iterations=} ;;
        --streams=*) streams=${arg#--streams=} ;;
        --bytes-per-stream=*) bytes_per_stream=${arg#--bytes-per-stream=} ;;
        --payload-bytes=*) payload_bytes=${arg#--payload-bytes=} ;;
        --chunk-bytes=*) chunk_bytes=${arg#--chunk-bytes=} ;;
        --stream-window=*) stream_window=${arg#--stream-window=} ;;
        --timeout-ms=*) timeout_ms=${arg#--timeout-ms=} ;;
        --netz-ack-every=*) netz_ack_every=${arg#--netz-ack-every=} ;;
        --netz-max-ack-delay-us=*)
          netz_max_ack_delay_us=${arg#--netz-max-ack-delay-us=}
          ;;
      esac
    fi
  done
  if [[ $stats == true && $traffic == true ]]; then
    echo '--stats and --traffic must run separately' >&2
    exit 2
  fi
  time_bin=${TIME_BIN:-/usr/bin/time}
  if [[ $stats == true && ! -x $time_bin ]]; then
    echo "GNU time not found at $time_bin" >&2
    exit 127
  fi
  cargo_args=(build --quiet --release --locked --manifest-path "$client_manifest")
  if [[ $stats == true ]]; then
    cargo_args+=(--features allocation-stats)
  fi
  cargo "${cargo_args[@]}"
  rust_bench="$repo_root/tools/interop/webtransport_wtransport/target/release/netz-webtransport-wtransport"

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
    local result_mode=$benchmark_mode
    local warmup=${warmup_override:-20}
    local iterations=${iterations_override:-5}
    if [[ $benchmark_mode == datagram-pingpong ]]; then
      warmup=${warmup_override:-200}
      iterations=${iterations_override:-5000}
    else
      result_mode=stream-upload
    fi

    check_result() {
      local check_args=(python3 \
        "$repo_root/tools/interop/webtransport_benchmark_check.py" \
        --role-pair="$1" --mode="$result_mode" --warmup="$warmup" \
        --iterations="$iterations" --streams="$streams" \
        --bytes-per-stream="$bytes_per_stream" \
        --payload-bytes="$payload_bytes" --chunk-bytes="$chunk_bytes" \
        --stream-window="$stream_window" --timeout-ms="$timeout_ms" \
        --netz-ack-every="$netz_ack_every" \
        --netz-max-ack-delay-us="$netz_max_ack_delay_us" \
        --client-log="$2" --server-log="$3")
      if [[ -n ${4:-} ]]; then
        check_args+=(--client-rss="$4" --server-rss="$5")
      fi
      if [[ $traffic == true ]]; then
        check_args+=(--require-traffic)
      fi
      "${check_args[@]}"
    }

    if [[ $stats == true ]]; then
      timeout 180s "$time_bin" -f '%M' -o "$pair_dir/netz-server.rss" \
        taskset -c "$server_cpu" "$netz_server" \
        bench-server 0 "${mode_args[@]}" \
        >"$pair_dir/netz-server.log" 2>&1 &
    else
      timeout 180s taskset -c "$server_cpu" "$netz_server" \
        bench-server 0 "${mode_args[@]}" \
        >"$pair_dir/netz-server.log" 2>&1 &
    fi
    server_pid=$!
    local netz_port
    netz_port=$(wait_for_port "$server_pid" \
      "$pair_dir/netz-server.log" NETZ_BENCH_PORT)
    if [[ $stats == true ]]; then
      timeout 180s "$time_bin" -f '%M' -o "$pair_dir/wtransport-client.rss" \
        taskset -c "$client_cpu" "$rust_bench" \
        bench-client "$netz_port" "${mode_args[@]}" \
        >"$pair_dir/wtransport-client.log" 2>&1
    else
      timeout 180s taskset -c "$client_cpu" "$rust_bench" \
        bench-client "$netz_port" "${mode_args[@]}" \
        >"$pair_dir/wtransport-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    if [[ $stats == true ]]; then
      check_result wtransport-client+netz-server \
        "$pair_dir/wtransport-client.log" "$pair_dir/netz-server.log" \
        "$pair_dir/wtransport-client.rss" "$pair_dir/netz-server.rss"
    else
      check_result wtransport-client+netz-server \
        "$pair_dir/wtransport-client.log" "$pair_dir/netz-server.log"
    fi
    cat "$pair_dir/netz-server.log"
    cat "$pair_dir/wtransport-client.log"

    rust_log="$pair_dir/wtransport-server.log"
    if [[ $stats == true ]]; then
      timeout 180s "$time_bin" -f '%M' -o "$pair_dir/wtransport-server.rss" \
        taskset -c "$server_cpu" "$rust_bench" \
        bench-server 0 "${mode_args[@]}" >"$rust_log" 2>&1 &
    else
      timeout 180s taskset -c "$server_cpu" "$rust_bench" \
        bench-server 0 "${mode_args[@]}" >"$rust_log" 2>&1 &
    fi
    server_pid=$!
    local rust_port
    rust_port=$(wait_for_port "$server_pid" "$rust_log" \
      WTRANSPORT_BENCH_PORT)
    if [[ $stats == true ]]; then
      timeout 180s "$time_bin" -f '%M' -o "$pair_dir/netz-client.rss" \
        taskset -c "$client_cpu" "$netz_client" \
        bench-client "$rust_port" "${mode_args[@]}" \
        >"$pair_dir/netz-client.log" 2>&1
    else
      timeout 180s taskset -c "$client_cpu" "$netz_client" \
        bench-client "$rust_port" "${mode_args[@]}" \
        >"$pair_dir/netz-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    if [[ $stats == true ]]; then
      check_result netz-client+wtransport-server \
        "$pair_dir/netz-client.log" "$pair_dir/wtransport-server.log" \
        "$pair_dir/netz-client.rss" "$pair_dir/wtransport-server.rss"
    else
      check_result netz-client+wtransport-server \
        "$pair_dir/netz-client.log" "$pair_dir/wtransport-server.log"
    fi
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
