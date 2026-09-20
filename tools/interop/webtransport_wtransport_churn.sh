#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz WebTransport churn client executable path}
netz_server=${2:?netz WebTransport churn server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
manifest="$repo_root/tools/interop/webtransport_wtransport/Cargo.toml"
work=$(mktemp -d)
server_pid=
proxy_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    find "$work" -type f -name '*.log' -size +0c -print0 | sort -z |
      while IFS= read -r -d '' log; do
        echo "===== $log =====" >&2
        sed -n '1,240p' "$log" >&2
      done
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

cargo build --quiet --release --locked --manifest-path "$manifest"
wtransport="$repo_root/tools/interop/webtransport_wtransport/target/release/netz-webtransport-wtransport"
runs=${NETZ_WEBTRANSPORT_EXTERNAL_CHURN_RUNS:-2}
stream_values=${NETZ_WEBTRANSPORT_EXTERNAL_CHURN_STREAMS:-"32 64 128 256"}
timeout_seconds=${NETZ_WEBTRANSPORT_EXTERNAL_CHURN_TIMEOUT_SECONDS:-45}
bytes_per_stream=${NETZ_WEBTRANSPORT_EXTERNAL_CHURN_BYTES:-16384}
reset_after_bytes=256
reset_every=2

if (( runs < 1 || bytes_per_stream < reset_after_bytes )); then
  echo 'invalid external WebTransport churn configuration' >&2
  exit 2
fi

wait_for_port() {
  local log=$1
  local prefix=$2
  local pid=$3
  local value=
  for _ in $(seq 1 600); do
    value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
    if [[ -n $value ]]; then
      printf '%s\n' "$value"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  return 1
}

for streams in $stream_values; do
  for fault in loss reorder; do
    for ((run = 1; run <= runs; run++)); do
      case_dir="$work/${streams}-${fault}-${run}"
      mkdir -p "$case_dir"
      timeout "${timeout_seconds}s" "$wtransport" bench-server 0 \
        "--churn=$fault" --mode=stream --warmup=1 --iterations=1 \
        "--streams=$streams" "--bytes-per-stream=$bytes_per_stream" \
        "--chunk-bytes=$((bytes_per_stream < 16384 ? bytes_per_stream : 16384))" \
        --stream-window=65536 --timeout-ms=30000 \
        >"$case_dir/server.log" 2>&1 &
      server_pid=$!
      if ! port=$(wait_for_port "$case_dir/server.log" WTRANSPORT_CHURN_PORT "$server_pid"); then
        echo "external WebTransport churn server did not become ready" >&2
        exit 1
      fi
      if ! timeout "${timeout_seconds}s" "$netz_client" churn-client "$port" \
          "--fault=$fault" "--streams=$streams" \
          "--bytes-per-stream=$bytes_per_stream" \
          >"$case_dir/client.log" 2>&1; then
        exit 1
      fi
      wait "$server_pid"
      server_pid=
      python3 "$repo_root/tools/interop/webtransport_churn_check.py" \
        "--fault=$fault" "--streams=$streams" \
        "--bytes-per-stream=$bytes_per_stream" \
        "--reset-after-bytes=$reset_after_bytes" \
        "--reset-every=$reset_every" \
        "--client-log=$case_dir/client.log" \
        "--server-log=$case_dir/server.log"
      printf 'external WebTransport churn passed: streams=%d fault=%s run=%d/%d\n' \
        "$streams" "$fault" "$run" "$runs"
    done
  done
done

for streams in $stream_values; do
  for fault in loss reorder; do
    for ((run = 1; run <= runs; run++)); do
      case_dir="$work/reverse-${streams}-${fault}-${run}"
      mkdir -p "$case_dir"
      timeout "$((timeout_seconds + 5))s" "$netz_server" churn-server 0 "$fault" \
        --mode=stream --warmup=1 --iterations=1 \
        "--streams=$streams" "--bytes-per-stream=$bytes_per_stream" \
        "--chunk-bytes=$((bytes_per_stream < 16384 ? bytes_per_stream : 16384))" \
        --stream-window=65536 --timeout-ms=30000 \
        >"$case_dir/server.log" 2>&1 &
      server_pid=$!
      if ! netz_port=$(wait_for_port "$case_dir/server.log" NETZ_CHURN_PORT "$server_pid"); then
        echo "netz WebTransport churn server did not become ready" >&2
        exit 1
      fi
      python3 "$repo_root/tools/interop/udp_fault_proxy.py" \
        "--server-port=$netz_port" "--fault=$fault" \
        >"$case_dir/proxy.log" 2>&1 &
      proxy_pid=$!
      if ! proxy_port=$(wait_for_port "$case_dir/proxy.log" UDP_FAULT_PROXY_PORT "$proxy_pid"); then
        echo "WebTransport UDP fault proxy did not become ready" >&2
        exit 1
      fi
      proxy_control_port=$(sed -n 's/^UDP_FAULT_CONTROL_PORT=//p' \
        "$case_dir/proxy.log" | head -1)
      if [[ -z $proxy_control_port ]]; then
        echo "WebTransport UDP fault proxy control port missing" >&2
        exit 1
      fi
      if ! timeout "${timeout_seconds}s" "$wtransport" bench-client "$proxy_port" \
          "--churn=$fault" "--proxy-control-port=$proxy_control_port" \
          --mode=stream --warmup=1 --iterations=1 \
          "--streams=$streams" "--bytes-per-stream=$bytes_per_stream" \
          "--chunk-bytes=$((bytes_per_stream < 16384 ? bytes_per_stream : 16384))" \
          --stream-window=65536 --timeout-ms=30000 \
          >"$case_dir/client.log" 2>&1; then
        exit 1
      fi
      wait "$server_pid"
      server_pid=
      wait "$proxy_pid"
      proxy_pid=
      python3 "$repo_root/tools/interop/webtransport_churn_check.py" \
        --sender=wtransport "--fault=$fault" "--streams=$streams" \
        "--bytes-per-stream=$bytes_per_stream" \
        "--reset-after-bytes=$reset_after_bytes" \
        "--reset-every=$reset_every" \
        "--client-log=$case_dir/client.log" \
        "--server-log=$case_dir/server.log" \
        "--proxy-log=$case_dir/proxy.log"
      printf 'external WebTransport reverse churn passed: streams=%d fault=%s run=%d/%d\n' \
        "$streams" "$fault" "$run" "$runs"
    done
  done
done
