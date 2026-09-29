#!/usr/bin/env bash
set -euo pipefail

netz_binary=${1:?netz WebSocket benchmark executable path}
build_mode=${2:?netz build mode}
shift 2

samples=3
connections=128
active_connections=8
warmup=2
iterations=20
for argument in "$@"; do
  case "$argument" in
    --samples=*) samples=${argument#*=} ;;
    --connections=*) connections=${argument#*=} ;;
    --active-connections=*) active_connections=${argument#*=} ;;
    --warmup=*) warmup=${argument#*=} ;;
    --iterations=*) iterations=${argument#*=} ;;
    *) echo "unsupported argument: $argument" >&2; exit 2 ;;
  esac
done

if [[ $build_mode != ReleaseFast ]]; then
  echo "bench-websocket-mostly-idle requires -Doptimize=ReleaseFast" >&2
  exit 2
fi
if ! [[ $samples =~ ^[0-9]+$ ]] || (( samples == 0 || samples % 2 == 0 )); then
  echo "--samples must be a positive odd integer" >&2
  exit 2
fi
for value in "$connections" "$active_connections" "$warmup" "$iterations"; do
  if ! [[ $value =~ ^[0-9]+$ ]]; then
    echo "benchmark arguments must be non-negative integers" >&2
    exit 2
  fi
done
if (( connections <= 1 || connections > 256 || active_connections == 0 || 
  active_connections >= connections || iterations == 0 )); then
  echo "invalid mostly-idle WebSocket workload" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
reference_root=${WEBSOCKET_ZIG_ROOT:-$HOME/Work/websocket.zig}
reference_revision=efa879736bd438bea8b86a91f220ba408de57273
actual_revision=$(git -C "$reference_root" rev-parse HEAD)
if [[ $actual_revision != "$reference_revision" ]]; then
  echo "expected websocket.zig $reference_revision, found $actual_revision" >&2
  exit 1
fi
if [[ -n $(git -C "$reference_root" status --short) ]]; then
  echo "websocket.zig checkout must be clean" >&2
  exit 1
fi
zio_root="$repo_root/zig-pkg/zio-0.17.0-xHbVVELgKQBIzMAdDWTrIamBlTyFlijzxFU7G4f2NUcw"
if [[ ! -f "$zio_root/src/zio.zig" ]]; then
  echo "missing locked zio source at $zio_root" >&2
  exit 1
fi
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
else
  echo "GNU or BusyBox time not found" >&2
  exit 127
fi

work=$(mktemp -d)
cleanup() {
  local status=$?
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      [[ -f $log ]] && { echo "WebSocket benchmark failure log: $log" >&2; sed -n '1,240p' "$log" >&2; }
    done
  fi
  rm -rf "$work"
}
trap cleanup EXIT
reference_binary="$work/websocket-zig-echo"
zig build-exe -OReleaseFast -lc \
  --dep websocket --dep counting_allocator --dep zio \
  -Mroot="$repo_root/benchmarks/reference/websocket_zig_echo.zig" \
  --dep build \
  -Mwebsocket="$reference_root/src/websocket.zig" \
  -Mcounting_allocator="$repo_root/examples/support/counting_allocator.zig" \
  --dep zio_options \
  -Mzio="$zio_root/src/zio.zig" \
  -Mbuild="$repo_root/benchmarks/reference/websocket_zig_build_options.zig" \
  -Mzio_options="$repo_root/benchmarks/reference/zio_options.zig" \
  -femit-bin="$reference_binary"

netz_log="$work/netz.log"
reference_log="$work/reference.log"
host=$(hostname)
arch=$(uname -m)
kernel=$(uname -r)
zig_version=$(zig version)
sha256() {
  sha256sum "$1" | cut -d' ' -f1
}
free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
environment="samples=$samples schedule=alternating connections=$connections active_connections=$active_connections idle_connections=$((connections - active_connections)) warmup=$warmup iterations=$iterations payload_bytes=4096 payload_schedule=fixed memory_stage=connections-live-after-workload rss_scope=whole-process-lifetime host=$host arch=$arch kernel=$kernel zig=$zig_version netz_build_mode=$build_mode reference_revision=$actual_revision netz_binary_sha256=$(sha256 "$netz_binary") reference_binary_sha256=$(sha256 "$reference_binary")"
printf 'record=environment implementation=netz %s complete=true\n' \
  "$environment" >"$netz_log"
printf 'record=environment implementation=websocket-zig %s complete=true\n' \
  "$environment" >"$reference_log"
for ((sample = 1; sample <= samples; sample++)); do
  first=netz
  second=reference
  if (( sample % 2 == 0 )); then
    first=reference
    second=netz
  fi
  for implementation in "$first" "$second"; do
    if [[ $implementation == netz ]]; then
      log=$netz_log
    else
      log=$reference_log
    fi
    order=2
    [[ $implementation == "$first" ]] && order=1
    result_implementation=$implementation
    [[ $implementation == reference ]] && result_implementation=websocket-zig
    printf 'record=run sample=%d implementation=%s order=%d complete=true\n' \
      "$sample" "$result_implementation" "$order" >>"$log"
    if [[ $implementation == netz ]]; then
      rss_file="$work/netz-$sample.rss"
      timeout 90s "${time_command[@]}" -f '%M' -o "$rss_file" "$netz_binary" \
        --connections="$connections" \
        --active-connections="$active_connections" \
        --warmup="$warmup" --iterations="$iterations" --stats \
        >>"$netz_log" 2>&1
    else
      rss_file="$work/reference-$sample.rss"
      reference_port=$(free_port)
      timeout 90s "${time_command[@]}" -f '%M' -o "$rss_file" "$reference_binary" --tcp-nodelay \
        --port="$reference_port" \
        --connections="$connections" \
        --active-connections="$active_connections" \
        --warmup="$warmup" --iterations="$iterations" --stats \
        >>"$reference_log" 2>&1
    fi
    process_peak_rss_kib=$(<"$rss_file")
    if ! [[ $process_peak_rss_kib =~ ^[1-9][0-9]*$ ]]; then
      echo "invalid process peak RSS: $process_peak_rss_kib" >&2
      exit 1
    fi
    printf 'record=rss sample=%d implementation=%s process_scope=client+server rss_scope=whole-process-lifetime rss_source=%s process_peak_rss_kib=%d complete=true\n' \
      "$sample" "$result_implementation" "$rss_source" "$process_peak_rss_kib" >>"$log"
  done
done
python3 "$repo_root/tools/interop/websocket_mostly_idle_benchmark_check.py" \
  --netz-log "$netz_log" --reference-log "$reference_log" \
  --samples "$samples" --connections "$connections" \
  --active-connections "$active_connections" --warmup "$warmup" \
  --iterations "$iterations"
