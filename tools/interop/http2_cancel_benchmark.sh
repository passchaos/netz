#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz HTTP/2 cancellation client path}
build_mode=${2:?netz build mode}
shift 2
samples=5
warmup=20
iterations=1000
client_cpu=0
server_cpu=1
for argument in "$@"; do
  case "$argument" in
    --samples=*) samples=${argument#*=} ;;
    --warmup=*) warmup=${argument#*=} ;;
    --iterations=*) iterations=${argument#*=} ;;
    --client-cpu=*) client_cpu=${argument#*=} ;;
    --server-cpu=*) server_cpu=${argument#*=} ;;
    *) echo "unsupported argument: $argument" >&2; exit 2 ;;
  esac
done
if [[ $build_mode != ReleaseFast ]]; then
  echo "bench-http2-cancel-hyper requires -Doptimize=ReleaseFast" >&2
  exit 2
fi
if [[ -n ${TIME_BIN:-} && ! -x ${TIME_BIN:-} ]]; then
  echo "time executable not found at ${TIME_BIN:-}" >&2
  exit 127
fi
if ! [[ $samples =~ ^[0-9]+$ ]] || (( samples == 0 || samples % 2 == 0 )); then
  echo "--samples must be a positive odd integer" >&2
  exit 2
fi
for value in "$warmup" "$iterations" "$client_cpu" "$server_cpu"; do
  [[ $value =~ ^[0-9]+$ ]] || { echo "invalid numeric argument" >&2; exit 2; }
done
(( iterations > 0 )) || { echo "--iterations must be positive" >&2; exit 2; }
if [[ $client_cpu == "$server_cpu" ]]; then
  echo "client and server CPUs must differ" >&2
  exit 2
fi
taskset -c "$client_cpu" true
taskset -c "$server_cpu" true

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hyper_root=${HYPER_ROOT:-$HOME/Work/hyper}
hyper_revision=084473f728f9d07b3be5845475aa2f62ed9ff579
actual_revision=$(git -C "$hyper_root" rev-parse HEAD)
[[ $actual_revision == "$hyper_revision" ]] || {
  echo "expected Hyper $hyper_revision, found $actual_revision" >&2; exit 1;
}
[[ -z $(git -C "$hyper_root" status --short) ]] || {
  echo "Hyper checkout must be clean" >&2; exit 1;
}
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
cargo build --release --offline --locked --features allocation-stats \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-cancel-server \
  --bin netz-hyper-http2-cancel-client >&2
server="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-cancel-server"
hyper_client="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-cancel-client"

time_command=()
rss_source=gnu-time-maxrss
if [[ -n ${TIME_BIN:-} ]]; then
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
server_pid=
cleanup() {
  local status=$?
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      [[ -f $log ]] && { echo "HTTP/2 cancellation benchmark failure log: $log" >&2; sed -n '1,240p' "$log" >&2; }
    done
  fi
  rm -rf "$work"
}
trap cleanup EXIT
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
run_one() {
  local implementation=$1
  local sample=$2
  local client_log=$3
  local server_log=$4
  local client_binary=$netz_client
  [[ $implementation == hyper ]] && client_binary=$hyper_client
  local port
  port=$(free_port)
  timeout 120s taskset -c "$server_cpu" "$server" "$port" $((warmup + iterations)) \
    >>"$server_log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if (( $(grep -Fc 'cancellation benchmark server listening' "$server_log" || true) >= sample )); then
      break
    fi
    kill -0 "$server_pid" 2>/dev/null || { cat "$server_log" >&2; exit 1; }
    sleep 0.025
  done
  if (( $(grep -Fc 'cancellation benchmark server listening' "$server_log" || true) < sample )); then
    echo "timed out waiting for Hyper server" >&2; exit 1;
  fi
  local rss="$work/$implementation-$sample.rss"
  timeout 120s "${time_command[@]}" -f '%M' -o "$rss" \
    taskset -c "$client_cpu" "$client_binary" "$port" "$warmup" "$iterations" \
    >>"$client_log" 2>&1
  wait "$server_pid"
  server_pid=
  local maxrss
  maxrss=$(<"$rss")
  [[ $maxrss =~ ^[1-9][0-9]*$ ]] || { echo "invalid RSS: $maxrss" >&2; exit 1; }
  printf 'record=rss sample=%d implementation=%s process_scope=client rss_scope=whole-process-lifetime rss_source=%s process_peak_rss_kib=%d complete=true\n' \
    "$sample" "$implementation" "$rss_source" "$maxrss" >>"$client_log"
}

netz_client_log="$work/netz-client.log"
netz_server_log="$work/netz-server.log"
hyper_client_log="$work/hyper-client.log"
hyper_server_log="$work/hyper-server.log"
host=$(hostname)
arch=$(uname -m)
kernel=$(uname -r)
zig_version=$(zig version)
rustc_version=$(rustc --version | awk '{print $2}')
environment="samples=$samples schedule=alternating warmup=$warmup iterations=$iterations stream_window=8192 connection_window=65535 offered_bytes=131072 canceled_bytes=8192 sibling_bytes=16384 client_cpu=$client_cpu server_cpu=$server_cpu host=$host arch=$arch kernel=$kernel zig=$zig_version rustc=$rustc_version netz_build_mode=$build_mode hyper_revision=$actual_revision netz_binary_sha256=$(sha256 "$netz_client") hyper_client_binary_sha256=$(sha256 "$hyper_client") hyper_server_binary_sha256=$(sha256 "$server") hyper_lock_sha256=$(sha256 "$repo_root/tools/hyper_http2_flow/Cargo.lock")"
printf 'record=environment implementation=netz %s complete=true\n' "$environment" >"$netz_client_log"
printf 'record=environment implementation=hyper %s complete=true\n' "$environment" >"$hyper_client_log"
for ((sample = 1; sample <= samples; sample++)); do
  first=netz
  second=hyper
  (( sample % 2 == 0 )) && { first=hyper; second=netz; }
  for implementation in "$first" "$second"; do
    if [[ $implementation == netz ]]; then
      client_log=$netz_client_log
      server_log=$netz_server_log
    else
      client_log=$hyper_client_log
      server_log=$hyper_server_log
    fi
    order=2
    [[ $implementation == "$first" ]] && order=1
    printf 'record=run sample=%d implementation=%s order=%d complete=true\n' \
      "$sample" "$implementation" "$order" >>"$client_log"
    run_one "$implementation" "$sample" "$client_log" "$server_log"
  done
done
python3 "$repo_root/tools/interop/http2_cancel_benchmark_check.py" \
  --netz-client-log "$netz_client_log" --netz-server-log "$netz_server_log" \
  --hyper-client-log "$hyper_client_log" --hyper-server-log "$hyper_server_log" \
  --samples "$samples" --warmup "$warmup" --iterations "$iterations"
