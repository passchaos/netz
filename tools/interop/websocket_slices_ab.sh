#!/usr/bin/env bash
set -euo pipefail

h1=${1:?H1 WebSocket benchmark executable path}
h2=${2:?H2 WebSocket benchmark executable path}
h3=${3:?H3 WebSocket benchmark executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
samples=${NETZ_WEBSOCKET_SLICES_SAMPLES:-5}
warmup=${NETZ_WEBSOCKET_SLICES_WARMUP:-20}
iterations=${NETZ_WEBSOCKET_SLICES_ITERATIONS:-1000}
parts=${NETZ_WEBSOCKET_SLICES_PARTS:-8}
payload_bytes=4096
cpu=${NETZ_WEBSOCKET_SLICES_CPU:-}

if (( samples < 1 || warmup < 0 || iterations < 1 ||
      samples % 2 == 0 || parts < 2 || parts > 64 )); then
  echo 'invalid WebSocket slice A/B configuration' >&2
  exit 2
fi
if [[ -z $cpu ]]; then
  cpu=$(python3 - <<'PY'
import os
print(min(os.sched_getaffinity(0)))
PY
  )
fi
if [[ ! $cpu =~ ^[0-9]+$ ]] || ! command -v taskset >/dev/null 2>&1; then
  echo 'WebSocket slice A/B requires one valid CPU and taskset' >&2
  exit 2
fi
echo "benchmark_cpu=$cpu samples=$samples warmup=$warmup iterations=$iterations parts=$parts"

work=$(mktemp -d)
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

for protocol in websocket-h1 websocket-h2 websocket-h3; do
  case $protocol in
    websocket-h1) exe=$h1; extra=() ;;
    websocket-h2) exe=$h2; extra=(--no-compression) ;;
    websocket-h3) exe=$h3; extra=(--no-compression) ;;
  esac
  contiguous_log="$work/$protocol-contiguous.log"
  slices_log="$work/$protocol-slices.log"
  : >"$contiguous_log"
  : >"$slices_log"
  for ((sample = 0; sample < samples; sample += 1)); do
    if (( sample % 2 == 0 )); then
      shapes=(contiguous slices)
    else
      shapes=(slices contiguous)
    fi
    for shape in "${shapes[@]}"; do
      log="$work/$protocol-$shape.log"
      taskset -c "$cpu" "$exe" "${extra[@]}" "--warmup=$warmup" \
        "--iterations=$iterations" "--send-shape=$shape" \
        "--parts=$parts" >>"$log" 2>&1
    done
  done
  grep '^record=result ' "$contiguous_log"
  grep '^record=result ' "$slices_log"
  python3 "$repo_root/tools/interop/websocket_slices_benchmark_check.py" \
    "--protocol=$protocol" "--parts=$parts" "--warmup=$warmup" \
    "--iterations=$iterations" "--payload-bytes=$payload_bytes" \
    "--samples=$samples" "--contiguous-log=$contiguous_log" \
    "--slices-log=$slices_log"
done
