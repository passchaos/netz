#!/usr/bin/env bash
set -euo pipefail

netz_pipeline=${1:?netz pipeline executable path}
netz_body=${2:?netz body executable path}
build_mode=${3:?netz build mode}
shift 3

samples=5
cpu=0
pipeline_warmup=200
pipeline_iterations=2000
body_warmup=20
body_iterations=200
body_bytes=1048576
chunk_bytes=16384
for argument in "$@"; do
  case "$argument" in
    --samples=*) samples=${argument#*=} ;;
    --cpu=*) cpu=${argument#*=} ;;
    --pipeline-warmup=*) pipeline_warmup=${argument#*=} ;;
    --pipeline-iterations=*) pipeline_iterations=${argument#*=} ;;
    --body-warmup=*) body_warmup=${argument#*=} ;;
    --body-iterations=*) body_iterations=${argument#*=} ;;
    --body-bytes=*) body_bytes=${argument#*=} ;;
    --chunk-bytes=*) chunk_bytes=${argument#*=} ;;
    *) echo "unsupported argument: $argument" >&2; exit 2 ;;
  esac
done

if [[ $build_mode != ReleaseFast ]]; then
  echo "bench-http1-hyper requires -Doptimize=ReleaseFast" >&2
  exit 2
fi
if ! [[ $samples =~ ^[0-9]+$ ]] || (( samples == 0 || samples % 2 == 0 )); then
  echo "--samples must be a positive odd integer" >&2
  exit 2
fi
for value in "$cpu" "$pipeline_warmup" "$pipeline_iterations" \
  "$body_warmup" "$body_iterations" "$body_bytes" "$chunk_bytes"; do
  if ! [[ $value =~ ^[0-9]+$ ]]; then
    echo "benchmark numeric arguments must be non-negative integers" >&2
    exit 2
  fi
done
if (( pipeline_iterations == 0 || body_iterations == 0 || body_bytes == 0 || \
  chunk_bytes == 0 || body_bytes % chunk_bytes != 0 )); then
  echo "invalid HTTP/1 benchmark workload" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hyper_root=${HYPER_ROOT:-$HOME/Work/hyper}
expected_hyper_revision=084473f728f9d07b3be5845475aa2f62ed9ff579
actual_hyper_revision=$(git -C "$hyper_root" rev-parse HEAD)
if [[ $actual_hyper_revision != "$expected_hyper_revision" ]]; then
  echo "expected Hyper $expected_hyper_revision, found $actual_hyper_revision" >&2
  exit 1
fi
if [[ -n $(git -C "$hyper_root" status --short) ]]; then
  echo "Hyper checkout must be clean" >&2
  exit 1
fi
if ! taskset -c "$cpu" true; then
  echo "cannot pin benchmark to CPU $cpu" >&2
  exit 1
fi

manifest=$repo_root/tools/hyper_http1_body/Cargo.toml
cargo build --release --offline --locked --manifest-path "$manifest" \
  --bin netz-hyper-http1-pipeline --bin netz-hyper-http1-body >&2
hyper_pipeline=$repo_root/tools/hyper_http1_body/target/release/netz-hyper-http1-pipeline
hyper_body=$repo_root/tools/hyper_http1_body/target/release/netz-hyper-http1-body
checker=$repo_root/tools/interop/http1_hyper_benchmark_check.py
host=$(hostname)
arch=$(uname -m)
kernel=$(uname -r)
zig_version=$(zig version)
rustc_version=$(rustc --version | awk '{print $2}')
work=$(mktemp -d)
cleanup() {
  local status=$?
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      if [[ -f $log ]]; then
        echo "HTTP/1 benchmark failure log: $log" >&2
        sed -n '1,240p' "$log" >&2
      fi
    done
  fi
  rm -rf "$work"
}
trap cleanup EXIT

sha256() {
  sha256sum "$1" | cut -d' ' -f1
}

run_pair() {
  local log=$1
  local sample=$2
  local netz_binary=$3
  local hyper_binary=$4
  shift 4
  local first=netz
  local second=hyper
  if (( sample % 2 == 0 )); then
    first=hyper
    second=netz
  fi
  for implementation in "$first" "$second"; do
    printf 'record=run protocol=http1 workload=%s sample=%d implementation=%s schedule=abba cpu=%d\n' \
      "$workload" "$sample" "$implementation" "$cpu" >>"$log"
    if [[ $implementation == netz ]]; then
      timeout 120s taskset -c "$cpu" "$netz_binary" "$@" >>"$log" 2>&1
    else
      timeout 120s taskset -c "$cpu" "$hyper_binary" "$@" >>"$log" 2>&1
    fi
  done
}

run_workload() {
  local workload=$1
  local log=$2
  local netz_binary=$3
  local hyper_binary=$4
  shift 4
  printf '%s\n' \
    "record=environment protocol=http1 workload=$workload samples=$samples schedule=abba cpu=$cpu host=$host arch=$arch kernel=$kernel zig=$zig_version rustc=$rustc_version netz_build_mode=$build_mode hyper_revision=$actual_hyper_revision netz_binary_sha256=$(sha256 "$netz_binary") hyper_binary_sha256=$(sha256 "$hyper_binary") hyper_lock_sha256=$(sha256 "$repo_root/tools/hyper_http1_body/Cargo.lock") complete=true" \
    >"$log"
  for ((sample = 1; sample <= samples; sample++)); do
    run_pair "$log" "$sample" "$netz_binary" "$hyper_binary" "$@"
  done
}

run_workload pipeline "$work/pipeline.log" \
  "$netz_pipeline" "$hyper_pipeline" \
  --warmup="$pipeline_warmup" --iterations="$pipeline_iterations"
python3 "$checker" \
  --log "$work/pipeline.log" --workload pipeline --samples "$samples" \
  --cpu "$cpu" --warmup "$pipeline_warmup" \
  --iterations "$pipeline_iterations"

for mode in fixed chunked; do
  run_workload streaming-body "$work/body-$mode.log" \
    "$netz_body" "$hyper_body" \
    --mode="$mode" --body-bytes="$body_bytes" --chunk-bytes="$chunk_bytes" \
    --warmup="$body_warmup" --iterations="$body_iterations"
  python3 "$checker" \
    --log "$work/body-$mode.log" --workload streaming-body \
    --samples "$samples" --cpu "$cpu" \
    --warmup "$body_warmup" --iterations "$body_iterations" \
    --mode "$mode" --body-bytes "$body_bytes" --chunk-bytes "$chunk_bytes"
done
