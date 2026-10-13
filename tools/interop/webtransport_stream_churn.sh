#!/usr/bin/env bash
set -euo pipefail

benchmark=${1:?WebTransport stream benchmark executable path}
runs=${NETZ_WEBTRANSPORT_CHURN_RUNS:-3}
timeout_seconds=${NETZ_WEBTRANSPORT_CHURN_TIMEOUT_SECONDS:-20}
streams=${NETZ_WEBTRANSPORT_CHURN_STREAMS:-8}
transfer_bytes=${NETZ_WEBTRANSPORT_CHURN_BYTES:-262144}
reset_every=${NETZ_WEBTRANSPORT_CHURN_RESET_EVERY:-2}
reset_after_bytes=${NETZ_WEBTRANSPORT_CHURN_RESET_BYTES:-256}

if (( runs < 1 || streams < 1 || transfer_bytes < 1 || reset_every < 1 )); then
  echo "invalid WebTransport churn configuration" >&2
  exit 2
fi

reset_streams=$((streams / reset_every))
finished_streams=$((streams - reset_streams))
reset_prefix=$reset_after_bytes
if (( reset_prefix > transfer_bytes )); then
  reset_prefix=$transfer_bytes
fi
expected_bytes=$((finished_streams * transfer_bytes + reset_streams * reset_prefix))

run_case() {
  local label=$1
  shift
  local output
  output=$(mktemp)

  for ((run = 1; run <= runs; run++)); do
    if ! timeout "${timeout_seconds}s" "$benchmark" \
        "--transfer-bytes=$transfer_bytes" \
        "--streams=$streams" \
        "--reset-every=$reset_every" \
        "--reset-after-bytes=$reset_after_bytes" \
        "$@" >"$output" 2>&1; then
      cat "$output" >&2
      rm -f "$output"
      echo "WebTransport churn failed: case=$label run=$run" >&2
      exit 1
    fi
    grep -Fq "  total transfer bytes: $expected_bytes" "$output"
    grep -Fq "  streams: $streams" "$output"
    grep -Fq "  reset streams: $reset_streams" "$output"
    if [[ $label == reliable-* ]]; then
      grep -Fq '  reset mode: reliable' "$output"
    else
      grep -Fq '  reset mode: ordinary' "$output"
    fi
    case $label in
      loss|reliable-loss)
        grep -Fq '  simulated loss percent: 5' "$output"
        awk '/  datagrams dropped:/ { if ($3 + 0 > 0) found=1 } END { exit !found }' "$output"
        ;;
      client-reorder|reliable-client-reorder)
        grep -Fq '  reorder every: 5' "$output"
        grep -Fq '  fault direction: client' "$output"
        awk '/  datagrams held:/ { if ($3 + 0 > 0) found=1 } END { exit !found }' "$output"
        ;;
      *)
        rm -f "$output"
        echo "unknown WebTransport churn case: $label" >&2
        exit 2
        ;;
    esac
    printf 'WebTransport churn passed: case=%s run=%d/%d bytes=%d resets=%d\n' \
      "$label" "$run" "$runs" "$expected_bytes" "$reset_streams"
  done
  rm -f "$output"
}

run_case loss --loss-pct=5
# Exercise packet reordering over a sustained multi-stream FIN workload. The
# mixed FIN/reset shape is covered by the loss case above; combining resets
# with this benchmark interceptor can complete before the held tail is emitted
# and would turn the intended reorder into artificial loss.
saved_reset_every=$reset_every
reset_every=$((streams + 1))
reset_streams=0
finished_streams=$streams
expected_bytes=$((streams * transfer_bytes))
run_case client-reorder --reorder-every=5 --fault-direction=client
reset_every=$saved_reset_every

reset_streams=$((streams / reset_every))
finished_streams=$((streams - reset_streams))
expected_bytes=$((finished_streams * transfer_bytes + reset_streams * reset_prefix))
run_case reliable-loss --reliable-reset --loss-pct=5
run_case reliable-client-reorder --reliable-reset \
  --reorder-every=5 --fault-direction=client
