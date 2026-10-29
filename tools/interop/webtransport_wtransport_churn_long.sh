#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz WebTransport churn client executable path}
netz_server=${2:?netz WebTransport churn server executable path}
runner=$(cd "$(dirname "$0")" && pwd)/webtransport_wtransport_churn.sh

run_profile() {
  local label=$1
  local runs=$2
  local streams=$3
  local bytes=$4
  local timeout_seconds=$5
  local seed=$6

  printf 'WebTransport long-run profile starting: profile=%s runs=%d streams=%q bytes=%d\n' \
    "$label" "$runs" "$streams" "$bytes"
  NETZ_WEBTRANSPORT_EXTERNAL_CHURN_RUNS=$runs \
  NETZ_WEBTRANSPORT_EXTERNAL_CHURN_STREAMS=$streams \
  NETZ_WEBTRANSPORT_EXTERNAL_CHURN_BYTES=$bytes \
  NETZ_WEBTRANSPORT_EXTERNAL_CHURN_TIMEOUT_SECONDS=$timeout_seconds \
  NETZ_WEBTRANSPORT_EXTERNAL_CHURN_SEED=$seed \
    "$runner" "$netz_client" "$netz_server"
  printf 'WebTransport long-run profile passed: profile=%s runs=%d streams=%q bytes=%d faults=loss+reorder roles=both\n' \
    "$label" "$runs" "$streams" "$bytes"
}

# Maximum-concurrency streams with the 64-KiB payload shape that previously
# exposed congestion-limited RESET_STREAM teardown.
run_profile ceiling 10 "256" 65536 90 81985529217486895

# Non-power-of-two stream counts cross every result-mask word and vary the
# reset/FIN population without repeating the ordinary 32/64/128/256 matrix.
run_profile heterogeneous 5 "17 63 127 191" 32768 75 81985529218486895

# A small number of long-lived streams forces repeated flow-control, ACK, loss,
# and PTO cycles instead of deriving duration only from stream-count fanout.
run_profile large-stream 10 "3 7" 1048576 120 81985529219486895

echo 'WebTransport long-run churn passed: profiles=ceiling+heterogeneous+large-stream sessions=200 faults=loss+reorder roles=both verifier=seeded-mask+bytes+checksum+codes+sibling+peer-close'
