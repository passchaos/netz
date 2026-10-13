#!/usr/bin/env bash
set -euo pipefail

netz_broker=${1:?netz broker executable path}
driver=${2:?netz MQTT benchmark driver path}
repo_root=${NETZ_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
repo_root=$(realpath "$repo_root")
interop_root=${NETZ_INTEROP_ROOT:-"$repo_root/tools/interop"}
interop_root=$(realpath "$interop_root")
publishers=${PUBLISHERS:-2}
subscribers=${SUBSCRIBERS:-2}
warmup_messages=${WARMUP_MESSAGES:-100}
messages=${MESSAGES:-2000}
payload_bytes=${PAYLOAD_BYTES:-256}
publisher_window=${PUBLISHER_WINDOW:-16}
qos=${MQTT_QOS:-1}
session_expiry_seconds=${MQTT_SESSION_EXPIRY_SECONDS:-0}
broker_order=${MQTT_BROKER_ORDER:-netz-first}
client_cpu=${MQTT_CLIENT_CPU:-}
server_cpu=${MQTT_SERVER_CPU:-}
sampler_cpu=${MQTT_SAMPLER_CPU:-}
stats=${MQTT_STATS:-false}
max_artifact_bytes=33554432
if [[ "$qos" != 1 && "$qos" != 2 ]]; then
  echo 'MQTT_QOS must be 1 or 2' >&2
  exit 2
fi
if [[ ! "$session_expiry_seconds" =~ ^(0|[1-9][0-9]*)$ ||
      ${#session_expiry_seconds} -gt 10 ||
      (${#session_expiry_seconds} -eq 10 &&
       "$session_expiry_seconds" > 4294967295) ]]; then
  echo 'MQTT_SESSION_EXPIRY_SECONDS must be between 0 and 4294967295' >&2
  exit 2
fi
if [[ "$broker_order" != netz-first && "$broker_order" != mosquitto-first ]]; then
  echo 'MQTT_BROKER_ORDER must be netz-first or mosquitto-first' >&2
  exit 2
fi
if [[ -n "$client_cpu" || -n "$server_cpu" ]]; then
  if [[ ! "$client_cpu" =~ ^[0-9]+$ ||
        ! "$server_cpu" =~ ^[0-9]+$ ||
        "$client_cpu" == "$server_cpu" ]]; then
    echo 'MQTT_CLIENT_CPU and MQTT_SERVER_CPU must be distinct CPU numbers' >&2
    exit 2
  fi
  command -v taskset >/dev/null || {
    echo 'CPU-pinned MQTT comparison requires taskset' >&2
    exit 127
  }
  python3 - "$client_cpu" "$server_cpu" <<'PY'
import os
import sys
requested = {int(sys.argv[1]), int(sys.argv[2])}
if not requested <= os.sched_getaffinity(0):
    raise SystemExit("requested MQTT benchmark CPU is unavailable")
PY
fi
if [[ -n "$sampler_cpu" ]]; then
  if [[ "$stats" != true ]]; then
    echo 'MQTT_SAMPLER_CPU requires MQTT_STATS=true' >&2
    exit 2
  fi
  if [[ -z "$client_cpu" || -z "$server_cpu" ]]; then
    echo 'MQTT_SAMPLER_CPU requires pinned client and server CPUs' >&2
    exit 2
  fi
  if [[ ! "$sampler_cpu" =~ ^[0-9]+$ ||
        "$sampler_cpu" == "$client_cpu" ||
        "$sampler_cpu" == "$server_cpu" ]]; then
    echo 'MQTT_SAMPLER_CPU must be distinct from client and server CPUs' >&2
    exit 2
  fi
  python3 - "$sampler_cpu" <<'PY'
import os
import sys
if int(sys.argv[1]) not in os.sched_getaffinity(0):
    raise SystemExit("requested MQTT sampler CPU is unavailable")
PY
fi
queue_args=(
  --warmup "$warmup_messages"
  --messages "$messages"
)
if [[ -n "${MQTT_MAX_QUEUED_MESSAGES:-}" ]]; then
  queue_args+=(--capacity "$MQTT_MAX_QUEUED_MESSAGES")
fi
max_queued_messages=$(python3 \
  "$interop_root/mqtt_broker_benchmark_config.py" \
  "${queue_args[@]}")
preserve_work=false
if [[ -n "${MQTT_ARTIFACT_DIR:-}" ]]; then
  if [[ -e "$MQTT_ARTIFACT_DIR" ]]; then
    echo "MQTT_ARTIFACT_DIR already exists: $MQTT_ARTIFACT_DIR" >&2
    exit 2
  fi
  mkdir -p "$MQTT_ARTIFACT_DIR"
  work=$(realpath "$MQTT_ARTIFACT_DIR")
  preserve_work=true
else
  work=$(mktemp -d)
fi
. "$interop_root/mosquitto_build.sh"
server_pid=
sampler_pid=
if [[ "$stats" != false && "$stats" != true ]]; then
  echo 'MQTT_STATS must be true or false' >&2
  exit 2
fi
if [[ "$stats" == true && ! -r /proc/self/status ]]; then
  echo 'MQTT_STATS=true requires Linux /proc process status data' >&2
  exit 127
fi

cleanup() {
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ "$preserve_work" != true ]]; then
    rm -rf "$work"
  fi
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    while IFS= read -r artifact; do
      echo "===== $artifact =====" >&2
      cat "$artifact" >&2
    done < <(find "$work" -maxdepth 1 -type f \
      \( -name '*.log' -o -name '*.txt' -o -name '*.rss' \) \
      -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

start_rss_sampler() {
  local pid=$1
  local output=$2
  (
    if [[ -n "$sampler_cpu" ]]; then
      taskset -pc "$sampler_cpu" "$BASHPID" >/dev/null
    fi
    local peak=0
    local value
    while kill -0 "$pid" 2>/dev/null; do
      value=$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status" \
        2>/dev/null || true)
      if [[ -n "$value" && "$value" -gt "$peak" ]]; then
        peak=$value
      fi
      sleep 0.002
    done
    if [[ "$peak" -le 0 ]]; then
      echo 'failed to sample broker RSS' >&2
      exit 1
    fi
    printf '%s\n' "$peak" >"$output"
  ) &
  sampler_pid=$!
}

finish_rss_sampler() {
  if [[ -z "$sampler_pid" ]]; then return; fi
  wait "$sampler_pid"
  sampler_pid=
}

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_log() {
  local log=$1
  local marker=$2
  for _ in $(seq 1 200); do
    if grep -q "$marker" "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for: $marker" >&2
  cat "$log" >&2
  exit 1
}

run_driver() {
  local port=$1
  local output=$2
  local server_implementation=$3
  local server_io=$4
  local command=(timeout 60s "$driver" \
    "--address=127.0.0.1:$port" \
    "--publishers=$publishers" \
    "--subscribers=$subscribers" \
    "--warmup-messages=$warmup_messages" \
    "--messages=$messages" \
    "--payload-bytes=$payload_bytes" \
    "--qos=$qos" \
    "--publisher-window=$publisher_window" \
    "--server-queue-capacity=$max_queued_messages" \
    "--session-expiry-seconds=$session_expiry_seconds" \
    "--server-implementation=$server_implementation" \
    "--server-io=$server_io" \
    --server-tcp-nodelay=true)
  if [[ -n "$client_cpu" ]]; then
    taskset -c "$client_cpu" "${command[@]}" >"$output" 2>&1
  else
    "${command[@]}" >"$output" 2>&1
  fi
  grep -Fq 'MQTT 5 TCP broker fanout workload' "$output"
  grep -Fq 'client io backend: zio-std-io' "$output"
  grep -Fq \
    "record=result implementation=netz protocol=mqtt5 transport=tcp mode=qos$qos-fanout role_pair=netz-client+$server_implementation-server client_io=zio-std-io server_io=$server_io" \
    "$output"
  grep -Eq 'publishes/s: [1-9][0-9]*' "$output"
  grep -Eq 'deliveries/s: [1-9][0-9]*' "$output"
  grep -Eq 'checksum: [1-9][0-9]*' "$output"
}

mosquitto_binary=$(resolve_mosquitto)

run_netz() {
  local netz_port
  netz_port=$(free_tcp_port)
  local command=("$netz_broker" \
    "--bind=127.0.0.1:$netz_port" \
    "--connections=$((publishers + subscribers))" \
    "--max-queued-deliveries=$max_queued_messages" \
    --max-outgoing-inflight=64)
  if [[ -n "$server_cpu" ]]; then
    taskset -c "$server_cpu" "${command[@]}" \
      >"$work/netz-server.log" 2>&1 &
  else
    "${command[@]}" >"$work/netz-server.log" 2>&1 &
  fi
  server_pid=$!
  wait_for_log "$work/netz-server.log" \
    'netz MQTT 3.1/3.1.1/5 broker listening.*server_io=zio-std-io'
  if [[ "$stats" == true ]]; then
    start_rss_sampler "$server_pid" "$work/netz-server.rss"
  fi
  run_driver "$netz_port" "$work/netz-result.txt" netz zio-std-io
  wait "$server_pid"
  server_pid=
  finish_rss_sampler
}

run_mosquitto() {
  local mosquitto_port
  mosquitto_port=$(free_tcp_port)
  cat >"$work/mosquitto.conf" <<EOF
listener $mosquitto_port 127.0.0.1
allow_anonymous true
persistence false
max_inflight_messages 64
max_queued_messages $max_queued_messages
set_tcp_nodelay true
log_dest stdout
EOF
  local command=("$mosquitto_binary" -c "$work/mosquitto.conf")
  if [[ -n "$server_cpu" ]]; then
    taskset -c "$server_cpu" "${command[@]}" \
      >"$work/mosquitto-server.log" 2>&1 &
  else
    "${command[@]}" >"$work/mosquitto-server.log" 2>&1 &
  fi
  server_pid=$!
  wait_for_log "$work/mosquitto-server.log" 'mosquitto version.*running'
  if [[ "$stats" == true ]]; then
    start_rss_sampler "$server_pid" "$work/mosquitto-server.rss"
  fi
  run_driver "$mosquitto_port" "$work/mosquitto-result.txt" \
    mosquitto mosquitto-event-loop
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
  finish_rss_sampler
}

printf 'record=run-order protocol=mqtt5 transport=tcp mode=qos%s-fanout benchmark_scope=same-client-workload timing_usable=true client_tcp_nodelay=true server_tcp_nodelay=true session_expiry_seconds=%s broker_order=%s client_cpu=%s server_cpu=%s sampler_cpu=%s complete=true\n' \
  "$qos" "$session_expiry_seconds" \
  "$broker_order" "${client_cpu:-unbound}" "${server_cpu:-unbound}" \
  "${sampler_cpu:-unbound}"
if [[ "$broker_order" == netz-first ]]; then
  run_netz
  run_mosquitto
else
  run_mosquitto
  run_netz
fi
while IFS= read -r artifact; do
  if [[ $(wc -c <"$artifact") -gt $max_artifact_bytes ]]; then
    echo "MQTT comparison artifact exceeds 32 MiB: $artifact" >&2
    exit 1
  fi
done < <(find "$work" -maxdepth 1 -type f)

check_args=(python3 \
  "$interop_root/mqtt_broker_benchmark_check.py" \
  --netz-log "$work/netz-result.txt" \
  --mosquitto-log "$work/mosquitto-result.txt" \
  --publishers "$publishers" \
  --subscribers "$subscribers" \
  --warmup "$warmup_messages" \
  --messages "$messages" \
  --payload-bytes "$payload_bytes" \
  --qos "$qos" \
  --session-expiry-seconds "$session_expiry_seconds" \
  --publisher-window "$publisher_window" \
  --server-queue-capacity "$max_queued_messages")
if [[ "$stats" == true ]]; then
  check_args+=(
    --netz-server-rss "$work/netz-server.rss"
    --mosquitto-server-rss "$work/mosquitto-server.rss"
    --rss-source proc-vmrss-sampled-2ms
  )
fi
"${check_args[@]}"

echo '--- netz ---'
cat "$work/netz-result.txt"
echo '--- Mosquitto ---'
cat "$work/mosquitto-result.txt"
echo "same-client MQTT comparison passed (Mosquitto $(git -C "$mosquitto_root" rev-parse --short HEAD)) client_io=zio-std-io server_io=zio-std-io+mosquitto-event-loop"
