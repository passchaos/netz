#!/usr/bin/env bash
set -euo pipefail

netz_broker=${1:?netz broker executable path}
driver=${2:?netz MQTT benchmark driver path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
publishers=${PUBLISHERS:-2}
subscribers=${SUBSCRIBERS:-2}
warmup_messages=${WARMUP_MESSAGES:-100}
messages=${MESSAGES:-2000}
payload_bytes=${PAYLOAD_BYTES:-256}
publisher_window=${PUBLISHER_WINDOW:-16}
queue_args=(
  --warmup "$warmup_messages"
  --messages "$messages"
)
if [[ -n "${MQTT_MAX_QUEUED_MESSAGES:-}" ]]; then
  queue_args+=(--capacity "$MQTT_MAX_QUEUED_MESSAGES")
fi
max_queued_messages=$(python3 \
  "$repo_root/tools/interop/mqtt_broker_benchmark_config.py" \
  "${queue_args[@]}")
work=$(mktemp -d)
. "$repo_root/tools/interop/mosquitto_build.sh"
server_pid=
sampler_pid=
stats=${MQTT_STATS:-false}
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
  rm -rf "$work"
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
  timeout 60s "$driver" \
    "--address=127.0.0.1:$port" \
    "--publishers=$publishers" \
    "--subscribers=$subscribers" \
    "--warmup-messages=$warmup_messages" \
    "--messages=$messages" \
    "--payload-bytes=$payload_bytes" \
    "--publisher-window=$publisher_window" \
    "--server-queue-capacity=$max_queued_messages" \
    "--server-implementation=$server_implementation" \
    "--server-io=$server_io" \
    >"$output" 2>&1
  grep -Fq 'MQTT 5 TCP broker fanout workload' "$output"
  grep -Fq 'client io backend: zio-std-io' "$output"
  grep -Fq \
    "record=result implementation=netz protocol=mqtt5 transport=tcp mode=qos1-fanout role_pair=netz-client+$server_implementation-server client_io=zio-std-io server_io=$server_io" \
    "$output"
  grep -Eq 'publishes/s: [1-9][0-9]*' "$output"
  grep -Eq 'deliveries/s: [1-9][0-9]*' "$output"
  grep -Eq 'checksum: [1-9][0-9]*' "$output"
}

mosquitto_binary=$(resolve_mosquitto)

netz_port=$(free_tcp_port)
"$netz_broker" \
  "--bind=127.0.0.1:$netz_port" \
  "--connections=$((publishers + subscribers))" \
  "--max-queued-deliveries=$max_queued_messages" \
  --max-outgoing-inflight=64 \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/netz-server.log" \
  'netz MQTT 3.1.1/5 broker listening.*server_io=zio-std-io'
if [[ "$stats" == true ]]; then
  start_rss_sampler "$server_pid" "$work/netz-server.rss"
fi
run_driver "$netz_port" "$work/netz-result.txt" netz zio-std-io
wait "$server_pid"
server_pid=
finish_rss_sampler

mosquitto_port=$(free_tcp_port)
cat >"$work/mosquitto.conf" <<EOF
listener $mosquitto_port 127.0.0.1
allow_anonymous true
persistence false
max_inflight_messages 64
max_queued_messages $max_queued_messages
log_dest stdout
EOF
"$mosquitto_binary" -c "$work/mosquitto.conf" -v \
  >"$work/mosquitto-server.log" 2>&1 &
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

check_args=(python3 \
  "$repo_root/tools/interop/mqtt_broker_benchmark_check.py" \
  --netz-log "$work/netz-result.txt" \
  --mosquitto-log "$work/mosquitto-result.txt" \
  --publishers "$publishers" \
  --subscribers "$subscribers" \
  --warmup "$warmup_messages" \
  --messages "$messages" \
  --payload-bytes "$payload_bytes" \
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
echo "equal-wire MQTT comparison passed (Mosquitto $(git -C "$mosquitto_root" rev-parse --short HEAD)) client_io=zio-std-io server_io=zio-std-io+mosquitto-event-loop"
