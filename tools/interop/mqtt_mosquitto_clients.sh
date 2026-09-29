#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz MQTT broker executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
. "$repo_root/tools/interop/mosquitto_build.sh"
server_pid=
subscriber_pid=

cleanup() {
  if [[ -n "$subscriber_pid" ]]; then
    kill "$subscriber_pid" 2>/dev/null || true
    wait "$subscriber_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local exit_status=$?
  if [[ $exit_status -ne 0 ]]; then
    find "$work" -maxdepth 1 -type f -size +0c -print -exec sed -n '1,240p' {} \; >&2
  fi
  cleanup
  exit "$exit_status"
}
trap on_exit EXIT

free_port() {
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
  local pid=$3
  for _ in $(seq 1 200); do
    if grep -Fq "$marker" "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.025
  done
  return 1
}

IFS=$'\t' read -r mosquitto_pub mosquitto_sub client_source \
  < <(resolve_mosquitto_clients)
client_version=$({ "$mosquitto_pub" --help 2>&1 || true; } | sed -nE \
  's/^mosquitto_pub version ([^ ]+) running on libmosquitto ([0-9.]+)\.$/mosquitto_pub-\1+libmosquitto-\2/p')
if [[ -z "$client_version" ]]; then
  echo 'unable to identify mosquitto_pub/libmosquitto version' >&2
  exit 1
fi
port=$(free_port)
"$server" \
  "--bind=127.0.0.1:$port" \
  --connections=13 \
  --max-queued-deliveries=32 \
  --max-outgoing-inflight=16 \
  --max-packet-size=4096 \
  >"$work/server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/server.log" \
  'netz MQTT 3.1.1/5 broker listening' "$server_pid"

run_version() {
  local label=$1
  local protocol=$2
  local topic="interop/$label/live"
  local retained_topic="interop/$label/retained"
  local output="$work/$label.out"
  local expected="$work/$label.expected"

  timeout 10s "$mosquitto_pub" -V "$protocol" -h 127.0.0.1 -p "$port" \
    -i "netz-$label-retain-pub" -t "$retained_topic" -q 1 -r \
    -m "retained-$label"
  timeout 12s "$mosquitto_sub" -V "$protocol" -h 127.0.0.1 -p "$port" \
    -i "netz-$label-sub" -t "$retained_topic" -t "$topic" -q 2 \
    -C 4 -W 10 -F '%t|%q|%r|%p' >"$output" 2>"$work/$label.err" &
  subscriber_pid=$!
  wait_for_log "$output" \
    "$retained_topic|1|1|retained-$label" "$subscriber_pid"

  for qos in 0 1 2; do
    timeout 10s "$mosquitto_pub" -V "$protocol" -h 127.0.0.1 -p "$port" \
      -i "netz-$label-pub-$qos" -t "$topic" -q "$qos" \
      -m "payload-$qos"
  done
  wait "$subscriber_pid"
  subscriber_pid=
  printf '%s\n' \
    "$retained_topic|1|1|retained-$label" \
    "$topic|0|0|payload-0" \
    "$topic|1|0|payload-1" \
    "$topic|2|0|payload-2" >"$expected"
  diff -u "$expected" "$output"
}

run_version mqtt311 mqttv311
run_version mqtt5 mqttv5

# One additional MQTT 5 client pair proves Response Topic and binary
# Correlation Data survive broker fanout and are decoded by libmosquitto.
property_topic=interop/mqtt5/properties
property_ready=interop/mqtt5/properties-ready
timeout 10s "$mosquitto_pub" -V mqttv5 -h 127.0.0.1 -p "$port" \
  -i netz-mqtt5-property-ready-pub -t "$property_ready" -q 1 -r \
  -m ready
timeout 12s "$mosquitto_sub" -V mqttv5 -h 127.0.0.1 -p "$port" \
  -i netz-mqtt5-property-sub -t "$property_ready" -t "$property_topic" \
  -q 0 -C 2 -W 10 \
  -F '%t|%R|%D|%p' >"$work/properties.out" \
  2>"$work/properties.err" &
subscriber_pid=$!
wait_for_log "$work/properties.out" "$property_ready|||ready" \
  "$subscriber_pid"
timeout 10s "$mosquitto_pub" -V mqttv5 -h 127.0.0.1 -p "$port" \
  -i netz-mqtt5-property-pub -t "$property_topic" -q 0 \
  -D PUBLISH response-topic interop/mqtt5/reply \
  -D PUBLISH correlation-data correlation-42 \
  -m property-payload
wait "$subscriber_pid"
subscriber_pid=
printf '%s\n' \
  "$property_ready|||ready" \
  "$property_topic|interop/mqtt5/reply|correlation-42|property-payload" \
  >"$work/properties.expected"
diff -u "$work/properties.expected" "$work/properties.out"

wait "$server_pid"
server_pid=
grep -Fq 'server_io=zio-std-io' "$work/server.log"
echo "Mosquitto CLI client interop passed: source=$client_source version=$client_version protocols=mqtt311,mqtt5 qos=0,1,2 retained=true response-topic=true correlation-data=true client_io=libmosquitto server_io=zio-std-io"
