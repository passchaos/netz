#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz MQTT broker executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/interop/mqtt_rumqttc/Cargo.toml"
client="$repo_root/tools/interop/mqtt_rumqttc/target/release/netz-mqtt-rumqttc-interop"
work=$(mktemp -d)
journal="$work/broker.log"
server_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill -KILL "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --offline --locked --manifest-path "$manifest"
free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
start_broker() {
  local port=$1
  local connections=$2
  local log=$3
  "$server" \
    "--bind=127.0.0.1:$port" \
    "--connections=$connections" \
    --max-queued-deliveries=32 \
    --max-outgoing-inflight=16 \
    --max-packet-size=4096 \
    "--commit-log=$journal" \
    >"$log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -Fq 'netz MQTT 3.1.1/5 broker listening' "$log"; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      exit 1
    fi
    sleep 0.025
  done
  cat "$log" >&2
  echo 'timed out waiting for netz MQTT broker' >&2
  exit 1
}

source_port=$(free_port)
start_broker "$source_port" 5 "$work/source-server.log"
timeout 30s "$client" prepare-crash "$source_port" \
  >"$work/prepare.log" 2>&1 || {
    cat "$work/prepare.log" >&2
    cat "$work/source-server.log" >&2
    exit 1
  }
grep -Fq \
  'rumqttc crash preparation passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 persistent-subscription=true offline-qos=1,2 client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/prepare.log"
[[ -s "$journal" ]]
kill -KILL "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

delivery_port=$(free_port)
start_broker "$delivery_port" 3 "$work/delivery-server.log"
packet_ids="$work/packet-ids"
timeout 30s "$client" deliver-unacked "$delivery_port" "$packet_ids" \
  >"$work/delivery.log" 2>&1 || {
    cat "$work/delivery.log" >&2
    cat "$work/delivery-server.log" >&2
    exit 1
  }
grep -Fq \
  'rumqttc unacknowledged delivery passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 offline-qos=1,2 session-present=true no-resubscribe=true manual-ack=true dup=false client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/delivery.log"
v4_qos1_packet_id=$(sed -n 's/^v4_qos1_pkid=//p' "$packet_ids")
v4_qos2_packet_id=$(sed -n 's/^v4_qos2_pkid=//p' "$packet_ids")
v5_qos1_packet_id=$(sed -n 's/^v5_qos1_pkid=//p' "$packet_ids")
v5_qos2_packet_id=$(sed -n 's/^v5_qos2_pkid=//p' "$packet_ids")
[[ "$v4_qos1_packet_id" =~ ^[1-9][0-9]*$ ]]
[[ "$v4_qos2_packet_id" =~ ^[1-9][0-9]*$ ]]
[[ "$v5_qos1_packet_id" =~ ^[1-9][0-9]*$ ]]
[[ "$v5_qos2_packet_id" =~ ^[1-9][0-9]*$ ]]
kill -KILL "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

retry_port=$(free_port)
start_broker "$retry_port" 3 "$work/retry-server.log"
timeout 30s "$client" retry-ack "$retry_port" \
  "$v4_qos1_packet_id" "$v4_qos2_packet_id" \
  "$v5_qos1_packet_id" "$v5_qos2_packet_id" \
  >"$work/retry.log" 2>&1 || {
    cat "$work/retry.log" >&2
    cat "$work/retry-server.log" >&2
    exit 1
  }
grep -Fq \
  'rumqttc inflight retry passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 qos=1,2 sigkill=true commit-log=true session-present=true no-resubscribe=true dup=true stable-packet-id=true manual-puback=true manual-pubrec=true pubrel=true pubcomp=true client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/retry.log"
kill -KILL "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

final_port=$(free_port)
start_broker "$final_port" 2 "$work/final-server.log"
timeout 30s "$client" verify-cleared "$final_port" \
  >"$work/final.log" 2>&1 || {
    cat "$work/final.log" >&2
    cat "$work/final-server.log" >&2
    exit 1
  }
wait "$server_pid"
server_pid=
cat "$work/final.log"
grep -Fq \
  'rumqttc crash recovery passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 offline-qos=1,2 sigkill=true commit-log=true session-present=true no-resubscribe=true dup-retry=true stable-packet-id=true acknowledged-not-replayed=true client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/final.log"
grep -Fq 'server_io=zio-std-io' "$work/source-server.log"
grep -Fq 'server_io=zio-std-io' "$work/delivery-server.log"
grep -Fq 'server_io=zio-std-io' "$work/retry-server.log"
grep -Fq 'server_io=zio-std-io' "$work/final-server.log"
