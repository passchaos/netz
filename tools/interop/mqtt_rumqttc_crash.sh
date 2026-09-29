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
  'rumqttc crash preparation passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 persistent-subscription=true offline-qos1=true client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/prepare.log"
[[ -s "$journal" ]]
kill -KILL "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=

restored_port=$(free_port)
start_broker "$restored_port" 2 "$work/restored-server.log"
timeout 30s "$client" recover-crash "$restored_port" \
  >"$work/recover.log" 2>&1 || {
    cat "$work/recover.log" >&2
    cat "$work/restored-server.log" >&2
    exit 1
  }
wait "$server_pid"
server_pid=
cat "$work/recover.log"
grep -Fq \
  'rumqttc crash recovery passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 sigkill=true commit-log=true session-present=true no-resubscribe=true offline-qos1=true single-delivery=true automatic-ack=true client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/recover.log"
grep -Fq 'server_io=zio-std-io' "$work/source-server.log"
grep -Fq 'server_io=zio-std-io' "$work/restored-server.log"
