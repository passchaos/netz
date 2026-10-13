#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz MQTT broker executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/interop/mqtt_rumqttc/Cargo.toml"
client="$repo_root/tools/interop/mqtt_rumqttc/target/release/netz-mqtt-rumqttc-interop"
work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --offline --locked --manifest-path "$manifest"
port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
"$server" \
  "--bind=127.0.0.1:$port" \
  --connections=6 \
  --max-queued-deliveries=32 \
  --max-outgoing-inflight=16 \
  --max-packet-size=4096 \
  >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -Fq 'netz MQTT 3.1/3.1.1/5 broker listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.025
done
if ! timeout 30s "$client" "$port" >"$work/client.log" 2>&1; then
  cat "$work/client.log" >&2
  cat "$work/server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/client.log"
grep -Fq \
  'rumqttc client interop passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 qos=0,1,2 retained=true single-delivery=true automatic-ack=true response-topic=true correlation-data=true user-property=true session-resume=true offline-qos1=true client_io=rumqttc-tokio server_io=zio-std-io' \
  "$work/client.log"
grep -Fq 'server_io=zio-std-io' "$work/server.log"
