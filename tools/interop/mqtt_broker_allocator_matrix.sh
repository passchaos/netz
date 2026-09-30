#!/usr/bin/env bash
set -euo pipefail

broker=${1:?netz broker executable path}
driver=${2:?netz MQTT benchmark driver path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
samples=${MQTT_ALLOCATOR_MATRIX_SAMPLES:-4}
qos=${MQTT_QOS:-1}
if [[ ! "$samples" =~ ^[0-9]+$ || "$samples" -eq 0 ]]; then
  echo 'MQTT_ALLOCATOR_MATRIX_SAMPLES must be positive' >&2
  exit 2
fi
if [[ "$qos" != 1 && "$qos" != 2 ]]; then
  echo 'MQTT_QOS must be 1 or 2' >&2
  exit 2
fi
if [[ -n "${MQTT_ALLOCATOR_MATRIX_ROOT:-}" ]]; then
  root=$MQTT_ALLOCATOR_MATRIX_ROOT
else
  root="$repo_root/zig-out/mqtt-broker-allocator-matrix/run.$(date -u +%Y%m%dT%H%M%SZ).$$"
fi
if [[ -e "$root" ]]; then
  echo "MQTT allocator matrix root already exists: $root" >&2
  exit 2
fi
mkdir -p "$root/identity"
root=$(realpath "$root")
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

mapfile -t cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
)
if [[ ${#cpus[@]} -lt 2 ]]; then
  echo 'MQTT allocator matrix requires two available CPUs' >&2
  exit 1
fi
client_cpu=${cpus[0]}
server_cpu=${cpus[1]}

install -m 0755 "$broker" "$root/identity/netz-broker"
install -m 0755 "$driver" "$root/identity/mqtt-driver"
install -m 0755 "$repo_root/tools/interop/mqtt_broker_allocator_matrix.sh" \
  "$root/identity/mqtt_broker_allocator_matrix.sh"
install -m 0755 "$repo_root/tools/interop/mqtt_broker_allocator_matrix_check.py" \
  "$root/identity/mqtt_broker_allocator_matrix_check.py"

sha256() { sha256sum "$1" | awk '{print $1}'; }
printf 'record=environment protocol=mqtt5 transport=tcp mode=qos%s-fanout-allocator-matrix benchmark_scope=same-client-workload timing_usable=false allocator_scope=broker-explicit connection_scope=persistent client_tcp_nodelay=true server_tcp_nodelay=true shapes=%s samples=%s schedule=sequential client_cpu=%s server_cpu=%s timeout_seconds=60 max_artifact_bytes=33554432 max_matrix_bytes=134217728 host=%s arch=%s kernel=%s zig=%s netz_build_mode=ReleaseFast netz_broker_sha256=%s driver_sha256=%s runner_sha256=%s checker_sha256=%s complete=true\n' \
  "$qos" \
  "$(python3 "$root/identity/mqtt_broker_allocator_matrix_check.py" --list-shapes | wc -l)" \
  "$samples" "$client_cpu" "$server_cpu" "$(hostname)" "$(uname -m)" \
  "$(uname -r)" "$(zig version)" \
  "$(sha256 "$root/identity/netz-broker")" \
  "$(sha256 "$root/identity/mqtt-driver")" \
  "$(sha256 "$root/identity/mqtt_broker_allocator_matrix.sh")" \
  "$(sha256 "$root/identity/mqtt_broker_allocator_matrix_check.py")" \
  >"$root/environment.log"

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

while IFS=$'\t' read -r shape publishers subscribers warmup messages payload window; do
  queue_capacity=$((messages > 1024 ? messages : 1024))
  for ((sample = 1; sample <= samples; sample++)); do
    printf 'mqtt_allocator_shape=%s sample=%d/%d\n' "$shape" "$sample" "$samples"
    run="$root/$shape/sample-$(printf '%02d' "$sample")"
    mkdir -p "$run"
    port=$(free_port)
    taskset -c "$server_cpu" timeout 60s "$root/identity/netz-broker" \
      "--bind=127.0.0.1:$port" \
      "--connections=$((publishers + subscribers))" \
      "--max-queued-deliveries=$queue_capacity" \
      --max-outgoing-inflight=64 --allocator-stats \
      "--allocator-stats-qos=$qos" \
      >"$run/server.log" 2>&1 &
    server_pid=$!
    for _ in $(seq 1 200); do
      if grep -q 'netz MQTT 3.1.1/5 broker listening' "$run/server.log"; then
        break
      fi
      if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$run/server.log" >&2
        exit 1
      fi
      sleep 0.05
    done
    grep -q 'netz MQTT 3.1.1/5 broker listening' "$run/server.log"
    taskset -c "$client_cpu" timeout 60s "$root/identity/mqtt-driver" \
      "--address=127.0.0.1:$port" "--publishers=$publishers" \
      "--subscribers=$subscribers" "--warmup-messages=$warmup" \
      "--messages=$messages" "--payload-bytes=$payload" \
      "--qos=$qos" \
      "--publisher-window=$window" \
      "--server-queue-capacity=$queue_capacity" \
      --server-implementation=netz --server-io=zio-std-io \
      --server-tcp-nodelay=true >"$run/driver.log" 2>&1
    wait "$server_pid"
    server_pid=
    grep -q '^record=allocator .* complete=true$' "$run/server.log"
    grep -q '^record=result .* complete=true$' "$run/driver.log"
  done
done < <(python3 "$root/identity/mqtt_broker_allocator_matrix_check.py" --list-shapes)

: >"$root/summary.log"
python3 "$root/identity/mqtt_broker_allocator_matrix_check.py" \
  --root "$root" --samples "$samples" \
  --qos "$qos" \
  --client-cpu "$client_cpu" --server-cpu "$server_cpu" \
  >"$work/summary.log"
cp "$work/summary.log" "$root/summary.log"
cmp "$work/summary.log" <(
  python3 "$root/identity/mqtt_broker_allocator_matrix_check.py" \
    --root "$root" --samples "$samples" \
    --qos "$qos" \
    --client-cpu "$client_cpu" --server-cpu "$server_cpu"
)
matrix_bytes=$(du -sb "$root" | awk '{print $1}')
if [[ "$matrix_bytes" -gt 134217728 ]]; then
  echo "MQTT allocator matrix exceeds 128 MiB: $matrix_bytes" >&2
  exit 1
fi
cat "$root/summary.log"
echo "MQTT broker allocator matrix artifacts: $root"
