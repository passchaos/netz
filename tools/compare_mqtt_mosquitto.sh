#!/usr/bin/env bash
set -euo pipefail

netz_broker=${1:?netz broker executable path}
driver=${2:?netz MQTT benchmark driver path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mosquitto_root=${MOSQUITTO_ROOT:-"$HOME/Work/mosquitto"}
mosquitto_binary=${MOSQUITTO_BIN:-}
expected_mosquitto_commit=${MOSQUITTO_COMMIT:-5cd25465}
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

build_mosquitto() {
  local build_dir="$work/mosquitto-build"
  local cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
    -DWITH_APPS=OFF -DWITH_CLIENTS=OFF -DWITH_DOCS=OFF
    -DWITH_PLUGINS=OFF -DWITH_TESTS=OFF -DWITH_TLS=OFF
    -DWITH_WEBSOCKETS=OFF -DWITH_UNIX_SOCKETS=OFF
  )
  if [[ -n "${CJSON_INCLUDE_DIR:-}" ]]; then
    cmake_args+=("-DCJSON_INCLUDE_DIR=$CJSON_INCLUDE_DIR")
  elif [[ -f /usr/include/cjson/cJSON.h ]]; then
    cmake_args+=("-DCJSON_INCLUDE_DIR=/usr/include")
  elif [[ -e /usr/lib/x86_64-linux-gnu/libcjson.so.1 ]]; then
    # Runtime-only distro packages omit the development header and unversioned
    # linker name. Fetch the matching upstream declaration into the temporary
    # build tree; do not mutate the audited Mosquitto checkout or system.
    mkdir -p "$work/cjson-include/cjson"
    curl -fsSL \
      https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.17/cJSON.h \
      -o "$work/cjson-include/cjson/cJSON.h"
    echo 'c01a8ca5609bb2c956dd1ae836d5d926ec68153ecebc5a75ea0febc2e076da8d  cJSON.h' \
      | (cd "$work/cjson-include/cjson" && sha256sum -c -) >&2
    cmake_args+=("-DCJSON_INCLUDE_DIR=$work/cjson-include")
  fi
  if [[ -n "${CJSON_LIBRARY:-}" ]]; then
    cmake_args+=("-DCJSON_LIBRARY=$CJSON_LIBRARY")
  elif [[ ! -e /usr/lib/x86_64-linux-gnu/libcjson.so &&
        -e /usr/lib/x86_64-linux-gnu/libcjson.so.1 ]]; then
    ln -s /usr/lib/x86_64-linux-gnu/libcjson.so.1 \
      "$work/libcjson.so"
    cmake_args+=("-DCJSON_LIBRARY=$work/libcjson.so")
  fi
  if [[ ! -f "$mosquitto_root/CMakeLists.txt" ]]; then
    echo "Mosquitto checkout not found at $mosquitto_root" >&2
    echo 'set MOSQUITTO_ROOT to an audited local checkout' >&2
    exit 1
  fi
  cmake -S "$mosquitto_root" -B "$build_dir" "${cmake_args[@]}" \
    >"$work/mosquitto-configure.log" || {
      cat "$work/mosquitto-configure.log" >&2
      echo 'Mosquitto build dependencies are unavailable; install its documented build dependencies (including cJSON development headers).' >&2
      exit 1
    }
  cmake --build "$build_dir" --target mosquitto -j2 \
    >"$work/mosquitto-build.log" || {
      cat "$work/mosquitto-build.log" >&2
      exit 1
    }
  printf '%s\n' "$build_dir/src/mosquitto"
}

resolve_mosquitto() {
  if [[ -n "$mosquitto_binary" ]]; then
    [[ -x "$mosquitto_binary" ]] || {
      echo "MOSQUITTO_BIN is not executable: $mosquitto_binary" >&2
      exit 1
    }
    printf '%s\n' "$mosquitto_binary"
    return
  fi
  local actual_commit
  actual_commit=$(git -C "$mosquitto_root" rev-parse --short HEAD)
  if [[ "$actual_commit" != "$expected_mosquitto_commit" ]]; then
    echo "Mosquitto checkout is $actual_commit; expected $expected_mosquitto_commit" >&2
    echo 'set MOSQUITTO_COMMIT explicitly when auditing another revision' >&2
    exit 1
  fi
  for candidate in \
    "$mosquitto_root/build/src/mosquitto" \
    "$mosquitto_root/src/mosquitto"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  build_mosquitto
}

run_driver() {
  local port=$1
  local output=$2
  timeout 60s "$driver" \
    "--address=127.0.0.1:$port" \
    "--publishers=${PUBLISHERS:-2}" \
    "--subscribers=${SUBSCRIBERS:-2}" \
    "--warmup-messages=${WARMUP_MESSAGES:-100}" \
    "--messages=${MESSAGES:-2000}" \
    "--payload-bytes=${PAYLOAD_BYTES:-256}" \
    "--publisher-window=${PUBLISHER_WINDOW:-16}" \
    >"$output" 2>&1
  grep -Fq 'MQTT 5 TCP broker fanout workload' "$output"
  grep -Eq 'publishes/s: [1-9][0-9]*' "$output"
  grep -Eq 'deliveries/s: [1-9][0-9]*' "$output"
  grep -Eq 'checksum: [1-9][0-9]*' "$output"
}

result_value() {
  local label=$1
  local output=$2
  awk -F': ' -v label="$label" '$1 ~ "^[[:space:]]*" label "$" { print $2 }' "$output"
}

mosquitto_binary=$(resolve_mosquitto)

netz_port=$(free_tcp_port)
"$netz_broker" \
  "--bind=127.0.0.1:$netz_port" \
  "--connections=$((${PUBLISHERS:-2} + ${SUBSCRIBERS:-2}))" \
  --max-queued-deliveries=1024 \
  --max-outgoing-inflight=64 \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/netz-server.log" 'netz MQTT 3.1.1/5 broker listening'
run_driver "$netz_port" "$work/netz-result.txt"
wait "$server_pid"
server_pid=

mosquitto_port=$(free_tcp_port)
cat >"$work/mosquitto.conf" <<EOF
listener $mosquitto_port 127.0.0.1
allow_anonymous true
persistence false
max_inflight_messages 64
max_queued_messages 1024
log_dest stdout
EOF
"$mosquitto_binary" -c "$work/mosquitto.conf" -v \
  >"$work/mosquitto-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/mosquitto-server.log" 'mosquitto version.*running'
run_driver "$mosquitto_port" "$work/mosquitto-result.txt"
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=

for label in 'measured publishes' 'measured deliveries' 'checksum'; do
  netz_value=$(result_value "$label" "$work/netz-result.txt")
  mosquitto_value=$(result_value "$label" "$work/mosquitto-result.txt")
  if [[ -z "$netz_value" || "$netz_value" != "$mosquitto_value" ]]; then
    echo "comparison mismatch for $label: netz=$netz_value mosquitto=$mosquitto_value" >&2
    exit 1
  fi
done

echo '--- netz ---'
cat "$work/netz-result.txt"
echo '--- Mosquitto ---'
cat "$work/mosquitto-result.txt"
echo "equal-wire MQTT comparison passed (Mosquitto $(git -C "$mosquitto_root" rev-parse --short HEAD))"
