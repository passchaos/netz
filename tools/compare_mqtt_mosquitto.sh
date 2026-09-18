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

build_mosquitto() {
  local build_dir="$work/mosquitto-build"
  local multiarch
  multiarch=$(cc -print-multiarch 2>/dev/null || true)
  local system_cjson="/usr/lib/$multiarch/libcjson.so.1"
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
  elif [[ -n "$multiarch" && -e "$system_cjson" ]]; then
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
  elif [[ -n "$multiarch" && ! -e "/usr/lib/$multiarch/libcjson.so" &&
        -e "$system_cjson" ]]; then
    ln -s "$system_cjson" \
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
  local server_implementation=$3
  local server_io=$4
  timeout 60s "$driver" \
    "--address=127.0.0.1:$port" \
    "--publishers=${PUBLISHERS:-2}" \
    "--subscribers=${SUBSCRIBERS:-2}" \
    "--warmup-messages=${WARMUP_MESSAGES:-100}" \
    "--messages=${MESSAGES:-2000}" \
    "--payload-bytes=${PAYLOAD_BYTES:-256}" \
    "--publisher-window=${PUBLISHER_WINDOW:-16}" \
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
  "--connections=$((${PUBLISHERS:-2} + ${SUBSCRIBERS:-2}))" \
  --max-queued-deliveries=1024 \
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
max_queued_messages 1024
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
  --publishers "${PUBLISHERS:-2}" \
  --subscribers "${SUBSCRIBERS:-2}" \
  --warmup "${WARMUP_MESSAGES:-100}" \
  --messages "${MESSAGES:-2000}" \
  --payload-bytes "${PAYLOAD_BYTES:-256}" \
  --publisher-window "${PUBLISHER_WINDOW:-16}")
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
