#!/usr/bin/env bash
set -euo pipefail

netz_broker=${1:?netz broker executable path}
driver=${2:?netz MQTT benchmark driver path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
samples=${MQTT_MATRIX_SAMPLES:-4}
qos=${MQTT_QOS:-1}
session_expiry_seconds=${MQTT_SESSION_EXPIRY_SECONDS:-0}
if [[ ! "$samples" =~ ^[0-9]+$ || "$samples" -eq 0 ||
      $((samples % 4)) -ne 0 ]]; then
  echo 'MQTT_MATRIX_SAMPLES must be a positive multiple of four' >&2
  exit 2
fi
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
if [[ -n "${MQTT_MATRIX_ROOT:-}" ]]; then
  matrix_root=$MQTT_MATRIX_ROOT
else
  matrix_root="$repo_root/zig-out/mqtt-broker-matrix/run.$(date -u +%Y%m%dT%H%M%SZ).$$"
fi
if [[ -e "$matrix_root" ]]; then
  echo "MQTT matrix artifact root already exists: $matrix_root" >&2
  exit 2
fi
mkdir -p "$matrix_root/identity"
matrix_root=$(realpath "$matrix_root")
build_work=$(mktemp -d)
work=$build_work
. "$repo_root/tools/interop/mosquitto_build.sh"
trap 'rm -rf "$build_work"' EXIT
audited_mosquitto_revision=5cd2546511596a269dbf53f85858c623b09ebdd6
if [[ -n "${MOSQUITTO_BIN:-}" ]]; then
  echo 'MQTT matrix builds Mosquitto from the audited checkout; MOSQUITTO_BIN is not accepted' >&2
  exit 2
fi
if [[ -n "${MOSQUITTO_COMMIT:-}" && "$MOSQUITTO_COMMIT" != 5cd25465 ]]; then
  echo 'MQTT matrix does not accept a Mosquitto revision override' >&2
  exit 2
fi
expected_mosquitto_commit=5cd25465
verify_mosquitto_checkout
if [[ -n $(git -C "$mosquitto_root" status --porcelain=v1 --untracked-files=all) ]]; then
  echo "Mosquitto checkout must be clean for a matrix capture: $mosquitto_root" >&2
  exit 1
fi
mosquitto_binary=$(build_mosquitto)
mosquitto_revision=$(git -C "$mosquitto_root" rev-parse HEAD)
if [[ "$mosquitto_revision" != "$audited_mosquitto_revision" ]]; then
  echo "Mosquitto checkout is $mosquitto_revision; expected $audited_mosquitto_revision" >&2
  exit 1
fi

mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:3]:
    print(cpu)
PY
)
if [[ ${#bench_cpus[@]} -lt 3 ]]; then
  echo 'MQTT matrix requires three available CPUs' >&2
  exit 1
fi
client_cpu=${bench_cpus[0]}
server_cpu=${bench_cpus[1]}
sampler_cpu=${bench_cpus[2]}

install -m 0755 "$netz_broker" "$matrix_root/identity/netz-broker"
install -m 0755 "$driver" "$matrix_root/identity/mqtt-driver"
install -m 0755 "$mosquitto_binary" "$matrix_root/identity/mosquitto"
install -m 0755 "$repo_root/tools/compare_mqtt_mosquitto.sh" \
  "$matrix_root/identity/compare_mqtt_mosquitto.sh"
install -m 0755 "$repo_root/tools/interop/mqtt_broker_matrix.sh" \
  "$matrix_root/identity/mqtt_broker_matrix.sh"
install -m 0644 "$repo_root/tools/interop/mqtt_broker_benchmark_check.py" \
  "$matrix_root/identity/mqtt_broker_benchmark_check.py"
install -m 0644 "$repo_root/tools/interop/mqtt_broker_benchmark_config.py" \
  "$matrix_root/identity/mqtt_broker_benchmark_config.py"
install -m 0755 "$repo_root/tools/interop/mqtt_broker_matrix_check.py" \
  "$matrix_root/identity/mqtt_broker_matrix_check.py"
install -m 0644 "$repo_root/tools/interop/mosquitto_build.sh" \
  "$matrix_root/identity/mosquitto_build.sh"
install -m 0644 "$build_work/mosquitto-configure.log" \
  "$matrix_root/identity/mosquitto-configure.log"
install -m 0644 "$build_work/mosquitto-build.log" \
  "$matrix_root/identity/mosquitto-build.log"
printf '%s\n' "$mosquitto_revision" >"$matrix_root/identity/mosquitto-head.txt"
printf 'revision=%s source_clean=true\n' "$mosquitto_revision" \
  >"$matrix_root/identity/mosquitto-source-state.txt"
mapfile -t matrix_shapes < <(
  python3 "$matrix_root/identity/mqtt_broker_matrix_check.py" --list-shapes
)
if [[ ${#matrix_shapes[@]} -eq 0 ]]; then
  echo 'MQTT matrix checker returned no shapes' >&2
  exit 1
fi

sha256() { sha256sum "$1" | awk '{print $1}'; }
printf 'record=environment protocol=mqtt5 transport=tcp mode=qos%s-fanout-matrix benchmark_scope=same-client-workload timing_usable=true client_tcp_nodelay=true server_tcp_nodelay=true session_expiry_seconds=%s shapes=%s samples=%s schedule=abba client_cpu=%s server_cpu=%s sampler_cpu=%s rss_source=proc-vmrss-sampled-2ms max_artifact_bytes=33554432 max_matrix_bytes=134217728 host=%s arch=%s kernel=%s zig=%s netz_build_mode=ReleaseFast mosquitto_revision=%s mosquitto_source_clean=true netz_broker_sha256=%s driver_sha256=%s mosquitto_binary_sha256=%s single_runner_sha256=%s matrix_runner_sha256=%s single_checker_sha256=%s config_helper_sha256=%s matrix_checker_sha256=%s mosquitto_build_helper_sha256=%s mosquitto_configure_log_sha256=%s mosquitto_build_log_sha256=%s mosquitto_source_state_sha256=%s complete=true\n' \
  "$qos" "$session_expiry_seconds" "${#matrix_shapes[@]}" "$samples" "$client_cpu" "$server_cpu" "$sampler_cpu" \
  "$(hostname)" "$(uname -m)" "$(uname -r)" "$(zig version)" \
  "$mosquitto_revision" \
  "$(sha256 "$matrix_root/identity/netz-broker")" \
  "$(sha256 "$matrix_root/identity/mqtt-driver")" \
  "$(sha256 "$matrix_root/identity/mosquitto")" \
  "$(sha256 "$matrix_root/identity/compare_mqtt_mosquitto.sh")" \
  "$(sha256 "$matrix_root/identity/mqtt_broker_matrix.sh")" \
  "$(sha256 "$matrix_root/identity/mqtt_broker_benchmark_check.py")" \
  "$(sha256 "$matrix_root/identity/mqtt_broker_benchmark_config.py")" \
  "$(sha256 "$matrix_root/identity/mqtt_broker_matrix_check.py")" \
  "$(sha256 "$matrix_root/identity/mosquitto_build.sh")" \
  "$(sha256 "$matrix_root/identity/mosquitto-configure.log")" \
  "$(sha256 "$matrix_root/identity/mosquitto-build.log")" \
  "$(sha256 "$matrix_root/identity/mosquitto-source-state.txt")" \
  >"$matrix_root/environment.log"

for shape_record in "${matrix_shapes[@]}"; do
  IFS=$'\t' read -r shape publishers subscribers warmup messages payload window \
    <<<"$shape_record"
  for ((sample = 1; sample <= samples; sample++)); do
    case $(((sample - 1) % 4)) in
      0|3) order=netz-first ;;
      1|2) order=mosquitto-first ;;
    esac
    printf 'mqtt_matrix_shape=%s sample=%d/%d broker_order=%s\n' \
      "$shape" "$sample" "$samples" "$order"
    sample_dir="$matrix_root/$shape/sample-$(printf '%02d' "$sample")"
    mkdir -p "$sample_dir"
    PUBLISHERS="$publishers" SUBSCRIBERS="$subscribers" \
      WARMUP_MESSAGES="$warmup" MESSAGES="$messages" \
      PAYLOAD_BYTES="$payload" PUBLISHER_WINDOW="$window" \
      MQTT_QOS="$qos" \
      MQTT_SESSION_EXPIRY_SECONDS="$session_expiry_seconds" \
      MQTT_STATS=true MQTT_BROKER_ORDER="$order" \
      MQTT_CLIENT_CPU="$client_cpu" MQTT_SERVER_CPU="$server_cpu" \
      MQTT_SAMPLER_CPU="$sampler_cpu" \
      MQTT_ARTIFACT_DIR="$sample_dir/artifacts" \
      NETZ_REPO_ROOT="$repo_root" \
      NETZ_INTEROP_ROOT="$matrix_root/identity" \
      MOSQUITTO_ROOT="$mosquitto_root" MOSQUITTO_COMMIT="$expected_mosquitto_commit" \
      MOSQUITTO_BIN="$matrix_root/identity/mosquitto" \
      "$matrix_root/identity/compare_mqtt_mosquitto.sh" \
      "$matrix_root/identity/netz-broker" \
      "$matrix_root/identity/mqtt-driver" \
      >"$sample_dir/runner.log" 2>&1
  done
done
matrix_bytes=$(du -sb "$matrix_root" | awk '{print $1}')
if [[ "$matrix_bytes" -gt 134217728 ]]; then
  echo "MQTT matrix artifacts exceed 128 MiB: $matrix_bytes bytes" >&2
  exit 1
fi

: >"$matrix_root/summary.log"
python3 "$matrix_root/identity/mqtt_broker_matrix_check.py" \
  --root "$matrix_root" --samples "$samples" \
  --qos "$qos" \
  --session-expiry-seconds "$session_expiry_seconds" \
  --client-cpu "$client_cpu" --server-cpu "$server_cpu" \
  --sampler-cpu "$sampler_cpu" >"$build_work/summary.log"
cp "$build_work/summary.log" "$matrix_root/summary.log"
cmp "$build_work/summary.log" <(
  python3 "$matrix_root/identity/mqtt_broker_matrix_check.py" \
    --root "$matrix_root" --samples "$samples" \
    --qos "$qos" \
    --session-expiry-seconds "$session_expiry_seconds" \
    --client-cpu "$client_cpu" --server-cpu "$server_cpu" \
    --sampler-cpu "$sampler_cpu"
)
cat "$matrix_root/summary.log"
echo "MQTT broker matrix artifacts: $matrix_root"
