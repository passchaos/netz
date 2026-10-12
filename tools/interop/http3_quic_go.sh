#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz HTTP/3 client executable path}
server=${2:?netz HTTP/3 server executable path}
bench_mode=${3:-}
netz_only=false
capture=false
socket_traffic=false
if [[ $bench_mode == --bench ]]; then
  for arg in "${@:4}"; do
    if [[ $arg == --netz-only ]]; then
      if [[ $netz_only == true ]]; then
        echo 'duplicate --netz-only option' >&2
        exit 2
      fi
      netz_only=true
    fi
    if [[ $arg == --capture ]]; then
      if [[ $capture == true ]]; then
        echo 'duplicate --capture option' >&2
        exit 2
      fi
      capture=true
    fi
    if [[ $arg == --socket-traffic ]]; then
      if [[ $socket_traffic == true ]]; then
        echo 'duplicate --socket-traffic option' >&2
        exit 2
      fi
      socket_traffic=true
    fi
  done
fi
netz_root=$(cd "$(dirname "$0")/../.." && pwd)
fixture_dir="$netz_root/tools/interop/quic_go_module"
version=${NETZ_HTTP3_INTEROP_VERSION:-1}
if [[ "$version" != 1 && "$version" != 2 ]]; then
  echo "invalid HTTP/3 QUIC version: $version" >&2
  exit 2
fi
go_version_args=()
netz_version_args=()
if [[ "$version" == 2 ]]; then
  go_version_args=(-v2-only)
  netz_version_args=(--version=2)
fi
if [[ $netz_only != true && ! -f "$fixture_dir/http3_peer/main.go" ]]; then
  echo "repository-owned quic-go HTTP/3 fixture not found under $fixture_dir" >&2
  exit 127
fi
go_bin=${GO_BIN:-}
if [[ -z $go_bin ]]; then
  go_bin=$(command -v go 2>/dev/null || true)
fi
if [[ -z $go_bin && -x /tmp/go/bin/go ]]; then
  go_bin=/tmp/go/bin/go
fi
if [[ $netz_only != true && ( -z $go_bin || ! -x $go_bin ) ]]; then
  echo "go not found; install it to build the quic-go HTTP/3 fixture" >&2
  exit 127
fi

work=$(mktemp -d)
server_pid=
capture_pid=
capture_log=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$capture_pid" ]]; then
    kill -TERM "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    if [[ -n "$server_pid" ]]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      server_pid=
    fi
    if [[ -n "$capture_pid" ]]; then
      kill -TERM "$capture_pid" 2>/dev/null || true
      wait "$capture_pid" 2>/dev/null || true
      capture_pid=
    fi
    while IFS= read -r log_file; do
      echo "===== $log_file =====" >&2
      cat "$log_file" >&2
    done < <(find "$work" -type f \
      \( -name '*.log' -o -name '*.rss' \) -size +0c | sort)
    [[ -z $capture_log || ! -s $capture_log ]] || cat "$capture_log" >&2
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if [[ ${3:-} == --bench ]]; then
  shift 3
  filtered_args=()
  for arg in "$@"; do
    [[ $arg == --netz-only || $arg == --capture ]] ||
      filtered_args+=("$arg")
  done
  set -- "${filtered_args[@]}"
  python3 "$netz_root/tools/interop/http3_benchmark_check_test.py"
  python3 "$netz_root/tools/interop/http3_socket_traffic_check_test.py"
  python3 "$netz_root/tools/interop/http3_packet_capture_test.py"
  python3 "$netz_root/tools/interop/http3_packet_capture_check_test.py"
  python3 "$netz_root/tools/interop/http3_packet_capture_compare_test.py"
  python3 "$netz_root/tools/interop/quic_quic_go_auxiliary_check_test.py"
  free_udp_port() {
    python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
  }
  cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
  mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:3]:
    print(cpu)
PY
  )
  if [[ ${#bench_cpus[@]} -lt 2 ]]; then
    echo 'HTTP/3 comparison requires two available CPUs' >&2
    exit 1
  fi
  client_cpu=${bench_cpus[0]}
  server_cpu=${bench_cpus[1]}
  if [[ $netz_only != true ]]; then
    (cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" test -mod=readonly \
      ./http3_bench ./internal/sockettraffic)
    (cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" build -mod=readonly \
      -o "$work/quic-go-http3-bench" ./http3_bench)
  fi
  requested_modes=(upload download)
  common_args=()
  stats=false
  warmup=10
  iterations=5
  body_bytes=4194304
  streams=1
  chunk_bytes=16384
  stream_window=1048576
  timeout_ms=30000
  netz_max_pacing_rate_bytes_per_second=0
  netz_max_pacing_rate_set=false
  for arg in "$@"; do
    if [[ $arg == --mode=* ]]; then
      requested_modes=("${arg#--mode=}")
    elif [[ $arg == --version=* || $arg == --v2-only ]]; then
      echo 'select benchmark QUIC version with NETZ_HTTP3_INTEROP_VERSION=1|2' >&2
      exit 2
    else
      common_args+=("$arg")
      case "$arg" in
        --stats) stats=true ;;
        --warmup=*) warmup=${arg#--warmup=} ;;
        --iterations=*) iterations=${arg#--iterations=} ;;
        --body-bytes=*) body_bytes=${arg#--body-bytes=} ;;
        --streams=*) streams=${arg#--streams=} ;;
        --chunk-bytes=*) chunk_bytes=${arg#--chunk-bytes=} ;;
        --stream-window=*) stream_window=${arg#--stream-window=} ;;
        --timeout-ms=*) timeout_ms=${arg#--timeout-ms=} ;;
        --netz-max-pacing-rate-bytes-per-second=*)
          if [[ $netz_max_pacing_rate_set == true ]]; then
            echo 'duplicate --netz-max-pacing-rate-bytes-per-second option' >&2
            exit 2
          fi
          netz_max_pacing_rate_bytes_per_second=${arg#--netz-max-pacing-rate-bytes-per-second=}
          if [[ ! $netz_max_pacing_rate_bytes_per_second =~ ^[1-9][0-9]*$ ]]; then
            echo '--netz-max-pacing-rate-bytes-per-second must be positive' >&2
            exit 2
          fi
          netz_max_pacing_rate_set=true
          ;;
      esac
    fi
  done
  if [[ $stats == true && ( $capture == true || $socket_traffic == true ) ]]; then
    echo '--stats, --capture, and --socket-traffic must run separately' >&2
    exit 2
  fi
  if [[ $capture == true && $socket_traffic == true ]]; then
    echo '--capture and --socket-traffic must run separately' >&2
    exit 2
  fi
  capture_cpu=
  capture_artifact_dir=
  capture_python=${HTTP3_CAPTURE_PYTHON:-python3}
  if [[ $capture == true ]]; then
    if [[ $netz_only == true ]]; then
      echo '--capture requires the external quic-go comparison' >&2
      exit 2
    fi
    if [[ ${#bench_cpus[@]} -lt 3 ]]; then
      echo 'HTTP/3 capture requires three available CPUs' >&2
      exit 1
    fi
    capture_cpu=${bench_cpus[2]}
    "$capture_python" \
      "$netz_root/tools/interop/http3_packet_capture.py" --check
    mkdir -p "$netz_root/zig-out/http3-captures"
    capture_artifact_dir=$(mktemp -d \
      "$netz_root/zig-out/http3-captures/run.XXXXXX")
    capture_tool="$capture_artifact_dir/http3_packet_capture.py"
    capture_go_mod="$capture_artifact_dir/quic-go.mod"
    capture_go_sum="$capture_artifact_dir/quic-go.sum"
    cp "$netz_root/tools/interop/http3_packet_capture.py" "$capture_tool"
    cp "$fixture_dir/go.mod" "$capture_go_mod"
    cp "$fixture_dir/go.sum" "$capture_go_sum"
    echo "capture_artifact_dir=$capture_artifact_dir"
  fi
  go_environment=()
  if [[ $capture == true || $socket_traffic == true ]]; then
    go_environment=(env QUIC_GO_DISABLE_GSO=true)
  else
    go_environment=(env -u QUIC_GO_DISABLE_GSO)
  fi
  time_command=()
  rss_source=gnu-time-maxrss
  if [[ -n ${TIME_BIN:-} ]]; then
    if [[ ! -x $TIME_BIN ]]; then
      echo "time executable not found at $TIME_BIN" >&2
      exit 127
    fi
    time_command=("$TIME_BIN")
  elif [[ -x /usr/bin/time ]]; then
    time_command=(/usr/bin/time)
  elif command -v busybox >/dev/null 2>&1; then
    time_command=("$(command -v busybox)" time)
    rss_source=busybox-time-maxrss
  fi
  if [[ $stats == true && ${#time_command[@]} -eq 0 ]]; then
    echo 'GNU or BusyBox time not found' >&2
    exit 127
  fi

  check_samples() {
    local capture_args=()
    if [[ $capture == true ]]; then capture_args+=(--capture); fi
    if [[ $socket_traffic == true ]]; then capture_args+=(--socket-traffic); fi
    python3 "$netz_root/tools/interop/http3_benchmark_check.py" \
      "${capture_args[@]}" "$@"
  }

  check_socket_traffic() {
    if [[ $socket_traffic != true ]]; then return; fi
    local client_binary_sha256 server_binary_sha256
    client_binary_sha256=$(sha256sum "$4" | awk '{print $1}')
    server_binary_sha256=$(sha256sum "$5" | awk '{print $1}')
    python3 "$netz_root/tools/interop/http3_socket_traffic_check.py" \
      --role-pair="$1" --mode="$benchmark_mode" \
      --warmup="$warmup" --iterations="$iterations" \
      --streams="$streams" --body-bytes="$body_bytes" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --netz-max-pacing-rate-bytes-per-second="$netz_max_pacing_rate_bytes_per_second" \
      --quic-version="$version" --client-log="$2" --server-log="$3" \
      --client-binary-sha256="$client_binary_sha256" \
      --server-binary-sha256="$server_binary_sha256"
  }

  check_memory() {
    if [[ $stats != true ]]; then return; fi
    python3 "$netz_root/tools/interop/quic_memory_telemetry_check.py" \
      --protocol=http3 "--rss-source=$rss_source" "$@"
  }

  wait_for_line() {
    local pid=$1 log=$2 prefix=$3
    local value=
    for _ in $(seq 1 600); do
      if [[ -f $log ]]; then
        value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
      fi
      if [[ -n $value ]]; then printf '%s\n' "$value"; return 0; fi
      if ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; return 1; fi
      sleep 0.05
    done
    echo "timed out waiting for $prefix" >&2
    cat "$log" >&2
    return 1
  }

  start_capture() {
    local role_pair=$1 capture_port=$2 client_binary=$3 server_binary=$4
    if [[ $capture != true ]]; then return; fi
    local stem="$benchmark_mode.$role_pair"
    capture_log="$capture_artifact_dir/$stem.log"
    capture_pcap="$capture_artifact_dir/$stem.pcap"
    client_binary_sha256=$(sha256sum "$client_binary" | awk '{print $1}')
    server_binary_sha256=$(sha256sum "$server_binary" | awk '{print $1}')
    quic_go_mod_sha256=$(sha256sum "$capture_go_mod" | awk '{print $1}')
    quic_go_sum_sha256=$(sha256sum "$capture_go_sum" | awk '{print $1}')
    taskset -c "$capture_cpu" "$capture_python" \
      "$capture_tool" \
      --interface=lo --output="$capture_pcap" --server-ip=127.0.0.1 \
      --server-port="$capture_port" --role-pair="$role_pair" \
      --mode="$benchmark_mode" --client-cpu="$client_cpu" \
      --server-cpu="$server_cpu" --capture-cpu="$capture_cpu" \
      --warmup="$warmup" --iterations="$iterations" \
      --streams="$streams" --body-bytes="$body_bytes" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --timeout-ms="$timeout_ms" \
      --quic-version="$version" \
      --client-binary-sha256="$client_binary_sha256" \
      --server-binary-sha256="$server_binary_sha256" \
      --quic-go-mod-sha256="$quic_go_mod_sha256" \
      --quic-go-sum-sha256="$quic_go_sum_sha256" \
      --quic-go-version=0.59.0 \
      >"$capture_log" 2>&1 &
    capture_pid=$!
    wait_for_line "$capture_pid" "$capture_log" CAPTURE_READY >/dev/null
  }

  stop_and_check_capture() {
    local role_pair=$1 capture_port=$2 client_binary=$3 server_binary=$4
    local client_log=$5 server_log=$6
    if [[ $capture != true ]]; then return; fi
    kill -TERM "$capture_pid"
    wait "$capture_pid"
    capture_pid=
    local stem="$benchmark_mode.$role_pair"
    local retained_client_log="$capture_artifact_dir/$stem.client.log"
    local retained_server_log="$capture_artifact_dir/$stem.server.log"
    cp "$client_log" "$retained_client_log"
    cp "$server_log" "$retained_server_log"
    "$capture_python" \
      "$netz_root/tools/interop/http3_packet_capture_check.py" \
      --role-pair="$role_pair" --mode="$benchmark_mode" \
      --iterations="$iterations" --streams="$streams" \
      --body-bytes="$body_bytes" --quic-version="$version" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --netz-max-pacing-rate-bytes-per-second="$netz_max_pacing_rate_bytes_per_second" \
      --timeout-ms="$timeout_ms" \
      --warmup="$warmup" --chunk-bytes="$chunk_bytes" \
      --stream-window="$stream_window" --timeout-ms="$timeout_ms" \
      --server-port="$capture_port" --client-cpu="$client_cpu" \
      --server-cpu="$server_cpu" --capture-cpu="$capture_cpu" \
      --client-binary="$client_binary" --server-binary="$server_binary" \
      --quic-go-mod="$capture_go_mod" \
      --quic-go-sum="$capture_go_sum" \
      --capture-tool="$capture_tool" \
      --client-log="$retained_client_log" \
      --server-log="$retained_server_log" \
      --capture-log="$capture_log" --pcap="$capture_pcap"
    cat "$capture_log"
  }

  compare_captures() {
    if [[ $capture != true ]]; then return; fi
    "$capture_python" \
      "$netz_root/tools/interop/http3_packet_capture_compare.py" \
      --mode="$benchmark_mode" --warmup="$warmup" \
      --iterations="$iterations" --streams="$streams" \
      --body-bytes="$body_bytes" --quic-version="$version" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --timeout-ms="$timeout_ms" \
      --client-cpu="$client_cpu" --server-cpu="$server_cpu" \
      --capture-cpu="$capture_cpu" \
      --netz-client-capture="$capture_artifact_dir/$benchmark_mode.netz-client+quic-go-server.log" \
      --quic-go-client-capture="$capture_artifact_dir/$benchmark_mode.quic-go-client+netz-server.log" \
      --netz-client-pcap="$capture_artifact_dir/$benchmark_mode.netz-client+quic-go-server.pcap" \
      --quic-go-client-pcap="$capture_artifact_dir/$benchmark_mode.quic-go-client+netz-server.pcap" |
      tee "$capture_artifact_dir/$benchmark_mode.comparison.log"
  }

  if [[ $capture == true ]]; then
    echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu,capture:$capture_cpu"
  else
    echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu"
  fi

  for benchmark_mode in "${requested_modes[@]}"; do
    if [[ $benchmark_mode != upload && $benchmark_mode != download ]]; then
      echo "unsupported HTTP/3 benchmark mode: $benchmark_mode" >&2
      exit 1
    fi
    if [[ $benchmark_mode == upload ]]; then
      sender_role=client
    else
      sender_role=server
    fi
    mode_args=("--mode=$benchmark_mode" "${netz_version_args[@]}" "${common_args[@]}")
    if [[ $capture == true ]]; then mode_args+=(--capture); fi
    go_args=("-bench-mode=$benchmark_mode" "${go_version_args[@]}")
    for arg in "${common_args[@]}"; do
      go_args+=("-${arg#--}")
    done
    if [[ $capture == true ]]; then go_args+=(-capture); fi
    pair_dir="$work/$benchmark_mode"
    mkdir -p "$pair_dir"

    if [[ $netz_only == true ]]; then
      port=$(free_udp_port)
      local_mode_args=(--role-pair=netz-client+netz-server "${mode_args[@]}")
      if [[ $stats == true ]]; then
        timeout 180s "${time_command[@]}" -f '%M' \
          -o "$pair_dir/netz-server.rss" taskset -c "$server_cpu" \
          "$server" bench-server "$port" "${local_mode_args[@]}" \
          >"$pair_dir/netz-server.log" 2>&1 &
      else
        timeout 180s taskset -c "$server_cpu" "$server" bench-server \
          "$port" "${local_mode_args[@]}" >"$pair_dir/netz-server.log" 2>&1 &
      fi
      server_pid=$!
      wait_for_line "$server_pid" "$pair_dir/netz-server.log" \
        NETZ_HTTP3_BENCH_PORT >/dev/null
      if [[ $stats == true ]]; then
        timeout 180s "${time_command[@]}" -f '%M' \
          -o "$pair_dir/netz-client.rss" taskset -c "$client_cpu" \
          "$client" bench-client "$port" "$work/netz-ca.pem" \
          "${local_mode_args[@]}" >"$pair_dir/netz-client.log" 2>&1
      else
        timeout 180s taskset -c "$client_cpu" "$client" bench-client \
          "$port" "$work/netz-ca.pem" "${local_mode_args[@]}" \
          >"$pair_dir/netz-client.log" 2>&1
      fi
      wait "$server_pid"
      server_pid=
      check_samples --role-pair=netz-client+netz-server \
        --mode="$benchmark_mode" --iterations="$iterations" \
        --streams="$streams" --body-bytes="$body_bytes" \
        --quic-version="$version" --warmup="$warmup" \
        --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
        --netz-max-pacing-rate-bytes-per-second="$netz_max_pacing_rate_bytes_per_second" \
        --timeout-ms="$timeout_ms" --client-log="$pair_dir/netz-client.log" \
        --server-log="$pair_dir/netz-server.log"
      check_socket_traffic netz-client+netz-server \
        "$pair_dir/netz-client.log" "$pair_dir/netz-server.log" \
        "$client" "$server"
      check_memory --role-pair=netz-client+netz-server \
        --sender="$sender_role" --streams="$streams" \
        --mode="$benchmark_mode" --body-bytes="$body_bytes" \
        --quic-version="$version" --warmup="$warmup" \
        --iterations="$iterations" --client-log="$pair_dir/netz-client.log" \
        --server-log="$pair_dir/netz-server.log" \
        --client-rss="$pair_dir/netz-client.rss" \
        --server-rss="$pair_dir/netz-server.rss"
      cat "$pair_dir/netz-server.log"
      cat "$pair_dir/netz-client.log"
      continue
    fi

    port=$(free_udp_port)
    start_capture netz-client+quic-go-server "$port" \
      "$client" "$work/quic-go-http3-bench"
    if [[ $stats == true ]]; then
      timeout 180s "${time_command[@]}" -f '%M' -o "$pair_dir/quic-go-server.rss" \
        taskset -c "$server_cpu" "${go_environment[@]}" \
        "$work/quic-go-http3-bench" \
        -role=server -addr="127.0.0.1:$port" \
        -ca-out="$pair_dir/quic-go-ca.pem" "${go_args[@]}" \
        >"$pair_dir/quic-go-server.log" 2>&1 &
    else
      timeout 180s "${go_environment[@]}" \
        taskset -c "$server_cpu" "$work/quic-go-http3-bench" \
        -role=server -addr="127.0.0.1:$port" \
        -ca-out="$pair_dir/quic-go-ca.pem" "${go_args[@]}" \
        >"$pair_dir/quic-go-server.log" 2>&1 &
    fi
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/quic-go-server.log" \
      QUIC_GO_HTTP3_BENCH_ADDR >/dev/null
    if [[ $stats == true ]]; then
      timeout 180s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-client.rss" \
        taskset -c "$client_cpu" "$client" bench-client "$port" \
        "$pair_dir/quic-go-ca.pem" "${mode_args[@]}" \
        >"$pair_dir/netz-client.log" 2>&1
    else
      timeout 180s taskset -c "$client_cpu" "$client" \
        bench-client "$port" "$pair_dir/quic-go-ca.pem" \
        "${mode_args[@]}" >"$pair_dir/netz-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    stop_and_check_capture netz-client+quic-go-server "$port" \
      "$client" "$work/quic-go-http3-bench" \
      "$pair_dir/netz-client.log" "$pair_dir/quic-go-server.log"
    check_samples --role-pair=netz-client+quic-go-server \
      --mode="$benchmark_mode" --iterations="$iterations" \
      --streams="$streams" --body-bytes="$body_bytes" --quic-version="$version" \
      --warmup="$warmup" --chunk-bytes="$chunk_bytes" \
      --stream-window="$stream_window" --timeout-ms="$timeout_ms" \
      --netz-max-pacing-rate-bytes-per-second="$netz_max_pacing_rate_bytes_per_second" \
      --client-log="$pair_dir/netz-client.log" \
      --server-log="$pair_dir/quic-go-server.log"
    check_socket_traffic netz-client+quic-go-server \
      "$pair_dir/netz-client.log" "$pair_dir/quic-go-server.log" \
      "$client" "$work/quic-go-http3-bench"
    check_memory --role-pair=netz-client+quic-go-server \
      --sender="$sender_role" \
      --streams="$streams" --mode="$benchmark_mode" --body-bytes="$body_bytes" \
      --quic-version="$version" \
      --warmup="$warmup" --iterations="$iterations" \
      --client-log="$pair_dir/netz-client.log" \
      --server-log="$pair_dir/quic-go-server.log" \
      --client-rss="$pair_dir/netz-client.rss" \
      --server-rss="$pair_dir/quic-go-server.rss"
    cat "$pair_dir/quic-go-server.log"
    cat "$pair_dir/netz-client.log"

    port=$(free_udp_port)
    start_capture quic-go-client+netz-server "$port" \
      "$work/quic-go-http3-bench" "$server"
    if [[ $stats == true ]]; then
      timeout 180s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-server.rss" \
        taskset -c "$server_cpu" "$server" bench-server "$port" \
        "${mode_args[@]}" >"$pair_dir/netz-server.log" 2>&1 &
    else
      timeout 180s taskset -c "$server_cpu" "$server" \
        bench-server "$port" "${mode_args[@]}" \
        >"$pair_dir/netz-server.log" 2>&1 &
    fi
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/netz-server.log" \
      NETZ_HTTP3_BENCH_PORT >/dev/null
    if [[ $stats == true ]]; then
      timeout 180s "${time_command[@]}" -f '%M' -o "$pair_dir/quic-go-client.rss" \
        taskset -c "$client_cpu" "${go_environment[@]}" \
        "$work/quic-go-http3-bench" \
        -role=client -addr="127.0.0.1:$port" -ca="$work/netz-ca.pem" \
        "${go_args[@]}" >"$pair_dir/quic-go-client.log" 2>&1
    else
      timeout 180s "${go_environment[@]}" \
        taskset -c "$client_cpu" "$work/quic-go-http3-bench" \
        -role=client -addr="127.0.0.1:$port" -ca="$work/netz-ca.pem" \
        "${go_args[@]}" >"$pair_dir/quic-go-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    stop_and_check_capture quic-go-client+netz-server "$port" \
      "$work/quic-go-http3-bench" "$server" \
      "$pair_dir/quic-go-client.log" "$pair_dir/netz-server.log"
    check_samples --role-pair=quic-go-client+netz-server \
      --mode="$benchmark_mode" --iterations="$iterations" \
      --streams="$streams" --body-bytes="$body_bytes" --quic-version="$version" \
      --warmup="$warmup" --chunk-bytes="$chunk_bytes" \
      --stream-window="$stream_window" --timeout-ms="$timeout_ms" \
      --netz-max-pacing-rate-bytes-per-second="$netz_max_pacing_rate_bytes_per_second" \
      --client-log="$pair_dir/quic-go-client.log" \
      --server-log="$pair_dir/netz-server.log"
    check_socket_traffic quic-go-client+netz-server \
      "$pair_dir/quic-go-client.log" "$pair_dir/netz-server.log" \
      "$work/quic-go-http3-bench" "$server"
    check_memory --role-pair=quic-go-client+netz-server \
      --sender="$sender_role" \
      --streams="$streams" --mode="$benchmark_mode" --body-bytes="$body_bytes" \
      --quic-version="$version" \
      --warmup="$warmup" --iterations="$iterations" \
      --client-log="$pair_dir/quic-go-client.log" \
      --server-log="$pair_dir/netz-server.log" \
      --client-rss="$pair_dir/quic-go-client.rss" \
      --server-rss="$pair_dir/netz-server.rss"
    cat "$pair_dir/netz-server.log"
    cat "$pair_dir/quic-go-client.log"
    compare_captures
  done
  exit 0
fi

(cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" test -mod=readonly ./...)
(cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" build -mod=readonly \
  -o "$work/quic-go-http3-peer" ./http3_peer)
(cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" build -mod=readonly \
  -o "$work/quic-go-http3-informational-peer" ./http3_informational)

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port=$(free_udp_port)
"$work/quic-go-http3-peer" \
  -mode server -addr "127.0.0.1:$port" -ca-out "$work/quic-go-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-ca.pem" ]] && \
      grep -q 'quic-go HTTP/3 interop server listening=' \
        "$work/quic-go-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/quic-go-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/quic-go-ca.pem" ]] || ! \
    grep -q 'quic-go HTTP/3 interop server listening=' \
      "$work/quic-go-server.log"; then
  echo 'timed out waiting for quic-go HTTP/3 server' >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" "$work/quic-go-ca.pem" \
    "${netz_version_args[@]}" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 concurrent_sibling=true stream_window=8192 read_before_cancel>=12288 large_response=131072 request_body=12 request_trailers=1 response_body=16 response_trailers=1" \
  "$work/netz-client.log"
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED concurrent_sibling=true stream_window=8192 large_response=131072 request_body=12 request_trailers=1 response_body=16 response_trailers=1" \
  "$work/quic-go-server.log"
cat "$work/netz-client.log"
cat "$work/quic-go-server.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

port=$(free_udp_port)
"$server" "$port" "${netz_version_args[@]}" \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/3 quic-go interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/3 quic-go interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz HTTP/3 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-http3-peer" \
    -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
    "${go_version_args[@]}" \
    >"$work/quic-go-client.log" 2>&1; then
  cat "$work/quic-go-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "version=$version cancel=H3_REQUEST_CANCELLED dropped_stop_sending=1 stop_sending_transmissions>=2 concurrent_sibling=true connection_reused=true stream_window=8192 read_before_cancel=12288 large_response=131072 request_body=15 request_trailers=1 response_body=13 response_trailers=1" \
  "$work/quic-go-client.log"
grep -Fq \
  "version=$version origin=true cancel=H3_REQUEST_CANCELLED concurrent_sibling=true connection_reused=true stream_window=8192 read_before_cancel=12288 large_response=131072 request_body=15 request_trailers=1 response_body=13 response_trailers=1" \
  "$work/netz-server.log"
cat "$work/quic-go-client.log"
cat "$work/netz-server.log"

port=$(free_udp_port)
"$work/quic-go-http3-informational-peer" \
  -mode server -addr "127.0.0.1:$port" \
  -ca-out "$work/quic-go-informational-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-informational-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-informational-ca.pem" ]] && \
      grep -q 'quic-go HTTP/3 informational server listening=' \
        "$work/quic-go-informational-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/quic-go-informational-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/quic-go-informational-ca.pem" ]] || ! \
    grep -q 'quic-go HTTP/3 informational server listening=' \
      "$work/quic-go-informational-server.log"; then
  echo 'timed out waiting for quic-go HTTP/3 informational server' >&2
  cat "$work/quic-go-informational-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" \
  "$work/quic-go-informational-ca.pem" --informational \
  "${netz_version_args[@]}" \
  >"$work/netz-informational-client.log" 2>&1; then
  cat "$work/netz-informational-client.log" >&2
  cat "$work/quic-go-informational-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "netz HTTP/3 client observed quic-go informational responses: version=$version statuses=103,102 final=200 body=5" \
  "$work/netz-informational-client.log"
grep -Fq \
  "quic-go HTTP/3 server sent informational responses to netz: version=$version statuses=103,102 final=200 body=5" \
  "$work/quic-go-informational-server.log"
cat "$work/netz-informational-client.log"
cat "$work/quic-go-informational-server.log"

port=$(free_udp_port)
"$server" "$port" --informational "${netz_version_args[@]}" \
  >"$work/netz-informational-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/3 quic-go interop server listening' \
      "$work/netz-informational-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-informational-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/3 quic-go interop server listening' \
    "$work/netz-informational-server.log"; then
  echo 'timed out waiting for netz HTTP/3 informational server' >&2
  cat "$work/netz-informational-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-http3-informational-peer" \
  -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-informational-client.log" 2>&1; then
  cat "$work/quic-go-informational-client.log" >&2
  cat "$work/netz-informational-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "quic-go HTTP/3 client received netz informational responses: version=$version statuses=103,102 final=200 body=5" \
  "$work/quic-go-informational-client.log"
grep -Fq \
  "netz HTTP/3 server sent informational responses to quic-go: version=$version origin=true statuses=103,102 final=200 body=5" \
  "$work/netz-informational-server.log"
cat "$work/quic-go-informational-client.log"
cat "$work/netz-informational-server.log"

if [[ "$version" == 1 ]]; then
  NETZ_HTTP3_INTEROP_VERSION=2 "$0" "$client" "$server"
fi
