#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz raw QUIC benchmark client executable path}
netz_server=${2:?netz raw QUIC benchmark server executable path}
shift 2
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
fixture_dir="$quicz_root/examples/interop/go_echo_client"
repo_root=$(cd "$(dirname "$0")/../.." && pwd)

stats=false
netz_only=false
forwarded_args=()
for arg in "$@"; do
  case $arg in
    --stats) stats=true; forwarded_args+=("$arg") ;;
    --netz-only) netz_only=true ;;
    *) forwarded_args+=("$arg") ;;
  esac
done
set -- "${forwarded_args[@]}"
if [[ $netz_only != true && ! -f "$fixture_dir/go.mod" ]]; then
  echo "audited quic-go fixture not found under $fixture_dir" >&2
  exit 127
fi
if [[ $netz_only != true ]] && ! command -v go >/dev/null 2>&1; then
  echo 'go not found' >&2
  exit 127
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

work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    while IFS= read -r log_file; do
      echo "===== $log_file =====" >&2
      cat "$log_file" >&2
    done < <(find "$work" -type f \
      \( -name '*.log' -o -name '*.rss' \) -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

python3 "$repo_root/tools/interop/quic_quic_go_benchmark_check_test.py"
python3 "$repo_root/tools/interop/quic_quic_go_auxiliary_check_test.py"
if [[ $netz_only != true ]]; then
  (cd "$fixture_dir" && go build \
    -mod=readonly \
    -o "$work/quic-go-raw-bench" \
    "$repo_root/tools/interop/quic_quic_go_bench.go" \
    "$repo_root/tools/interop/quic_quic_go_churn.go")
fi

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_line() {
  local pid=$1 log=$2 prefix=$3
  local value=
  for _ in $(seq 1 600); do
    value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
    if [[ -n $value ]]; then printf '%s\n' "$value"; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; return 1; fi
    sleep 0.05
  done
  echo "timed out waiting for $prefix" >&2
  return 1
}

check_memory() {
  if [[ $stats != true ]]; then return; fi
  python3 "$repo_root/tools/interop/quic_memory_telemetry_check.py" \
    "--rss-source=$rss_source" "$@"
}

mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
)
if [[ ${#bench_cpus[@]} -lt 2 ]]; then
  echo 'raw QUIC comparison requires two available CPUs' >&2
  exit 1
fi
client_cpu=${bench_cpus[0]}
server_cpu=${bench_cpus[1]}

requested_streams=(1 4)
common_args=()
warmup=2
iterations=5
bytes_per_stream=4194304
chunk_bytes=16384
stream_window=1048576
timeout_ms=30000
for arg in "$@"; do
  if [[ $arg == --streams=* ]]; then
    requested_streams=("${arg#--streams=}")
  else
    common_args+=("$arg")
    case $arg in
      --warmup=*) warmup=${arg#--warmup=} ;;
      --iterations=*) iterations=${arg#--iterations=} ;;
      --bytes-per-stream=*) bytes_per_stream=${arg#--bytes-per-stream=} ;;
      --chunk-bytes=*) chunk_bytes=${arg#--chunk-bytes=} ;;
      --stream-window=*) stream_window=${arg#--stream-window=} ;;
      --timeout-ms=*) timeout_ms=${arg#--timeout-ms=} ;;
    esac
  fi
done
go_common=()
for arg in "${common_args[@]}"; do go_common+=("-${arg#--}"); done

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu"
for stream_count in "${requested_streams[@]}"; do
  if [[ $stream_count != 1 && $stream_count != 4 ]]; then
    echo "unsupported stream count: $stream_count" >&2
    exit 1
  fi
  stream_args=("--streams=$stream_count" "${common_args[@]}")
  go_stream_args=("-streams=$stream_count" "${go_common[@]}")
  for sender_role in client server; do
    pair_dir="$work/streams-$stream_count-$sender_role"
    mkdir -p "$pair_dir"

    if [[ $netz_only == true ]]; then
      port=$(free_udp_port)
      if [[ $stats == true ]]; then
        timeout 300s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-server.rss" \
          taskset -c "$server_cpu" "$netz_server" bench-server "$port" \
          --role-pair=netz-client+netz-server "--sender=$sender_role" \
          "${stream_args[@]}" >"$pair_dir/netz-server.log" 2>&1 &
      else
        timeout 300s taskset -c "$server_cpu" "$netz_server" \
          bench-server "$port" --role-pair=netz-client+netz-server \
          "--sender=$sender_role" "${stream_args[@]}" \
          >"$pair_dir/netz-server.log" 2>&1 &
      fi
      server_pid=$!
      wait_for_line "$server_pid" "$pair_dir/netz-server.log" \
        NETZ_QUIC_BENCH_PORT >/dev/null
      if [[ $stats == true ]]; then
        timeout 300s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-client.rss" \
          taskset -c "$client_cpu" "$netz_client" bench-client "$port" \
          "$work/netz-ca.pem" --role-pair=netz-client+netz-server \
          "--sender=$sender_role" "${stream_args[@]}" \
          >"$pair_dir/netz-client.log" 2>&1
      else
        timeout 300s taskset -c "$client_cpu" "$netz_client" \
          bench-client "$port" "$work/netz-ca.pem" \
          --role-pair=netz-client+netz-server "--sender=$sender_role" \
          "${stream_args[@]}" >"$pair_dir/netz-client.log" 2>&1
      fi
      wait "$server_pid"
      server_pid=
      python3 "$repo_root/tools/interop/quic_quic_go_benchmark_check.py" \
        --role-pair=netz-client+netz-server --sender="$sender_role" \
        --warmup="$warmup" --iterations="$iterations" \
        --streams="$stream_count" --bytes-per-stream="$bytes_per_stream" \
        --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
        --timeout-ms="$timeout_ms" \
        --client-log="$pair_dir/netz-client.log" \
        --server-log="$pair_dir/netz-server.log"
      python3 "$repo_root/tools/interop/quic_socket_traffic_check.py" \
        --role-pair=netz-client+netz-server --sender="$sender_role" \
        --streams="$stream_count" --iterations="$iterations" \
        "$pair_dir/netz-server.log" "$pair_dir/netz-client.log"
      check_memory --role-pair=netz-client+netz-server \
        --sender="$sender_role" --streams="$stream_count" \
        --client-log="$pair_dir/netz-client.log" \
        --server-log="$pair_dir/netz-server.log" \
        --client-rss="$pair_dir/netz-client.rss" \
        --server-rss="$pair_dir/netz-server.rss"
      cat "$pair_dir/netz-server.log"
      cat "$pair_dir/netz-client.log"
      continue
    fi

    port=$(free_udp_port)
    if [[ $stats == true ]]; then
      QUIC_GO_DISABLE_GSO=true timeout 300s \
        "${time_command[@]}" -f '%M' -o "$pair_dir/quic-go-server.rss" \
        taskset -c "$server_cpu" "$work/quic-go-raw-bench" \
        -role=server -addr="127.0.0.1:$port" \
        -ca-out="$pair_dir/quic-go-ca.pem" -sender="$sender_role" \
        "${go_stream_args[@]}" >"$pair_dir/quic-go-server.log" 2>&1 &
    else
      QUIC_GO_DISABLE_GSO=true timeout 300s taskset -c "$server_cpu" \
        "$work/quic-go-raw-bench" -role=server \
        -addr="127.0.0.1:$port" -ca-out="$pair_dir/quic-go-ca.pem" \
        -sender="$sender_role" "${go_stream_args[@]}" \
        >"$pair_dir/quic-go-server.log" 2>&1 &
    fi
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/quic-go-server.log" \
      QUIC_GO_RAW_BENCH_ADDR >/dev/null
    if [[ $stats == true ]]; then
      timeout 300s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-client.rss" \
        taskset -c "$client_cpu" "$netz_client" bench-client "$port" \
        "$pair_dir/quic-go-ca.pem" "--sender=$sender_role" \
        "${stream_args[@]}" >"$pair_dir/netz-client.log" 2>&1
    else
      timeout 300s taskset -c "$client_cpu" "$netz_client" \
        bench-client "$port" "$pair_dir/quic-go-ca.pem" \
        "--sender=$sender_role" "${stream_args[@]}" \
        >"$pair_dir/netz-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    python3 "$repo_root/tools/interop/quic_quic_go_benchmark_check.py" \
      --role-pair=netz-client+quic-go-server --sender="$sender_role" \
      --warmup="$warmup" --iterations="$iterations" \
      --streams="$stream_count" --bytes-per-stream="$bytes_per_stream" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --timeout-ms="$timeout_ms" \
      --client-log="$pair_dir/netz-client.log" \
      --server-log="$pair_dir/quic-go-server.log"
    python3 "$repo_root/tools/interop/quic_socket_traffic_check.py" \
      --role-pair=netz-client+quic-go-server --sender="$sender_role" \
      --streams="$stream_count" --iterations="$iterations" \
      "$pair_dir/quic-go-server.log" "$pair_dir/netz-client.log"
    check_memory --role-pair=netz-client+quic-go-server \
      --sender="$sender_role" --streams="$stream_count" \
      --client-log="$pair_dir/netz-client.log" \
      --server-log="$pair_dir/quic-go-server.log" \
      --client-rss="$pair_dir/netz-client.rss" \
      --server-rss="$pair_dir/quic-go-server.rss"
    cat "$pair_dir/quic-go-server.log"
    cat "$pair_dir/netz-client.log"

    port=$(free_udp_port)
    if [[ $stats == true ]]; then
      timeout 300s "${time_command[@]}" -f '%M' -o "$pair_dir/netz-server.rss" \
        taskset -c "$server_cpu" "$netz_server" bench-server "$port" \
        "--sender=$sender_role" "${stream_args[@]}" \
        >"$pair_dir/netz-server.log" 2>&1 &
    else
      timeout 300s taskset -c "$server_cpu" "$netz_server" \
        bench-server "$port" "--sender=$sender_role" \
        "${stream_args[@]}" >"$pair_dir/netz-server.log" 2>&1 &
    fi
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/netz-server.log" \
      NETZ_QUIC_BENCH_PORT >/dev/null
    if [[ $stats == true ]]; then
      QUIC_GO_DISABLE_GSO=true timeout 300s \
        "${time_command[@]}" -f '%M' -o "$pair_dir/quic-go-client.rss" \
        taskset -c "$client_cpu" "$work/quic-go-raw-bench" \
        -role=client -addr="127.0.0.1:$port" -ca="$work/netz-ca.pem" \
        -sender="$sender_role" "${go_stream_args[@]}" \
        >"$pair_dir/quic-go-client.log" 2>&1
    else
      QUIC_GO_DISABLE_GSO=true timeout 300s taskset -c "$client_cpu" \
        "$work/quic-go-raw-bench" -role=client \
        -addr="127.0.0.1:$port" -ca="$work/netz-ca.pem" \
        -sender="$sender_role" "${go_stream_args[@]}" \
        >"$pair_dir/quic-go-client.log" 2>&1
    fi
    wait "$server_pid"
    server_pid=
    python3 "$repo_root/tools/interop/quic_quic_go_benchmark_check.py" \
      --role-pair=quic-go-client+netz-server --sender="$sender_role" \
      --warmup="$warmup" --iterations="$iterations" \
      --streams="$stream_count" --bytes-per-stream="$bytes_per_stream" \
      --chunk-bytes="$chunk_bytes" --stream-window="$stream_window" \
      --timeout-ms="$timeout_ms" \
      --client-log="$pair_dir/quic-go-client.log" \
      --server-log="$pair_dir/netz-server.log"
    python3 "$repo_root/tools/interop/quic_socket_traffic_check.py" \
      --role-pair=quic-go-client+netz-server --sender="$sender_role" \
      --streams="$stream_count" --iterations="$iterations" \
      "$pair_dir/netz-server.log" "$pair_dir/quic-go-client.log"
    check_memory --role-pair=quic-go-client+netz-server \
      --sender="$sender_role" --streams="$stream_count" \
      --client-log="$pair_dir/quic-go-client.log" \
      --server-log="$pair_dir/netz-server.log" \
      --client-rss="$pair_dir/quic-go-client.rss" \
      --server-rss="$pair_dir/netz-server.rss"
    cat "$pair_dir/netz-server.log"
    cat "$pair_dir/quic-go-client.log"
  done
done
