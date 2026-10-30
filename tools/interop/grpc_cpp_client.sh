#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz grpc-cpp server executable path}
grpc_root=${GRPC_ROOT:-"$HOME/Work/grpc"}
expected_grpc_commit=03d65cc67c450ccbb58a8a45627c4da83a886ccd
bazel_bin=${BAZEL:-}
bazel_startup_args=()
if [[ -n "${GRPC_BAZEL_OUTPUT_USER_ROOT:-}" ]]; then
  bazel_startup_args+=("--output_user_root=$GRPC_BAZEL_OUTPUT_USER_ROOT")
fi
client=${GRPC_CPP_INTEROP_CLIENT:-}
build_timeout=${GRPC_CPP_BUILD_TIMEOUT:-20m}
case_timeout=${GRPC_CPP_CASE_TIMEOUT:-30s}
slow_consumer_timeout=${GRPC_CPP_SLOW_CONSUMER_TIMEOUT:-90s}
rpc_soak_timeout=${GRPC_CPP_RPC_SOAK_TIMEOUT:-90s}
channel_soak_timeout=${GRPC_CPP_CHANNEL_SOAK_TIMEOUT:-120s}
work=$(mktemp -d)
server_pid=

cleanup_server() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
  fi
}
cleanup() {
  cleanup_server
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    for log in "$work"/*.log; do
      [[ ! -s "$log" ]] || {
        echo "--- $log ---" >&2
        cat "$log" >&2
      }
    done
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if [[ ! -x "$server" ]]; then
  echo "netz gRPC interop server is not executable: $server" >&2
  exit 127
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo 'python3 not found; required to reserve loopback ports' >&2
  exit 127
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo 'timeout not found; required to bound the external gate' >&2
  exit 127
fi

if [[ -z "$client" ]]; then
  if [[ ! -f "$grpc_root/test/cpp/interop/client.cc" ]]; then
    echo "upstream gRPC checkout not found under $grpc_root" >&2
    echo 'set GRPC_ROOT or GRPC_CPP_INTEROP_CLIENT to an existing binary' >&2
    exit 127
  fi
  actual_grpc_commit=$(git -C "$grpc_root" rev-parse HEAD)
  if [[ "$actual_grpc_commit" != "$expected_grpc_commit" ]]; then
    echo "gRPC must be checked out at $expected_grpc_commit (found $actual_grpc_commit)" >&2
    exit 1
  fi
  if [[ -z "$bazel_bin" ]]; then
    if command -v bazelisk >/dev/null 2>&1; then
      bazel_bin=bazelisk
    elif command -v bazel >/dev/null 2>&1; then
      bazel_bin=bazel
    else
      echo 'bazel/bazelisk not found; required to build grpc-cpp interop_client' >&2
      exit 127
    fi
  fi
  required_bazel_version=$(tr -d '[:space:]' <"$grpc_root/.bazelversion")
  actual_bazel_label="$(
    cd "$grpc_root"
    timeout 60s "$bazel_bin" "${bazel_startup_args[@]}" --batch version 2>/dev/null |
      sed -n 's/^Build label: //p' | head -n 1
  )" || {
    echo "failed to query $bazel_bin within 60 seconds" >&2
    exit 1
  }
  # Pixi's official Bazel package identifies an otherwise exact release as
  # `8.7.0- (@non-git)`. Accept only that packaging suffix; keep prerelease or
  # unrelated labels mismatched against the upstream pin.
  actual_bazel_version="$(
    printf '%s\n' "$actual_bazel_label" |
      sed -n -E 's/^([0-9]+\.[0-9]+\.[0-9]+)(- \(@non-git\))?$/\1/p'
  )"
  if [[ "$actual_bazel_version" != "$required_bazel_version" ]]; then
    echo "gRPC requires Bazel $required_bazel_version (found ${actual_bazel_label:-unknown})" >&2
    echo 'set BAZEL to that executable or install Bazelisk' >&2
    exit 1
  fi
  (cd "$grpc_root" && timeout "$build_timeout" "$bazel_bin" "${bazel_startup_args[@]}" build \
    --compilation_mode=opt //test/cpp/interop:interop_client)
  client="$grpc_root/bazel-bin/test/cpp/interop/interop_client"
fi
if [[ ! -x "$client" ]]; then
  echo "grpc-cpp interop client is not executable: $client" >&2
  exit 127
fi
cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

run_case() {
  local scenario=$1
  local transport=$2
  local client_scenario=${3:-$scenario}
  local additional_metadata=${4:-}
  local port server_log client_log
  port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
  )
  server_log="$work/server-$transport-$scenario.log"
  client_log="$work/client-$transport-$scenario.log"

  local server_args=("$port" "$scenario")
  local client_args=(
    --server_host=127.0.0.1
    --server_port="$port"
    --test_case="$client_scenario"
  )
  if [[ -n "$additional_metadata" ]]; then
    client_args+=(--additional_metadata="$additional_metadata")
  fi
  if [[ "$client_scenario" == max_concurrent_streams_connection_scaling ]]; then
    client_args+=(
      '--service_config_json={"connectionScaling":{"maxConnectionsPerSubchannel": 2}}'
    )
  fi
  if [[ "$client_scenario" == orca_per_rpc ]]; then
    # Upstream's registered test policy is selected by the official interop
    # coordinator; invoking the client binary alone otherwise uses pick_first
    # and never installs its per-call backend-metric tracker.
    client_args+=(
      '--service_config_json={"loadBalancingConfig":[{"test_backend_metrics_load_balancer":{}}]}'
    )
  fi
  if [[ "$scenario" == rpc_soak || "$scenario" == channel_soak ]]; then
    client_args+=(
      --soak_iterations=100
      --soak_max_failures=0
      --soak_per_iteration_max_acceptable_latency_ms=5000
      --soak_overall_timeout_seconds=60
      --soak_min_time_ms_between_rpcs=0
      --soak_request_size=271828
      --soak_response_size=314159
    )
  fi
  if [[ "$transport" == tls ]]; then
    server_args+=(--tls)
    client_args+=(
      --use_tls=true
      --use_test_ca=false
      --server_host_override=localhost
    )
    if [[ "$client_scenario" == pick_first_unary ]]; then
      # The upstream pick-first channel helper selects credentials from this
      # flag instead of its ordinary --use_tls branch.
      client_args+=(--custom_credentials_type=ssl)
    fi
  else
    client_args+=(--use_tls=false)
  fi

  "$server" "${server_args[@]}" >"$server_log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -Fq "netz grpc server ready: port=$port scenario=$scenario transport=$transport client_io=grpc-cpp-posix-event-engine server_io=zio-std-io" "$server_log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "netz server exited before readiness for $scenario" >&2
      return 1
    fi
    sleep 0.05
  done
  if ! grep -Fq "netz grpc server ready: port=$port scenario=$scenario transport=$transport client_io=grpc-cpp-posix-event-engine server_io=zio-std-io" "$server_log"; then
    echo "timed out waiting for netz server readiness for $scenario" >&2
    return 1
  fi

  local timeout_value=$case_timeout
  if [[ "$scenario" == slow_consumer ]]; then
    timeout_value=$slow_consumer_timeout
  elif [[ "$scenario" == rpc_soak ]]; then
    timeout_value=$rpc_soak_timeout
  elif [[ "$scenario" == channel_soak ]]; then
    timeout_value=$channel_soak_timeout
  fi
  local client_env=(
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=$work/netz-ca.pem"
  )
  if [[ "$client_scenario" == pick_first_unary ]]; then
    # The case deliberately enables service-config resolution. Keep it fully
    # local and deterministic: EventEngine DNS also issues a TXT query for
    # _grpc_config.127.0.0.1, which can wait on an unrelated host DNS outage.
    # Upstream's native resolver still exercises its pick_first channel and
    # address selection but performs only the numeric-host lookup.
    client_env+=(
      GRPC_EXPERIMENTS=-event_engine_dns
      GRPC_DNS_RESOLVER=native
    )
  fi
  env "${client_env[@]}" \
    timeout "$timeout_value" "$client" "${client_args[@]}" \
    >"$client_log" 2>&1

  # The client process exiting successfully is its assertion result. Require
  # the independent server to have observed the expected terminal condition
  # as well, so a client-only success cannot weaken cancellation/deadline tests.
  for _ in $(seq 1 200); do
    if grep -Fq "netz grpc server completed: scenario=$scenario transport=$transport" "$server_log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
    sleep 0.05
  done
  if ! grep -Fq "netz grpc server completed: scenario=$scenario transport=$transport" "$server_log"; then
    if [[ "$scenario" == timeout_on_sleeping_server ]] &&
       ! grep -Fq "netz grpc server accepted: scenario=$scenario transport=$transport" "$server_log" &&
       kill -0 "$server_pid" 2>/dev/null; then
      # The upstream case uses a hard-coded 1 ms end-to-end deadline. It can
      # therefore succeed with local DEADLINE_EXCEEDED before TCP scheduling
      # (or TLS accept) creates an RPC for the netz server to drain.
      cleanup_server
      echo "grpc-cpp client interoperated with netz: transport=$transport scenario=$scenario outcome=local-deadline-before-server-accept client_io=grpc-cpp-posix-event-engine server_io=zio-std-io"
      return
    fi
    echo "netz server did not complete $scenario" >&2
    return 1
  fi
  grep -Fq \
    'client_io=grpc-cpp-posix-event-engine server_io=zio-std-io' \
    "$server_log"
  wait "$server_pid"
  server_pid=
  echo "grpc-cpp client interoperated with netz: transport=$transport scenario=$scenario client_io=grpc-cpp-posix-event-engine server_io=zio-std-io"
}

for transport in h2c tls; do
  for scenario in \
    empty_unary \
    large_unary \
    orca_per_rpc \
    pick_first_unary \
    max_concurrent_streams_connection_scaling \
    ping_pong \
    half_duplex \
    slow_consumer \
    rpc_soak \
    channel_soak \
    empty_stream \
    cancel_after_begin \
    cancel_after_first_response \
    timeout_on_sleeping_server \
    custom_metadata \
    client_compressed_unary \
    server_compressed_unary \
    client_compressed_streaming \
    server_compressed_streaming \
    status_code_and_message \
    special_status_message \
    unimplemented_method \
    unimplemented_service \
    client_streaming \
    server_streaming
  do
    run_case "$scenario" "$transport"
  done
  run_case \
    authenticated_empty_unary \
    "$transport" \
    empty_unary \
    'authorization:Bearer interop-token'
done

echo 'grpc-cpp client interoperated with netz: transport=h2c+tls unary=empty+large orca=per-rpc pick_first=100-stable-server-id connection_scaling=2-streams+1@2-connections rpc_soak=100x271828/314159 channel_soak=100x271828/314159 ping_pong=true half_duplex=true slow_consumer=2000x1030@20ms empty_stream=true compression=unary+streaming-gzip+identity status=unary+bidi+unicode unimplemented=method+service client_streaming=true server_streaming=true cancel=begin+after-response deadline=DEADLINE_EXCEEDED metadata=unary+bidi auth=bearer certificate=verified alpn=h2 client_io=grpc-cpp-posix-event-engine server_io=zio-std-io'
