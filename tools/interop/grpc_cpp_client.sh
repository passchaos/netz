#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz grpc-cpp server executable path}
grpc_root=${GRPC_ROOT:-"$HOME/Work/grpc"}
expected_grpc_commit=03d65cc67c450ccbb58a8a45627c4da83a886ccd
bazel_bin=${BAZEL:-}
client=${GRPC_CPP_INTEROP_CLIENT:-}
build_timeout=${GRPC_CPP_BUILD_TIMEOUT:-20m}
case_timeout=${GRPC_CPP_CASE_TIMEOUT:-30s}
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
  actual_bazel_version="$(
    cd "$grpc_root"
    timeout 60s "$bazel_bin" --batch version 2>/dev/null |
      sed -n 's/^Build label: //p' | head -n 1
  )" || {
    echo "failed to query $bazel_bin within 60 seconds" >&2
    exit 1
  }
  if [[ "$actual_bazel_version" != "$required_bazel_version" ]]; then
    echo "gRPC requires Bazel $required_bazel_version (found ${actual_bazel_version:-unknown})" >&2
    echo 'set BAZEL to that executable or install Bazelisk' >&2
    exit 1
  fi
  (cd "$grpc_root" && timeout "$build_timeout" "$bazel_bin" build \
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
    --test_case="$scenario"
  )
  if [[ "$transport" == tls ]]; then
    server_args+=(--tls)
    client_args+=(
      --use_tls=true
      --use_test_ca=false
      --server_host_override=localhost
    )
  else
    client_args+=(--use_tls=false)
  fi

  "$server" "${server_args[@]}" >"$server_log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -Fq "netz grpc server ready: port=$port scenario=$scenario transport=$transport" "$server_log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "netz server exited before readiness for $scenario" >&2
      return 1
    fi
    sleep 0.05
  done
  if ! grep -Fq "netz grpc server ready: port=$port scenario=$scenario transport=$transport" "$server_log"; then
    echo "timed out waiting for netz server readiness for $scenario" >&2
    return 1
  fi

  GRPC_DEFAULT_SSL_ROOTS_FILE_PATH="$work/netz-ca.pem" \
    timeout "$case_timeout" "$client" "${client_args[@]}" \
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
    if [[ "$transport" == tls &&
          "$scenario" == timeout_on_sleeping_server ]] &&
       ! grep -Fq "netz grpc server accepted: scenario=$scenario transport=$transport" "$server_log" &&
       kill -0 "$server_pid" 2>/dev/null; then
      # The upstream case uses a hard-coded 1 ms end-to-end deadline. It can
      # therefore succeed with local DEADLINE_EXCEEDED before TLS accept
      # finishes and before an RPC exists for the netz server to drain.
      cleanup_server
      echo "grpc-cpp client interoperated with netz: transport=$transport scenario=$scenario outcome=local-deadline-before-tls-accept"
      return
    fi
    echo "netz server did not complete $scenario" >&2
    return 1
  fi
  wait "$server_pid"
  server_pid=
  echo "grpc-cpp client interoperated with netz: transport=$transport scenario=$scenario"
}

for transport in h2c tls; do
  for scenario in \
    ping_pong \
    empty_stream \
    cancel_after_first_response \
    timeout_on_sleeping_server \
    custom_metadata \
    client_streaming \
    server_streaming
  do
    run_case "$scenario" "$transport"
  done
done

echo 'grpc-cpp client interoperated with netz: transport=h2c+tls ping_pong=true empty_stream=true client_streaming=true server_streaming=true cancel=CANCEL deadline=DEADLINE_EXCEEDED metadata=unary+bidi certificate=verified alpn=h2'
