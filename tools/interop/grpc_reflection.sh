#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz reflection server executable path}
grpc_root=${GRPC_ROOT:-"$HOME/Work/grpc"}
expected_grpc_commit=03d65cc67c450ccbb58a8a45627c4da83a886ccd
bazel_bin=${BAZEL:-}
grpc_cli=${GRPC_CLI:-}
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

for command in python3 protoc timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command not found; required by the reflection gate" >&2
    exit 127
  fi
done
if [[ ! -x "$server" ]]; then
  echo "netz reflection server is not executable: $server" >&2
  exit 127
fi

if [[ -z "$grpc_cli" ]]; then
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
      echo 'bazel/bazelisk not found; required to build grpc_cli' >&2
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
    exit 1
  fi
  (cd "$grpc_root" && timeout "$build_timeout" "$bazel_bin" build \
    --compilation_mode=opt //test/cpp/util:grpc_cli)
  grpc_cli="$grpc_root/bazel-bin/test/cpp/util/grpc_cli"
fi
if [[ ! -x "$grpc_cli" ]]; then
  echo "grpc_cli is not executable: $grpc_cli" >&2
  exit 127
fi

cat >"$work/reflection.proto" <<'EOF'
syntax = "proto3";
package demo;
message Request { string value = 1; }
message Response { string value = 1; }
service Echo { rpc Unary(Request) returns (Response); }
EOF
protoc -I "$work" --include_imports \
  --descriptor_set_out="$work/reflection.pb" "$work/reflection.proto"

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

run_case() {
  local name=$1
  shift
  local command=$1
  shift
  local port server_log output
  port=$(free_tcp_port)
  server_log="$work/server-$name.log"
  output="$work/output-$name.log"
  "$server" "$port" "$work/reflection.pb" >"$server_log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -Fq "netz gRPC reflection server ready: port=$port client_io=grpc-cpp-posix-event-engine server_io=zio-std-io" "$server_log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "netz reflection server exited before readiness for $name" >&2
      return 1
    fi
    sleep 0.05
  done
  grep -Fq "netz gRPC reflection server ready: port=$port client_io=grpc-cpp-posix-event-engine server_io=zio-std-io" "$server_log"
  timeout "$case_timeout" "$grpc_cli" "$command" \
    "127.0.0.1:$port" "$@" \
    --channel_creds_type=insecure >"$output" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq \
    'netz gRPC reflection server completed client_io=grpc-cpp-posix-event-engine server_io=zio-std-io' \
    "$server_log"
}

run_case services ls
grep -Fxq 'demo.Echo' "$work/output-services.log"
grep -Fxq 'grpc.reflection.v1.ServerReflection' "$work/output-services.log"
grep -Fxq 'grpc.reflection.v1alpha.ServerReflection' "$work/output-services.log"

run_case service ls demo.Echo
grep -Fxq 'Unary' "$work/output-service.log"

run_case type type demo.Request
grep -Fq 'string value = 1' "$work/output-type.log"

echo 'grpc_cli interoperated with netz reflection: services=true service=true type=true client_io=grpc-cpp-posix-event-engine server_io=zio-std-io'
