#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz grpc-cpp client executable path}
grpc_root=${GRPC_ROOT:-"$HOME/Work/grpc"}
expected_grpc_commit=03d65cc67c450ccbb58a8a45627c4da83a886ccd
bazel_bin=${BAZEL:-}
server=${GRPC_CPP_INTEROP_SERVER:-}
work=$(mktemp -d)
server_pid=

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill -INT "$server_pid" 2>/dev/null || true
    # The upstream loop checks SIGINT at five-second intervals. Avoid leaving
    # the build gate stuck if it is already unhealthy.
    for _ in $(seq 1 60); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      kill "$server_pid" 2>/dev/null || true
    fi
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    for log in "$work"/*.log; do
      [[ ! -s "$log" ]] || cat "$log" >&2
    done
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if [[ -z "$server" ]]; then
  if [[ ! -f "$grpc_root/test/cpp/interop/interop_server.cc" ]]; then
    echo "upstream gRPC checkout not found under $grpc_root" >&2
    echo 'set GRPC_ROOT or GRPC_CPP_INTEROP_SERVER to an existing binary' >&2
    exit 127
  fi
  actual_grpc_commit=$(git -C "$grpc_root" rev-parse HEAD)
  if [[ "$actual_grpc_commit" != "$expected_grpc_commit" ]]; then
    echo "gRPC must be checked out at $expected_grpc_commit (found $actual_grpc_commit)" >&2
    exit 1
  fi
  if [[ -z "$bazel_bin" ]]; then
    if command -v bazel >/dev/null 2>&1; then
      bazel_bin=bazel
    elif command -v bazelisk >/dev/null 2>&1; then
      bazel_bin=bazelisk
    else
      echo 'bazel/bazelisk not found; required to build grpc-cpp interop_server' >&2
      exit 127
    fi
  fi
  (cd "$grpc_root" && "$bazel_bin" build \
    --compilation_mode=opt //test/cpp/interop:interop_server)
  server="$grpc_root/bazel-bin/test/cpp/interop/interop_server"
fi
if [[ ! -x "$server" ]]; then
  echo "grpc-cpp interop server is not executable: $server" >&2
  exit 127
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo 'python3 not found; required to reserve a loopback port' >&2
  exit 127
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo 'timeout not found; required to bound the external gate' >&2
  exit 127
fi

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" --port="$port" --use_tls=false \
  >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -Fq "Server listening on 0.0.0.0:$port" "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'grpc-cpp interop server exited before readiness' >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -Fq "Server listening on 0.0.0.0:$port" "$work/server.log"; then
  echo 'timed out waiting for grpc-cpp interop server readiness' >&2
  exit 1
fi

timeout 30s "$client" "$port" >"$work/client.log" 2>&1
grep -Fq \
  'netz gRPC client interoperated with grpc-cpp: transport=h2c ping_pong=4 metadata=initial+trailing-bin cancel=CANCEL reuse=true deadline=DEADLINE_EXCEEDED' \
  "$work/client.log"
cat "$work/client.log"
