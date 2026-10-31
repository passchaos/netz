#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz grpc-cpp client executable path}
pick_first_failover=${2:?netz grpc-cpp pick-first failover executable path}
proxy_client=${3:?netz grpc Hyper proxy client executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
hyper_manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
hyper_proxy="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http-connect-proxy"
grpc_root=${GRPC_ROOT:-"$HOME/Work/grpc"}
expected_grpc_commit=03d65cc67c450ccbb58a8a45627c4da83a886ccd
bazel_bin=${BAZEL:-}
bazel_startup_args=()
if [[ -n "${GRPC_BAZEL_OUTPUT_USER_ROOT:-}" ]]; then
  bazel_startup_args+=("--output_user_root=$GRPC_BAZEL_OUTPUT_USER_ROOT")
fi
server=${GRPC_CPP_INTEROP_SERVER:-}
build_timeout=${GRPC_CPP_BUILD_TIMEOUT:-20m}
case_timeout=${GRPC_CPP_CASE_TIMEOUT:-120s}
work=$(mktemp -d)
server_pid=
client_pid=
proxy_pid=

cleanup() {
  if [[ -n "$client_pid" ]]; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
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

if ! command -v python3 >/dev/null 2>&1; then
  echo 'python3 not found; required to reserve a loopback port' >&2
  exit 127
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo 'timeout not found; required to bound the external gate' >&2
  exit 127
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo 'cargo not found; required to build independent Hyper CONNECT proxy' >&2
  exit 127
fi
if [[ ! -x "$proxy_client" ]]; then
  echo "netz gRPC Hyper proxy client is not executable: $proxy_client" >&2
  exit 127
fi
cargo build --release --offline --locked \
  --manifest-path "$hyper_manifest" \
  --bin netz-hyper-http-connect-proxy

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
    # Bazelisk honors upstream's checked-in .bazelversion. Prefer it over an
    # unrelated host Bazel that may be too new for pinned dependencies.
    if command -v bazelisk >/dev/null 2>&1; then
      bazel_bin=bazelisk
    elif command -v bazel >/dev/null 2>&1; then
      bazel_bin=bazel
    else
      echo 'bazel/bazelisk not found; required to build grpc-cpp interop_server' >&2
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
    --compilation_mode=opt //test/cpp/interop:interop_server)
  server="$grpc_root/bazel-bin/test/cpp/interop/interop_server"
fi
if [[ ! -x "$server" ]]; then
  echo "grpc-cpp interop server is not executable: $server" >&2
  exit 127
fi
if [[ ! -x "$pick_first_failover" ]]; then
  echo "netz pick-first failover client is not executable: $pick_first_failover" >&2
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
  # Abseil may suppress INFO logs in some builds. A successful TCP connect is
  # an equivalent readiness signal and avoids coupling the gate to verbosity.
  if ! python3 - "$port" <<'PY'
import socket
import sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1):
        pass
except OSError:
    raise SystemExit(1)
PY
  then
    echo 'timed out waiting for grpc-cpp interop server readiness' >&2
    exit 1
  fi
fi

timeout "$case_timeout" "$client" "$port" >"$work/client.log" 2>&1
grep -Fq \
  'netz gRPC client interoperated with grpc-cpp: transport=h2c multiplexed_duplex=2+cancel-isolated shared_unary=2+health-gated+keepalive-exact-ack shared_duplex=2+bounded+operation-deadline+async-cancel-reuse shared_admission=rpc+resolution+control-deadline ping_pong=4 half_duplex=4 slow_consumer=2000x1030@20ms compression=unary+streaming-gzip+identity unary=empty+large orca=per-rpc+oob shared_orca=oob-background+fanout rpc_soak=100x271828/314159 channel_soak=100x271828/314159 status=unary+bidi+unicode unimplemented=method+service metadata=initial+trailing-bin cancel=begin+after-response reuse=true connectivity=transition+ready+shutdown deadline=DEADLINE_EXCEEDED-or-local-timeout+CANCEL client_io=zio-std-io server_io=grpc-cpp-posix-event-engine' \
  "$work/client.log"
cat "$work/client.log"

kill -INT "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
ca_file="$grpc_root/src/core/tsi/test_creds/ca.pem"
cert_file="$grpc_root/src/core/tsi/test_creds/server1.pem"
key_file="$grpc_root/src/core/tsi/test_creds/server1.key"
for file in "$ca_file" "$cert_file" "$key_file"; do
  if [[ ! -s "$file" ]]; then
    echo "missing upstream gRPC TLS fixture: $file" >&2
    exit 1
  fi
done

"$server" --port="$port" --use_tls=true \
  --tls_cert_file="$cert_file" --tls_key_file="$key_file" \
  >"$work/server-tls.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -Fq "Server listening on 0.0.0.0:$port" \
      "$work/server-tls.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'grpc-cpp TLS interop server exited before readiness' >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -Fq "Server listening on 0.0.0.0:$port" \
    "$work/server-tls.log"; then
  if ! python3 - "$port" <<'PY'
import socket
import sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1):
        pass
except OSError:
    raise SystemExit(1)
PY
  then
    echo 'timed out waiting for grpc-cpp TLS server readiness' >&2
    exit 1
  fi
fi

timeout "$case_timeout" "$client" "$port" "$ca_file" \
  >"$work/client-tls.log" 2>&1
grep -Fq \
  'netz gRPC client interoperated with grpc-cpp: transport=tls multiplexed_duplex=2+cancel-isolated shared_unary=2+health-gated+keepalive-exact-ack shared_duplex=2+bounded+operation-deadline+async-cancel-reuse shared_admission=rpc+resolution+control-deadline ping_pong=4 half_duplex=4 slow_consumer=2000x1030@20ms compression=unary+streaming-gzip+identity unary=empty+large orca=per-rpc+oob shared_orca=oob-background+fanout rpc_soak=100x271828/314159 channel_soak=100x271828/314159 status=unary+bidi+unicode unimplemented=method+service metadata=initial+trailing-bin cancel=begin+after-response reuse=true connectivity=transition+ready+shutdown deadline=DEADLINE_EXCEEDED-or-local-timeout+CANCEL client_io=zio-std-io server_io=grpc-cpp-posix-event-engine' \
  "$work/client-tls.log"
cat "$work/client-tls.log"

proxy_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
"$hyper_proxy" "$proxy_port" >"$work/hyper-proxy.log" 2>&1 &
proxy_pid=$!
for _ in $(seq 1 200); do
  if grep -Fq 'Hyper CONNECT proxy listening' "$work/hyper-proxy.log"; then
    break
  fi
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    echo 'Hyper CONNECT proxy exited before readiness' >&2
    exit 1
  fi
  sleep 0.05
done
grpc_proxy="http://hyper-proxy@127.0.0.1:$proxy_port" \
https_proxy="http://unused-https-proxy.invalid:8080" \
http_proxy="http://unused-http-proxy.invalid:8080" \
no_grpc_proxy="direct-only.invalid" \
no_proxy="foo.test.google.fr" \
timeout "$case_timeout" "$proxy_client" "$port" "$ca_file" \
  >"$work/proxy-client.log" 2>&1
wait "$proxy_pid"
proxy_pid=
grep -Fq \
  "netz gRPC tunneled grpc-cpp TLS through Hyper CONNECT proxy: rpcs=2 tunnel_authority=localhost:$port tls_identity=foo.test.google.fr certificate_verified=true alpn=h2 proxy_authorization=isolated connection_reused=true client_io=zio-std-io proxy_io=hyper-tokio server_io=grpc-cpp-posix-event-engine" \
  "$work/proxy-client.log"
grep -Fq \
  "Hyper CONNECT proxy tunneled netz TLS HTTP/2: authority=localhost:$port proxy_authorization=true client_io=zio-std-io proxy_io=hyper-tokio" \
  "$work/hyper-proxy.log"
cat "$work/proxy-client.log"
cat "$work/hyper-proxy.log"

kill -INT "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_failover_server() {
  local transport=$1
  local listen_port=$2
  local log=$3
  local args=(--port="$listen_port")
  if [[ "$transport" == tls ]]; then
    args+=(
      --use_tls=true
      --tls_cert_file="$cert_file"
      --tls_key_file="$key_file"
    )
  else
    args+=(--use_tls=false)
  fi
  "$server" "${args[@]}" >"$log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -Fq "Server listening on 0.0.0.0:$listen_port" "$log"; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "grpc-cpp failover server exited before readiness: $transport" >&2
      return 1
    fi
    sleep 0.05
  done
  python3 - "$listen_port" <<'PY'
import socket
import sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1):
    pass
PY
}

run_pick_first_failover() {
  local transport=$1
  local first_port second_port first_log second_log client_log
  first_port=$(free_port)
  second_port=$(free_port)
  while [[ "$second_port" == "$first_port" ]]; do second_port=$(free_port); done
  first_log="$work/failover-$transport-server-a.log"
  second_log="$work/failover-$transport-server-b.log"
  client_log="$work/failover-$transport-client.log"

  start_failover_server "$transport" "$first_port" "$first_log"
  local client_args=("$first_port" "$second_port")
  if [[ "$transport" == tls ]]; then client_args+=("$ca_file"); fi
  timeout "$case_timeout" "$pick_first_failover" "${client_args[@]}" \
    >"$client_log" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 400); do
    if grep -Fq \
        "netz grpc-cpp pick-first phase one complete: transport=$transport endpoint=0" \
        "$client_log"; then
      break
    fi
    if ! kill -0 "$client_pid" 2>/dev/null; then
      echo "netz pick-first client exited before phase one: $transport" >&2
      return 1
    fi
    sleep 0.05
  done
  grep -Fq \
    "netz grpc-cpp pick-first phase one complete: transport=$transport endpoint=0" \
    "$client_log"

  kill -INT "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
  start_failover_server "$transport" "$second_port" "$second_log"

  wait "$client_pid"
  client_pid=
  grep -Fq \
    "netz grpc-cpp pick-first failover complete: transport=$transport endpoint_order=0->1 rpcs=2" \
    "$client_log"
  cat "$client_log"
  kill -INT "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
}

run_pick_first_failover h2c
run_pick_first_failover tls
