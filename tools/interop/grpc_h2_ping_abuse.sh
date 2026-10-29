#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz gRPC server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
peer="$repo_root/tools/hyper_http2_flow/target/release/netz-h2-ping-abuse-client"
work=$(mktemp -d)
server_pid=

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
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

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-h2-ping-abuse-client

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" ping_abuse >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -Fq "netz grpc server ready: port=$port scenario=ping_abuse transport=h2c client_io=rust-h2-tokio server_io=zio-std-io" "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -Fq "netz grpc server ready: port=$port scenario=ping_abuse transport=h2c client_io=rust-h2-tokio server_io=zio-std-io" "$work/server.log"; then
  echo 'timed out waiting for netz gRPC PING abuse server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

timeout 10s "$peer" "$port" >"$work/client.log" 2>&1
wait "$server_pid"
server_pid=

grep -Fq \
  'Rust h2 client observed netz gRPC PING enforcement: transport=h2c acknowledged=3 violating_ack=false goaway=ENHANCE_YOUR_CALM client_io=h2-tokio server_io=zio-std-io' \
  "$work/client.log"
grep -Fq \
  'netz grpc server completed: scenario=ping_abuse transport=h2c pings=4 strikes=3 goaway=ENHANCE_YOUR_CALM debug=too_many_pings client_io=rust-h2-tokio server_io=zio-std-io' \
  "$work/server.log"
cat "$work/client.log"
cat "$work/server.log"
