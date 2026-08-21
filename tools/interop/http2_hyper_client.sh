#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz client executable path}
server=${2:?netz server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
server_binary="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-interop-server"
hyper_client_binary="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-http2-interop-client"
work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-http2-interop-server \
  --bin netz-hyper-http2-interop-client

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server_binary" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Hyper HTTP/2 interop server listening' "$work/server.log" \
      2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'Hyper HTTP/2 interop server listening' "$work/server.log" \
    2>/dev/null; then
  echo 'timed out waiting for Hyper HTTP/2 server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

if ! timeout 10s "$client" "$port" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/netz-client.log"
grep -Fq \
  'netz HTTP/2 client canceled flow-blocked Hyper stream and completed concurrent sibling: rst=CANCEL window=8192 received=8192 sibling=16384' \
  "$work/netz-client.log"
echo 'Hyper HTTP/2 server -> netz client interop passed'

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

"$server" "$port" >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz HTTP/2 Hyper interop server listening' \
      "$work/netz-server.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz HTTP/2 Hyper interop server listening' \
    "$work/netz-server.log" 2>/dev/null; then
  echo 'timed out waiting for netz HTTP/2 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi

if ! timeout 10s "$hyper_client_binary" "$port" \
    >"$work/hyper-client.log" 2>&1; then
  cat "$work/hyper-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
cat "$work/hyper-client.log"
wait "$server_pid"
server_pid=
grep -Fq \
  'Hyper HTTP/2 client interoperated with netz: status=201 body=13 trailers=1' \
  "$work/hyper-client.log"
grep -Fq \
  'Hyper HTTP/2 client canceled flow-blocked netz stream and completed concurrent sibling: rst=CANCEL window=8192 received=8192 sibling=16384' \
  "$work/hyper-client.log"
grep -Fq \
  'method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1' \
  "$work/netz-server.log"
grep -Fq \
  'netz HTTP/2 server observed flow-blocked Hyper cancellation and completed concurrent sibling: rst=CANCEL window=8192 offered=131072 sibling=16384' \
  "$work/netz-server.log"
echo 'Hyper HTTP/2 client -> netz server interop passed'
