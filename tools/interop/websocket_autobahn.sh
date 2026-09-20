#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
image=${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074}
use_tls=false
if [[ ${1:-} == "--tls" ]]; then
  use_tls=true
  shift
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found; install it or run the Autobahn container manually" >&2
  exit 127
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "Autobahn image not found; run: docker pull $image" >&2
  exit 127
fi

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

port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

server_args=("$port")
scheme=ws
if [[ $use_tls == true ]]; then
  server_args+=(--tls)
  scheme=wss
fi
"$server" "${server_args[@]}" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Autobahn WebSocket server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'Autobahn WebSocket server listening' "$work/server.log"; then
  echo 'timed out waiting for netz Autobahn server' >&2
  cat "$work/server.log" >&2
  exit 1
fi
grep -Fq \
  'workers=64 server_io=zio-std-io' \
  "$work/server.log"

cases='["*"]'
expected_count_args=(--expected-count=517)
if [[ $# -ne 0 ]]; then
  cases=$(printf '%s\n' "$@" | python3 -c \
    'import json, sys; print(json.dumps([line.rstrip("\n") for line in sys.stdin]))')
  expected_count_args=()
fi
mkdir -p "$work/reports"
cat >"$work/config.json" <<EOF
{
  "outdir": "/work/reports",
  "options": {"failByDrop": false},
  "servers": [
    {"agent": "netz", "url": "$scheme://localhost:$port"}
  ],
  "cases": $cases,
  "exclude-cases": [],
  "exclude-agent-cases": {}
}
EOF

docker run --rm --network host \
  -v "$work:/work" \
  "$image" \
  /opt/pypy/bin/wstest --mode fuzzingclient --spec /work/config.json \
  >"$work/autobahn.log" 2>&1 || {
    cat "$work/autobahn.log" >&2
    exit 1
  }

python3 "$(dirname "$0")/websocket_autobahn_report_check.py" \
  "$work/reports" --expected-agent=netz "${expected_count_args[@]}"
