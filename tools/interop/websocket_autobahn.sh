#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
image=${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite:latest}

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

"$server" "$port" >"$work/server.log" 2>&1 &
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

cases='["*"]'
if [[ $# -ne 0 ]]; then
  cases=$(printf '%s\n' "$@" | python3 -c \
    'import json, sys; print(json.dumps([line.rstrip("\n") for line in sys.stdin]))')
fi
mkdir -p "$work/reports"
cat >"$work/config.json" <<EOF
{
  "outdir": "/work/reports",
  "options": {"failByDrop": false},
  "servers": [
    {"agent": "netz", "url": "ws://127.0.0.1:$port"}
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

python3 - "$work/reports" <<'PY'
import json
from pathlib import Path
import sys

reports = Path(sys.argv[1])
indexes = sorted(reports.glob("index.json*"))
if not indexes:
    raise SystemExit("Autobahn did not produce an index report")
data = json.loads(indexes[0].read_text())
bad_statuses = {"FAILED", "FAILED BY CLIENT", "WRONG CODE", "UNCLEAN"}
bad = []
total = 0
for agent, cases in data.items():
    for case_id, result in cases.items():
        total += 1
        behavior = result.get("behavior")
        close_behavior = result.get("behaviorClose")
        if behavior in bad_statuses or close_behavior in bad_statuses:
            bad.append((agent, case_id, behavior, close_behavior))
if bad:
    for item in bad:
        print("Autobahn failure: %s %s behavior=%s close=%s" % item, file=sys.stderr)
    raise SystemExit(1)
print(f"Autobahn WebSocket cases passed: {total}")
PY
