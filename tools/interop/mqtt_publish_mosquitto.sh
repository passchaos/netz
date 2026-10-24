#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz publish client executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
server_pid=
cleanup() {
  local status=$?
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    [[ ! -f "$work/client.log" ]] || cat "$work/client.log" >&2
    [[ ! -f "$work/server.log" ]] || cat "$work/server.log" >&2
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
. "$repo_root/tools/interop/mosquitto_build.sh"
mosquitto=$(resolve_mosquitto)
port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
cat >"$work/mosquitto.conf" <<EOF
listener $port 127.0.0.1
allow_anonymous true
persistence false
EOF
"$mosquitto" -c "$work/mosquitto.conf" >"$work/server.log" 2>&1 &
server_pid=$!
python3 - "$port" <<'PY'
import socket, sys, time
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.1):
            break
    except OSError:
        time.sleep(0.025)
else:
    raise SystemExit("Mosquitto listener did not start")
PY
timeout 30s "$client" "$port" >"$work/client.log" 2>&1
cat "$work/client.log"
grep -Fq 'netz synchronous publish interop passed:' "$work/client.log"
grep -Fq 'split-subscriptions=true reverse-control-completion=true' "$work/client.log"
grep -Fq 'netz durable identifier interop passed: protocols=mqtt311,mqtt5 staged=true mixed-controls=true session-resume=true' "$work/client.log"
