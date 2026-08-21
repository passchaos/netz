#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
h2spec=${H2SPEC:-h2spec}
if ! command -v "$h2spec" >/dev/null 2>&1 && [[ ! -x "$h2spec" ]]; then
  echo "h2spec not found; install it or set H2SPEC=/absolute/path/to/h2spec" >&2
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
h2spec_transport_args=()
if [[ ${1:-} == "--tls" ]]; then
  shift
  server_args+=(--tls)
  h2spec_transport_args+=(--tls --insecure)
fi

"$server" "${server_args[@]}" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'h2spec server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'h2spec server listening' "$work/server.log"; then
  echo 'timed out waiting for netz h2spec server' >&2
  cat "$work/server.log" >&2
  exit 1
fi

log="$work/h2spec.log"
# Strict mode adds the connection-error GOAWAY check that h2spec otherwise
# skips. Keep it mandatory for the repository gate rather than relying on every
# caller to remember an optional flag.
"$h2spec" --host 127.0.0.1 --port "$port" --timeout 2 --strict \
  "${h2spec_transport_args[@]}" "$@" \
  2>&1 | tee "$log"

# h2spec currently exits successfully when a selector matches no tests. Its
# summary is therefore part of the gate contract: a successful run must execute
# at least one test and may neither skip nor fail one.
python3 - "$log" <<'PY'
import re
from pathlib import Path
import sys

log = Path(sys.argv[1]).read_text(errors="replace")
matches = re.findall(
    r"(?m)^(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed$",
    log.replace("\r", ""),
)
if len(matches) != 1:
    raise SystemExit("h2spec did not produce exactly one parseable summary")
total, passed, skipped, failed = map(int, matches[0])
if total == 0 or passed != total or skipped != 0 or failed != 0:
    raise SystemExit(
        f"h2spec gate rejected totals: total={total} passed={passed} "
        f"skipped={skipped} failed={failed}"
    )
print(f"h2spec strict cases passed: {passed}")
PY
