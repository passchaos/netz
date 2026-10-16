#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
h2spec=${H2SPEC:-h2spec}
if ! command -v "$h2spec" >/dev/null 2>&1 && [[ ! -x "$h2spec" ]]; then
  echo "h2spec not found; install it or set H2SPEC=/absolute/path/to/h2spec" >&2
  exit 127
fi
if command -v "$h2spec" >/dev/null 2>&1; then
  h2spec=$(command -v "$h2spec")
fi
h2spec_version=$("$h2spec" --version)
if [[ "$h2spec_version" != 'Version: 2.6.0 ('*')' ]]; then
  echo "h2spec 2.6.0 required; found: $h2spec_version" >&2
  exit 1
fi

source_root=${H2SPEC_SOURCE_ROOT:-}
go_archive=${H2SPEC_GO_ARCHIVE:-}
locked_source_commit=70ac2294010887f48b18e2d64f5cccd48421fad1
locked_go_archive_sha256=36e720b2d564980c162a48c7e97da2e407dfcc4239e1e58d98082dfa2486a0c1
locked_binary_sha256=e9c8ab68ca035b3acc8c94ef4858a2965a6c021065a050997ce5e65e4440af0a
if [[ -n "$source_root" || -n "$go_archive" ]]; then
  if [[ ! -d "$source_root/.git" || ! -f "$go_archive" ]]; then
    echo "locked h2spec mode requires H2SPEC_SOURCE_ROOT and H2SPEC_GO_ARCHIVE" >&2
    exit 127
  fi
  source_commit=$(git -C "$source_root" rev-parse HEAD)
  if [[ "$source_commit" != "$locked_source_commit" ]]; then
    echo "unexpected h2spec source commit: $source_commit" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]]; then
    echo "h2spec source checkout must be clean" >&2
    exit 1
  fi
  go_archive_sha256=$(sha256sum "$go_archive" | awk '{print $1}')
  if [[ "$go_archive_sha256" != "$locked_go_archive_sha256" ]]; then
    echo "unexpected Go archive SHA-256: $go_archive_sha256" >&2
    exit 1
  fi
  binary_sha256=$(sha256sum "$h2spec" | awk '{print $1}')
  if [[ "$binary_sha256" != "$locked_binary_sha256" ]]; then
    echo "unexpected h2spec binary SHA-256: $binary_sha256" >&2
    exit 1
  fi
  expected_version="Version: 2.6.0 ($locked_source_commit)"
  if [[ "$h2spec_version" != "$expected_version" ]]; then
    echo "unexpected locked h2spec version: $h2spec_version" >&2
    exit 1
  fi
  echo "h2spec locked runtime verified: source=$source_commit go_archive_sha256=$go_archive_sha256 binary_sha256=$binary_sha256"
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
server_transport=h2c
case ${1:-} in
  --tls)
    shift
    server_args+=(--tls)
    h2spec_transport_args+=(--tls --insecure)
    server_transport=tls13
    ;;
  --tls12)
    shift
    server_args+=(--tls12)
    h2spec_transport_args+=(--tls --insecure)
    server_transport=tls12
    ;;
esac

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
grep -Fq 'server_io=zio-std-io' "$work/server.log"
grep -Fq "transport=$server_transport" "$work/server.log"

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
