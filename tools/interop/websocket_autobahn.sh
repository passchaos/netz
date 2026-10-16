#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
shift
image=${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite:25.10.1@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074}
container_runtime=${AUTOBAHN_CONTAINER_RUNTIME:-docker}
local_wstest=${AUTOBAHN_WSTEST:-}
suite_package=${AUTOBAHN_TESTSUITE_PACKAGE:-}
pypy_archive=${AUTOBAHN_PYPY_ARCHIVE:-}
suite_package_sha256=b57ee6b22de624a03256878ad453c9897d2ad7ee08a4c38b35ee2847637e1383
pypy_archive_sha256=f22a1be607deeaa4f9be6bc63aae09fe4fb5b990d6a23aa4e7c5960dc5d93c96
pypy_executable_sha256=49e7090077ad56808642d5a73a44bd8b293780058c0203e6f90a8f9abed1beba
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
use_tls=false
if [[ ${1:-} == "--tls" ]]; then
  use_tls=true
  shift
fi

local_mode=false
if [[ -n "$local_wstest" ]]; then
  local_mode=true
  if [[ "$local_wstest" != /* || ! -x "$local_wstest" ]]; then
    echo "AUTOBAHN_WSTEST must be an absolute executable path" >&2
    exit 127
  fi
  if [[ ! -f "$suite_package" || ! -f "$pypy_archive" ]]; then
    echo "local Autobahn mode requires AUTOBAHN_TESTSUITE_PACKAGE and AUTOBAHN_PYPY_ARCHIVE" >&2
    exit 127
  fi
  actual_suite_sha256=$(sha256sum "$suite_package" | awk '{print $1}')
  actual_pypy_sha256=$(sha256sum "$pypy_archive" | awk '{print $1}')
  if [[ "$actual_suite_sha256" != "$suite_package_sha256" ]]; then
    echo "unexpected Autobahn Testsuite package SHA-256: $actual_suite_sha256" >&2
    exit 1
  fi
  if [[ "$actual_pypy_sha256" != "$pypy_archive_sha256" ]]; then
    echo "unexpected PyPy archive SHA-256: $actual_pypy_sha256" >&2
    exit 1
  fi
  IFS= read -r interpreter_line <"$local_wstest"
  local_python=${interpreter_line#\#!}
  if [[ "$interpreter_line" != '#!'/* || ! -x "$local_python" ]]; then
    echo "local wstest must name an absolute executable interpreter" >&2
    exit 127
  fi
  actual_pypy_executable_sha256=$(sha256sum "$local_python" | awk '{print $1}')
  if [[ "$actual_pypy_executable_sha256" != "$pypy_executable_sha256" ]]; then
    echo "unexpected PyPy executable SHA-256: $actual_pypy_executable_sha256" >&2
    exit 1
  fi
  local_versions=$(env -u PYTHONPATH "$local_wstest" --autobahnversion 2>&1)
  grep -Fxq 'Autobahn 0.10.9' <<<"$local_versions"
  grep -Fxq 'AutobahnTestSuite 25.10.1' <<<"$local_versions"
  local_python_version=$(env -u PYTHONPATH "$local_python" --version 2>&1)
  grep -Fq 'Python 2.7.18' <<<"$local_python_version"
  grep -Fq 'PyPy 7.3.20' <<<"$local_python_version"
  local_site_root=$(env -u PYTHONPATH "$local_python" -c \
    'import pkg_resources; print(pkg_resources.get_distribution("autobahntestsuite").location)' \
    2>/dev/null)
  python3 "$script_dir/websocket_autobahn_package_check.py" \
    "$suite_package" "$local_site_root/autobahntestsuite"
else
  if ! command -v "$container_runtime" >/dev/null 2>&1; then
    echo "Autobahn container runtime not found: $container_runtime" >&2
    echo "install Docker/Podman, set AUTOBAHN_CONTAINER_RUNTIME, or configure AUTOBAHN_WSTEST" >&2
    exit 127
  fi
  container_runtime=$(command -v "$container_runtime")
  if ! "$container_runtime" image inspect "$image" >/dev/null 2>&1; then
    echo "Autobahn image not found; run: $container_runtime pull $image" >&2
    exit 127
  fi
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

if [[ "$local_mode" == true ]]; then
  env -u PYTHONPATH "$local_python" -m pip freeze 2>/dev/null |
    LC_ALL=C sort >"$work/local-freeze.txt"
  diff -u \
    "$script_dir/websocket_autobahn_local_requirements_25_10_1.txt" \
    "$work/local-freeze.txt"
  local_freeze_sha256=$(sha256sum "$work/local-freeze.txt" | awk '{print $1}')
  echo "Autobahn local runtime verified: testsuite_sha256=$actual_suite_sha256 pypy_archive_sha256=$actual_pypy_sha256 pypy_executable_sha256=$actual_pypy_executable_sha256 freeze_sha256=$local_freeze_sha256"
fi

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
expected_count_args=(
  --expected-cases="$script_dir/websocket_autobahn_cases_25_10_1.json"
)
if [[ $# -eq 0 ]]; then
  expected_count_args+=(--expected-count=517)
else
  cases=$(printf '%s\n' "$@" | python3 -c \
    'import json, sys; print(json.dumps([line.rstrip("\n") for line in sys.stdin]))')
fi
mkdir -p "$work/reports"
report_dir=/work/reports
if [[ "$local_mode" == true ]]; then
  report_dir="$work/reports"
fi
cat >"$work/config.json" <<EOF
{
  "outdir": "$report_dir",
  "options": {"failByDrop": false},
  "servers": [
    {"agent": "netz", "url": "$scheme://localhost:$port"}
  ],
  "cases": $cases,
  "exclude-cases": [],
  "exclude-agent-cases": {}
}
EOF

if [[ "$local_mode" == true ]]; then
  autobahn_command=(
    env -u PYTHONPATH
    "$local_wstest" --mode fuzzingclient --spec "$work/config.json"
  )
else
  autobahn_command=(
    "$container_runtime" run --rm --network host
    -v "$work:/work"
    "$image"
    /opt/pypy/bin/wstest --mode fuzzingclient --spec /work/config.json
  )
fi
"${autobahn_command[@]}" >"$work/autobahn.log" 2>&1 || {
    cat "$work/autobahn.log" >&2
    exit 1
  }

python3 "$script_dir/websocket_autobahn_report_check.py" \
  "$work/reports" --expected-agent=netz "${expected_count_args[@]}"
