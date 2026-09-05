#!/usr/bin/env bash
set -euo pipefail

netz_server=${1:?netz server executable path}
shift
use_tls=false
if [[ ${1:-} == "--tls" ]]; then
  use_tls=true
  shift
fi
[[ $# -eq 0 ]] || {
  echo 'usage: websocket_chrome.sh SERVER [--tls]' >&2
  exit 1
}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
client_dir="$repo_root/tools/interop/webtransport_chrome"
client_js="$repo_root/tools/interop/websocket_chrome/client.js"
work=$(mktemp -d)
server_pid=
origin_pid=
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$origin_pid" ]]; then
    kill "$origin_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    [[ ! -s "$work/client.log" ]] || cat "$work/client.log" >&2
    [[ ! -s "$work/server.log" ]] || cat "$work/server.log" >&2
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

command -v "${CHROME:-google-chrome}" >/dev/null || {
  echo 'Google Chrome is required (override with CHROME=/path/to/chrome)' >&2
  exit 1
}
[[ -d "$client_dir/node_modules/puppeteer-core" ]] ||
  npm ci --prefix "$client_dir" --ignore-scripts --no-audit --no-fund

read -r port origin_port < <(python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(str(sock.getsockname()[1]))
    sock.close()
print(*ports)
PY
)
origin="http://localhost:$origin_port"
python3 -m http.server "$origin_port" --bind 127.0.0.1 \
  --directory "$work" >"$work/origin.log" 2>&1 &
origin_pid=$!
scheme=ws
server_args=("$port" "$origin")
chrome_env=()
if [[ $use_tls == true ]]; then
  scheme=wss
  openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem"
  openssl req -new -x509 -key "$work/key.pem" -out "$work/cert.pem" \
    -days 13 -sha256 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth'
  openssl x509 -in "$work/cert.pem" -outform der -out "$work/cert.der"
  openssl ec -in "$work/key.pem" -text -noout 2>/dev/null |
    awk '/priv:/{capture=1;next}/pub:/{capture=0} capture {gsub(/[: ]/,""); printf "%s",$0}' |
    xxd -r -p >"$work/private-scalar.bin"
  [[ $(wc -c <"$work/private-scalar.bin") -eq 32 ]] || {
    echo 'failed to extract a P-256 private scalar' >&2
    exit 1
  }
  spki_hash=$(openssl x509 -in "$work/cert.pem" -pubkey -noout |
    openssl pkey -pubin -outform der |
    openssl dgst -sha256 -binary | base64 -w0)
  server_args+=("$work/cert.der" "$work/private-scalar.bin")
  chrome_env=(CERTIFICATE_SPKI_SHA256="$spki_hash")
fi
"$netz_server" "${server_args[@]}" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'Chrome WebSocket server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
grep -q 'Chrome WebSocket server listening' "$work/server.log" || {
  echo 'timed out waiting for netz Chrome WebSocket server' >&2
  exit 1
}

env NODE_PATH="$client_dir/node_modules" ORIGIN_PORT="$origin_port" \
  "${chrome_env[@]}" timeout 30s node "$client_js" "$port" "$scheme" \
  >"$work/client.log" 2>&1
wait "$server_pid"
server_pid=
cat "$work/client.log"
cat "$work/server.log"
grep -Fq \
  "Chrome WebSocket interop passed: scheme=$scheme rejected-origin accepted-origin subprotocol compressed-text binary automatic-pong close=1001/netz-browser-done" \
  "$work/client.log"
grep -Fq \
  "netz Chrome WebSocket interop passed: scheme=$scheme rejected-origin accepted-origin subprotocol compressed-text binary ping-pong close=1001/netz-browser-done" \
  "$work/server.log"
