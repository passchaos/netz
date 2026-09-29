#!/usr/bin/env bash
set -euo pipefail

netz_server=${1:?netz server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
client_dir="$repo_root/tools/interop/webtransport_chrome"
browser_name=${BROWSER_NAME:-Chrome}
browser_product=${BROWSER_PRODUCT:-chrome}
browser_executable=${BROWSER_EXECUTABLE:-${CHROME:-google-chrome}}
browser_client_io=${BROWSER_CLIENT_IO:-chromium-network-service}
case "$browser_product:$browser_name:$browser_client_io" in
  chrome:Chrome:chromium-network-service)
    browser_ua=Chrome/
    browser_version=Chrome/
    ;;
  firefox:Firefox:firefox-necko)
    browser_ua=Firefox/
    browser_version=firefox/
    ;;
  *)
    echo 'unsupported or inconsistent browser identity' >&2
    exit 2
    ;;
esac
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
    [[ ! -s "$work/rejected-client.log" ]] || cat "$work/rejected-client.log" >&2
    [[ ! -s "$work/rejected-server.log" ]] || cat "$work/rejected-server.log" >&2
    [[ ! -s "$work/client.log" ]] || cat "$work/client.log" >&2
    [[ ! -s "$work/server.log" ]] || cat "$work/server.log" >&2
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

command -v "$browser_executable" >/dev/null || {
  echo "$browser_name is required (override with BROWSER_EXECUTABLE=/path/to/browser)" >&2
  exit 1
}
browser_executable=$(realpath "$(command -v "$browser_executable")")
"$browser_executable" --version >/dev/null 2>&1 || {
  echo "$browser_name executable is not runnable: $browser_executable" >&2
  exit 1
}
browser_launcher_sha256=$(sha256sum "$browser_executable" |
  awk '{print $1}')
[[ $browser_launcher_sha256 =~ ^[0-9a-f]{64}$ ]] || {
  echo "failed to hash $browser_name executable: $browser_executable" >&2
  exit 1
}
[[ -d "$client_dir/node_modules/puppeteer-core" ]] ||
  npm ci --prefix "$client_dir" --ignore-scripts --no-audit --no-fund

read -r rejected_port port origin_port < <(python3 - <<'PY'
import socket
ports = []
open_sockets = []
for sock_type in (socket.SOCK_DGRAM, socket.SOCK_DGRAM, socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.bind(("127.0.0.1", 0))
    ports.append(str(sock.getsockname()[1]))
    open_sockets.append(sock)
for sock in open_sockets:
    sock.close()
print(*ports)
PY
)

# Certificate hashes are only accepted by browsers for short-lived (<=14 day)
# self-signed certificates. Generate one for every run rather than checking in
# an identity whose validity window will inevitably expire. The netz fixture
# accepts the DER leaf plus the raw P-256 scalar so its normal TLS signer still
# performs CertificateVerify.
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
certificate_hash=$(openssl dgst -sha256 -binary "$work/cert.der" | xxd -p -c64)

python3 -m http.server "$origin_port" --bind 127.0.0.1 \
  --directory "$work" >"$work/origin.log" 2>&1 &
origin_pid=$!

# First prove that the browser-generated Origin cannot pass an unrelated exact
# allowlist and that the server returns a normal HTTP 403 rejection.
"$netz_server" "$rejected_port" "$work/cert.der" \
  "$work/private-scalar.bin" "https://denied.example" reject-origin \
  "$browser_client_io" \
  >"$work/rejected-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'WebTransport interop server listening' \
    "$work/rejected-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/rejected-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
grep -q 'WebTransport interop server listening' \
  "$work/rejected-server.log" || {
  echo 'timed out waiting for rejecting netz WebTransport server' >&2
  exit 1
}
BROWSER_NAME="$browser_name" BROWSER_PRODUCT="$browser_product" \
  BROWSER_EXECUTABLE="$browser_executable" \
  WEBTRANSPORT_REJECT_ONLY=1 ORIGIN_PORT="$origin_port" \
  timeout 30s node "$client_dir/client.js" \
  "$rejected_port" "$certificate_hash" >"$work/rejected-client.log" 2>&1
wait "$server_pid"
server_pid=
cat "$work/rejected-client.log"
cat "$work/rejected-server.log"
grep -Fq "$browser_name WebTransport Origin policy passed: rejected=true" \
  "$work/rejected-client.log"
grep -Eq "browser_ua=.*$browser_ua" "$work/rejected-client.log"
grep -Fq "browser_version=$browser_version" "$work/rejected-client.log"
grep -Fq "browser_launcher_sha256=$browser_launcher_sha256" \
  "$work/rejected-client.log"
grep -Eq 'browser_process_sha256=[0-9a-f]{64}' \
  "$work/rejected-client.log"
rejected_browser_version=$(sed -n \
  's/.*browser_version=\([^ ]*\).*/\1/p' "$work/rejected-client.log")
rejected_browser_process_sha256=$(sed -n \
  's/.*browser_process_sha256=\([0-9a-f]*\).*/\1/p' \
  "$work/rejected-client.log")
[[ -n $rejected_browser_version &&
  $rejected_browser_process_sha256 =~ ^[0-9a-f]{64}$ ]] || {
  echo "invalid rejected-session $browser_name identity record" >&2
  exit 1
}
grep -Fq 'netz WebTransport Origin policy passed: rejected=403' \
  "$work/rejected-server.log"
grep -Fq "client_io=$browser_client_io server_io=zio-std-io" \
  "$work/rejected-server.log"

server_args=(
  "$netz_server" "$port" "$work/cert.der" "$work/private-scalar.bin"
  "http://localhost:$origin_port"
)
if [[ ${WEBTRANSPORT_ORIGIN_ONLY:-0} == 1 ]]; then
  server_args+=(origin-only)
else
  server_args+=(full)
fi
server_args+=("$browser_client_io")
"${server_args[@]}" \
  >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'WebTransport interop server listening' "$work/server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.05
done
grep -q 'WebTransport interop server listening' "$work/server.log" || {
  echo 'timed out waiting for netz WebTransport server' >&2
  exit 1
}

if ! BROWSER_NAME="$browser_name" BROWSER_PRODUCT="$browser_product" \
  BROWSER_EXECUTABLE="$browser_executable" ORIGIN_PORT="$origin_port" \
  timeout 30s node "$client_dir/client.js" \
  "$port" "$certificate_hash" >"$work/client.log" 2>&1; then
  sleep 0.2
  exit 1
fi
wait "$server_pid"
server_pid=
cat "$work/client.log"
cat "$work/server.log"
grep -Fq \
  "$(if [[ ${WEBTRANSPORT_ORIGIN_ONLY:-0} == 1 ]]; then
      printf '%s' "$browser_name WebTransport Origin policy passed: exact-origin=true"
    else
      printf '%s' "$browser_name WebTransport interop passed: CONNECT DATAGRAM max_datagram_size="
    fi)" \
  "$work/client.log"
grep -Eq "browser_ua=.*$browser_ua" "$work/client.log"
grep -Fq "browser_version=$browser_version" "$work/client.log"
grep -Fq "browser_launcher_sha256=$browser_launcher_sha256" \
  "$work/client.log"
grep -Eq 'browser_process_sha256=[0-9a-f]{64}' "$work/client.log"
accepted_browser_version=$(sed -n \
  's/.*browser_version=\([^ ]*\).*/\1/p' "$work/client.log")
accepted_browser_process_sha256=$(sed -n \
  's/.*browser_process_sha256=\([0-9a-f]*\).*/\1/p' \
  "$work/client.log")
if [[ $accepted_browser_version != "$rejected_browser_version" ]] ||
  [[ $accepted_browser_process_sha256 != "$rejected_browser_process_sha256" ]]; then
  echo "$browser_name artifact changed between browser phases" >&2
  exit 1
fi
if [[ ${WEBTRANSPORT_ORIGIN_ONLY:-0} == 1 ]]; then
  grep -Fq \
    'netz WebTransport Origin policy passed: exact-origin=true' \
    "$work/server.log"
  grep -Fq "client_io=$browser_client_io server_io=zio-std-io" \
    "$work/server.log"
  exit 0
fi
grep -Fq \
  "$(if [[ $browser_product == firefox ]]; then
      printf '%s' 'bidi uni reset=71 reuse-after-reset=true drain-before-close=true close=77/netz-done'
    else
      printf '%s' 'bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-close=true close=77/netz-done'
    fi)" \
  "$work/client.log"
grep -Fq \
  'netz WebTransport server interop passed: CONNECT DATAGRAM max_datagram_size=' \
  "$work/server.log"
grep -Fq \
  "$(if [[ $browser_product == firefox ]]; then
      printf '%s' 'oversized_rejected=true bidi uni reset=71 reuse-after-reset=true drain-before-close=true close'
    else
      printf '%s' 'oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-close=true close'
    fi)" \
  "$work/server.log"
grep -Fq "client_io=$browser_client_io server_io=zio-std-io" \
  "$work/server.log"
