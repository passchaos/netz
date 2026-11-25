#!/usr/bin/env bash
set -euo pipefail

netz_server=${1:?netz server executable path}
netz_client=${2:?netz client executable path}
mode=${3:-tls12}
case "$mode" in
  tls12)
    tls_label='1.2'
    openssl_client_tls=(-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256)
    openssl_server_tls=(-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256)
    ;;
  tls13)
    tls_label='1.3'
    openssl_client_tls=(-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256)
    openssl_server_tls=(-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -num_tickets 1)
    ;;
  *)
    echo "unsupported TLS ticket mode: $mode" >&2
    exit 2
    ;;
esac
work=$(mktemp -d)
server_pid=
cleanup() {
  local status=$?
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    for log in "$work"/*.log; do
      [[ -f "$log" ]] || continue
      echo "--- $log ---" >&2
      sed -n '1,200p' "$log" >&2
    done
  fi
  rm -rf "$work"
}
trap cleanup EXIT

if ! command -v openssl >/dev/null 2>&1; then
  echo 'openssl not found' >&2
  exit 1
fi

cat >"$work/cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
cat >"$work/key.pem" <<'EOF'
-----BEGIN EC PRIVATE KEY-----
MDECAQEEIBI0VniavN7xI0VniavN7xI0VniavN7xI0VniavN7xI0oAoGCCqGSM49AwEH
-----END EC PRIVATE KEY-----
EOF

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_log() {
  local log=$1
  local marker=$2
  for _ in $(seq 1 100); do
    if grep -Fq "$marker" "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for server marker: $marker" >&2
  cat "$log" >&2
  return 1
}

run_openssl_client() {
  local port=$1
  local output=$2
  shift 2
  timeout 10s openssl s_client \
    -connect "127.0.0.1:$port" \
    "${openssl_client_tls[@]}" \
    -servername localhost \
    -verify_hostname localhost \
    -CAfile "$work/cert.pem" \
    -alpn http/1.1 \
    -quiet "$@" </dev/null >"$output" 2>&1
  grep -Fq 'ticket-ok' "$output"
}

port=$(free_port)
netz_server_args=("$netz_server" "$port")
if [[ "$mode" == tls13 ]]; then netz_server_args+=(tls13); fi
"${netz_server_args[@]}" >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/netz-server.log" \
  "netz TLS $tls_label ticket server listening server_io=zio-std-io"
run_openssl_client "$port" "$work/openssl-first.log" \
  -sess_out "$work/session.pem"
test -s "$work/session.pem"
run_openssl_client "$port" "$work/openssl-resumed.log" \
  -sess_in "$work/session.pem"
wait "$server_pid"
server_pid=
grep -Fq "netz accepted OpenSSL TLS $tls_label handshake resumed=false" \
  "$work/netz-server.log"
grep -Fq "netz accepted OpenSSL TLS $tls_label handshake resumed=true" \
  "$work/netz-server.log"

port=$(free_port)
# OpenSSL's generated -www status page uses HTTP/1.0. Serve a complete
# HTTP/1.1 response so this TLS ticket gate uses the supported HTTP codec.
printf 'HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nticket-ok' \
  >"$work/ticket-response.http"
(
  cd "$work"
  exec openssl s_server \
  -accept "$port" \
  -cert "$work/cert.pem" \
  -key "$work/key.pem" \
  "${openssl_server_tls[@]}" \
  -alpn http/1.1 \
  -state \
  -msg \
  -HTTP \
  -http_server_binmode \
  -naccept 2
) >"$work/openssl-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/openssl-server.log" ACCEPT
netz_client_args=("$netz_client" "$port" "$work/cert.pem")
if [[ "$mode" == tls13 ]]; then netz_client_args+=(tls13); fi
"${netz_client_args[@]}" >"$work/netz-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq "netz connected to OpenSSL TLS $tls_label server resumed=false status=200" \
  "$work/netz-client.log"
grep -Fq "netz connected to OpenSSL TLS $tls_label server resumed=true status=200" \
  "$work/netz-client.log"

echo "OpenSSL/netz TLS $tls_label session-ticket interop passed in both endpoint roles"
