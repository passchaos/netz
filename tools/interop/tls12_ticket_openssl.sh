#!/usr/bin/env bash
set -euo pipefail

netz_server=${1:?netz server executable path}
netz_client=${2:?netz client executable path}
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
    -tls1_2 \
    -cipher ECDHE-ECDSA-AES128-GCM-SHA256 \
    -servername localhost \
    -verify_hostname localhost \
    -CAfile "$work/cert.pem" \
    -alpn http/1.1 \
    -quiet "$@" </dev/null >"$output" 2>&1
  grep -Fq 'ticket-ok' "$output"
}

port=$(free_port)
"$netz_server" "$port" >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/netz-server.log" \
  'netz TLS 1.2 ticket server listening server_io=zio-std-io'
run_openssl_client "$port" "$work/openssl-first.log" \
  -sess_out "$work/session.pem"
test -s "$work/session.pem"
run_openssl_client "$port" "$work/openssl-resumed.log" \
  -sess_in "$work/session.pem"
wait "$server_pid"
server_pid=
grep -Fq 'netz accepted OpenSSL TLS 1.2 handshake resumed=false' \
  "$work/netz-server.log"
grep -Fq 'netz accepted OpenSSL TLS 1.2 handshake resumed=true' \
  "$work/netz-server.log"

port=$(free_port)
openssl s_server \
  -accept "$port" \
  -cert "$work/cert.pem" \
  -key "$work/key.pem" \
  -tls1_2 \
  -cipher ECDHE-ECDSA-AES128-GCM-SHA256 \
  -alpn http/1.1 \
  -state \
  -msg \
  -www \
  -naccept 2 >"$work/openssl-server.log" 2>&1 &
server_pid=$!
wait_for_log "$work/openssl-server.log" ACCEPT
"$netz_client" "$port" "$work/cert.pem" >"$work/netz-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq 'netz connected to OpenSSL TLS 1.2 server resumed=false status=200' \
  "$work/netz-client.log"
grep -Fq 'netz connected to OpenSSL TLS 1.2 server resumed=true status=200' \
  "$work/netz-client.log"

echo 'OpenSSL/netz TLS 1.2 RFC 5077 interop passed in both endpoint roles'
