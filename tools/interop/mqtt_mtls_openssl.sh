#!/usr/bin/env bash
set -euo pipefail

server=${1:?server executable path}
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
openssl req -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -x509 -days 1 \
  -keyout "$work/untrusted-key.pem" \
  -out "$work/untrusted-cert.pem" \
  -subj /CN=untrusted >/dev/null 2>&1
openssl req -newkey rsa:2048 \
  -nodes -x509 -days 1 \
  -keyout "$work/rsa-key.pem" \
  -out "$work/rsa-cert.pem" \
  -subj /CN=rsa-client >/dev/null 2>&1
openssl x509 -in "$work/rsa-cert.pem" -pubkey -noout |
  openssl rsa -pubin -RSAPublicKey_out -outform DER \
    -out "$work/rsa-public.der" 2>/dev/null

# MQTT 5 CONNECT for client ID "openssl-mtls".
mqtt_connect=101900044d5154540502001e00000c6f70656e73736c2d6d746c73

run_server() {
  local mode=$1
  local port=$2
  local log=$3
  shift 3
  "$server" "$mode" "$port" "$@" >"$log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    if grep -q 'MQTT mTLS server listening' "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      return 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for MQTT mTLS server" >&2
  cat "$log" >&2
  return 1
}

run_client() {
  local port=$1
  shift
  printf '%s' "$mqtt_connect" | xxd -r -p |
    timeout 5s openssl s_client \
      -connect "127.0.0.1:$port" \
      -tls1_3 \
      -servername localhost \
      -CAfile "$work/cert.pem" \
      -verify_hostname localhost \
      -quiet "$@" >"$work/client-$port.log" 2>&1 || true
}

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

port=$(free_port)
run_server required "$port" "$work/required.log"
run_client "$port" -cert "$work/cert.pem" -key "$work/key.pem"
wait "$server_pid"
server_pid=
grep -q 'required mTLS authenticated ECDSA peer certificate' "$work/required.log"

port=$(free_port)
run_server required_rsa "$port" "$work/rsa.log" "$work/rsa-public.der"
run_client "$port" -cert "$work/rsa-cert.pem" -key "$work/rsa-key.pem"
wait "$server_pid"
server_pid=
grep -q 'required mTLS authenticated RSA peer certificate' "$work/rsa.log"

port=$(free_port)
run_server required_reject "$port" "$work/reject.log"
run_client "$port"
wait "$server_pid"
server_pid=
grep -q 'required mTLS rejected anonymous client' "$work/reject.log"

port=$(free_port)
run_server required_untrusted "$port" "$work/untrusted.log"
run_client "$port" \
  -cert "$work/untrusted-cert.pem" \
  -key "$work/untrusted-key.pem"
wait "$server_pid"
server_pid=
grep -q 'required mTLS rejected untrusted client' "$work/untrusted.log"

port=$(free_port)
run_server optional_anonymous "$port" "$work/optional.log"
run_client "$port"
wait "$server_pid"
server_pid=
grep -q 'optional mTLS accepted anonymous client' "$work/optional.log"
