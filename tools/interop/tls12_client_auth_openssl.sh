#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz client executable path}
mode=${2:-tls12}
case "$mode" in
  tls12)
    tls_label='1.2'
    openssl_tls=(-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256)
    ;;
  tls13)
    tls_label='1.3'
    openssl_tls=(-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256)
    ;;
  *)
    echo "unsupported TLS client-auth mode: $mode" >&2
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

openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -days 1 \
  -subj '/CN=Requested Client Root' \
  -keyout "$work/requested-ca.key" \
  -out "$work/requested-ca.pem" \
  >"$work/ca-generation.log" 2>&1

free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

run_case() {
  local name=$1
  local client_ca=$2
  local expectation=$3
  local port
  port=$(free_port)

  openssl s_server \
    -accept "$port" \
    -cert "$work/cert.pem" \
    -key "$work/key.pem" \
    "${openssl_tls[@]}" \
    -alpn http/1.1 \
    -verify 1 \
    -verify_return_error \
    -CAfile "$client_ca" \
    -state \
    -msg \
    -www \
    -naccept 1 \
    >"$work/openssl-$name.log" 2>&1 &
  server_pid=$!

  for _ in $(seq 1 100); do
    if grep -Fq ACCEPT "$work/openssl-$name.log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      exit 1
    fi
    sleep 0.05
  done
  grep -Fq ACCEPT "$work/openssl-$name.log"

  "$netz_client" "$port" "$work/cert.pem" "$expectation" "$mode" \
    >"$work/netz-$name.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq \
    "netz TLS $tls_label client certificate selection=$expectation server=openssl client_io=zio-std-io status=200" \
    "$work/netz-$name.log"
}

run_case matching "$work/cert.pem" present
run_case unmatched "$work/requested-ca.pem" absent

echo "OpenSSL/netz TLS $tls_label matching/unmatched CertificateRequest selection passed"
