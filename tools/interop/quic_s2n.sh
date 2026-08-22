#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz client executable path}
netz_server=${2:?netz server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
s2n_root="$repo_root/../../Work/s2n-quic"
fixture_manifest="$repo_root/tools/interop/quic_s2n/Cargo.toml"
expected_s2n_commit=254767581b3b47f53ceb88206b09aa6066e0f7f5

if [[ ! -f "$s2n_root/quic/s2n-quic/Cargo.toml" ]]; then
  echo "s2n-quic checkout not found under $s2n_root" >&2
  exit 127
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo 'cargo not found; install it to build the s2n-quic interop fixture' >&2
  exit 127
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo 'openssl not found; install it to create the test identity' >&2
  exit 127
fi
actual_s2n_commit=$(git -C "$s2n_root" rev-parse HEAD)
if [[ "$actual_s2n_commit" != "$expected_s2n_commit" ]]; then
  echo "s2n-quic must be checked out at $expected_s2n_commit (found $actual_s2n_commit)" >&2
  exit 1
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
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    for log in "$work"/*.log; do
      [[ ! -s "$log" ]] || cat "$log" >&2
    done
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

# Generate a fresh CA and server leaf. The netz client loads only the CA and
# verifies the leaf's localhost SAN, so success cannot come from an insecure
# verifier or from treating the serving certificate itself as trusted.
openssl ecparam -name prime256v1 -genkey -noout -out "$work/s2n-ca-key.pem"
openssl req -new -x509 -key "$work/s2n-ca-key.pem" \
  -out "$work/s2n-ca.pem" -days 1 -sha256 -subj '/CN=netz s2n interop CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl ecparam -name prime256v1 -genkey -noout -out "$work/s2n-key.pem"
openssl req -new -key "$work/s2n-key.pem" -out "$work/s2n.csr" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
cat >"$work/s2n-leaf.ext" <<'EOF'
subjectAltName=DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$work/s2n.csr" -CA "$work/s2n-ca.pem" \
  -CAkey "$work/s2n-ca-key.pem" -CAcreateserial \
  -out "$work/s2n-cert.pem" -days 1 -sha256 \
  -extfile "$work/s2n-leaf.ext"

cargo build --quiet --release --locked --manifest-path "$fixture_manifest"
s2n_peer="$repo_root/tools/interop/quic_s2n/target/release/netz-quic-s2n-interop"

run_netz_client_case() {
  local scenario=$1
  local client_result=$2
  local server_result=$3
  local port
  port=$(free_udp_port)
  local server_log="$work/s2n-server-$scenario.log"
  local client_log="$work/netz-client-$scenario.log"

  "$s2n_peer" server "$port" "$work/s2n-cert.pem" \
    "$work/s2n-key.pem" "$scenario" >"$server_log" 2>&1 &
  server_pid=$!
  : >"$client_log"
  for _ in $(seq 1 200); do
    grep -q 's2n-quic interop server listening=' "$server_log" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  grep -q 's2n-quic interop server listening=' "$server_log" || {
    echo 'timed out waiting for s2n-quic server' >&2
    return 1
  }
  timeout 20s "$netz_client" "$port" "$work/s2n-ca.pem" \
    --peer=s2n-quic "--scenario=$scenario" >"$client_log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "$client_result" "$client_log"
  grep -Fq "$server_result" "$server_log"
  cat "$client_log"
  cat "$server_log"
}

run_netz_client_case echo \
  'netz QUIC client interoperated with s2n-quic: verified=true version=1 retry=false alpn=hq-interop streams=2 bytes=10 peer_close=57' \
  's2n-quic server interoperated with netz: version=1 alpn=hq-interop sni=localhost streams=2 bytes=10 peer_close=57'
run_netz_client_case reset \
  'netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=57' \
  's2n-quic server interoperated with netz: version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=57'
run_netz_client_case stop \
  'netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 concurrent_sibling=4 echo_bytes=5 peer_close=57' \
  's2n-quic server interoperated with netz: version=1 alpn=hq-interop stop_error=42 reset_error=42 concurrent_sibling=4 echo_bytes=5 peer_close=57'
run_netz_client_case flow \
  'netz QUIC client interoperated with s2n-quic: verified=true version=1 alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 flow_blocked=true stream_bytes=12288 echo_bytes=12288 peer_close=57' \
  's2n-quic server interoperated with netz: version=1 alpn=hq-interop initial_max_data=8192 initial_max_stream_data=2048 stream_bytes=12288 echo_bytes=12288 peer_close=57'

port=$(free_udp_port)
"$s2n_peer" server "$port" "$work/s2n-cert.pem" \
  "$work/s2n-key.pem" retry >"$work/s2n-server-retry.log" 2>&1 &
server_pid=$!
: >"$work/netz-client-retry.log"
for _ in $(seq 1 200); do
  grep -q 's2n-quic interop server listening=' \
    "$work/s2n-server-retry.log" && break
  if ! kill -0 "$server_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.05
done
grep -q 's2n-quic interop server listening=' \
  "$work/s2n-server-retry.log" || {
  echo 'timed out waiting for s2n-quic Retry server' >&2
  exit 1
}
timeout 20s "$netz_client" "$port" "$work/s2n-ca.pem" \
  --peer=s2n-quic --expect-retry >"$work/netz-client-retry.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq \
  'netz QUIC client interoperated with s2n-quic: verified=true version=1 retry=true alpn=hq-interop streams=2 bytes=10 peer_close=57' \
  "$work/netz-client-retry.log"
grep -Fq \
  's2n-quic server interoperated with netz: version=1 retry=true alpn=hq-interop sni=localhost streams=2 bytes=10 peer_close=57' \
  "$work/s2n-server-retry.log"
cat "$work/netz-client-retry.log"
cat "$work/s2n-server-retry.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

run_s2n_client_case() {
  local scenario=$1
  local server_mode=$2
  local client_result=$3
  local server_result=$4
  local port
  port=$(free_udp_port)
  local server_log="$work/netz-server-$scenario.log"
  local client_log="$work/s2n-client-$scenario.log"

  "$netz_server" "$port" "$server_mode" >"$server_log" 2>&1 &
  server_pid=$!
  : >"$client_log"
  for _ in $(seq 1 200); do
    grep -q 'netz QUIC interop server listening' "$server_log" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  grep -q 'netz QUIC interop server listening' "$server_log" || {
    echo 'timed out waiting for netz QUIC server' >&2
    return 1
  }
  timeout 20s "$s2n_peer" client "$port" "$work/netz-ca.pem" \
    "$scenario" >"$client_log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq "$client_result" "$client_log"
  grep -Fq "$server_result" "$server_log"
  cat "$client_log"
  cat "$server_log"
}

run_s2n_client_case echo s2n \
  's2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop streams=2 bytes=10 peer_close=58' \
  'netz QUIC close server interoperated with s2n-quic: alpn=hq-interop streams=2 bytes=10 peer_close=58'
run_s2n_client_case reset s2n_reset \
  's2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=58' \
  'netz QUIC reset server interoperated with s2n-quic: alpn=hq-interop reset_error=41 concurrent_sibling=4 echo_bytes=5 peer_close=58'
run_s2n_client_case stop s2n_stop \
  's2n-quic client interoperated with netz: verified=true version=1 alpn=hq-interop stop_error=42 reset_sent=42 concurrent_sibling=4 echo_bytes=5 peer_close=58' \
  'netz QUIC stop-sending server interoperated with s2n-quic: alpn=hq-interop stop_error=42 reset_error=42 concurrent_sibling=4 echo_bytes=5 peer_close=58'
