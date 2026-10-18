#!/usr/bin/env bash
set -euo pipefail

netz_peer=${1:?netz HTTP/3 CONNECT-UDP peer executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/interop/h3_connect_udp/Cargo.toml"
h3_peer="$repo_root/tools/interop/h3_connect_udp/target/release/netz-h3-connect-udp-interop"
work=$(mktemp -d)
server_pid=
echo_pid=
cleanup() {
  if [[ -n "$echo_pid" ]]; then
    kill "$echo_pid" 2>/dev/null || true
    wait "$echo_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cat >"$work/netz-cert.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
openssl x509 -in "$work/netz-cert.pem" -outform DER \
  -out "$work/netz-cert.der"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$work/h3-key.pem"
openssl req -new -x509 -key "$work/h3-key.pem" -days 1 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -out "$work/h3-cert.pem"
openssl x509 -in "$work/h3-cert.pem" -outform DER \
  -out "$work/h3-cert.der"
openssl pkcs8 -topk8 -nocrypt -in "$work/h3-key.pem" \
  -outform DER -out "$work/h3-key.der"

cargo build --release --offline --locked --manifest-path "$manifest"

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_marker() {
  local log=$1
  local marker=$2
  for _ in $(seq 1 200); do
    if grep -Fq "$marker" "$log" 2>/dev/null; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      exit 1
    fi
    sleep 0.05
  done
  echo "timed out waiting for $marker" >&2
  cat "$log" >&2
  exit 1
}

port=$(free_udp_port)
"$h3_peer" server "$port" "$work/h3-cert.der" "$work/h3-key.der" \
  >"$work/h3-server.log" 2>&1 &
server_pid=$!
wait_for_marker "$work/h3-server.log" \
  'h3/quinn CONNECT-UDP server listening'
if ! timeout 20s "$netz_peer" client "$port" "$work/h3-cert.pem" \
    >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/h3-server.log" >&2
  exit 1
fi
if ! wait "$server_pid"; then
  server_pid=
  cat "$work/netz-client.log" >&2
  cat "$work/h3-server.log" >&2
  exit 1
fi
server_pid=
grep -Fq \
  'netz HTTP/3 CONNECT-UDP client interoperated with h3/quinn: verified=true sent=513 received=777 settings_datagram=true settings_extended_connect=true unknown_context=true response_terminal=true' \
  "$work/netz-client.log"
grep -Fq \
  'h3/quinn CONNECT-UDP server interoperated with netz: received=513 proxied_udp=true sent=777 settings_datagram=true settings_extended_connect=true unknown_context=true delivery_ack=true response_fin=true' \
  "$work/h3-server.log"
cat "$work/netz-client.log"
cat "$work/h3-server.log"
echo 'netz HTTP/3 client -> h3/quinn CONNECT-UDP server passed'

port=$(free_udp_port)
target_port=$(free_udp_port)
python3 -u - "$target_port" >"$work/udp-echo.log" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", port))
    print(f"UDP echo ready on 127.0.0.1:{port}", flush=True)
    payload, peer = sock.recvfrom(2048)
    if payload != bytes([0x5A]) * 513:
        raise RuntimeError(f"unexpected UDP payload len={len(payload)}")
    sock.sendto(bytes([0xA5]) * 777, peer)
    print("UDP echo completed received=513 sent=777", flush=True)
PY
echo_pid=$!
wait_for_echo=false
for _ in $(seq 1 200); do
  if grep -Fq 'UDP echo ready' "$work/udp-echo.log" 2>/dev/null; then
    wait_for_echo=true
    break
  fi
  if ! kill -0 "$echo_pid" 2>/dev/null; then
    cat "$work/udp-echo.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ "$wait_for_echo" != true ]]; then
  echo 'timed out waiting for UDP echo' >&2
  cat "$work/udp-echo.log" >&2
  exit 1
fi
"$netz_peer" server "$port" "$target_port" \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
wait_for_marker "$work/netz-server.log" \
  'netz HTTP/3 CONNECT-UDP server listening'
if ! timeout 20s "$h3_peer" client "$port" "$work/netz-cert.der" \
    >"$work/h3-client.log" 2>&1; then
  cat "$work/h3-client.log" >&2
  cat "$work/netz-server.log" >&2
  cat "$work/udp-echo.log" >&2
  exit 1
fi
if ! wait "$server_pid"; then
  server_pid=
  cat "$work/h3-client.log" >&2
  cat "$work/netz-server.log" >&2
  cat "$work/udp-echo.log" >&2
  exit 1
fi
server_pid=
wait "$echo_pid"
echo_pid=
grep -Fq \
  'h3/quinn CONNECT-UDP client interoperated with netz: sent=513 received=777 settings_datagram=true settings_extended_connect=true unknown_context=true request_fin=true response_fin=true' \
  "$work/h3-client.log"
grep -Fq \
  'netz HTTP/3 CONNECT-UDP server interoperated with h3/quinn: received=513 proxied_udp=true sent=777 settings_datagram=true settings_extended_connect=true unknown_context=true request_terminal=true' \
  "$work/netz-server.log"
grep -Fq 'UDP echo completed received=513 sent=777' \
  "$work/udp-echo.log"
cat "$work/h3-client.log"
cat "$work/netz-server.log"
echo 'h3/quinn HTTP/3 client -> netz CONNECT-UDP server passed'

echo 'h3/quinn and netz bidirectional CONNECT-UDP interop passed'
