#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz client executable path}
netz_server=${2:?netz server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
quinn_root="$repo_root/../../Work/quinn"
fixture_manifest="$repo_root/tools/interop/quic_quinn/Cargo.toml"
expected_quinn_commit=d9c8c4c695fc64292d9b117844ea6924ca0d0815

if [[ ! -f "$quinn_root/quinn/Cargo.toml" ]]; then
  echo "Quinn checkout not found under $quinn_root" >&2
  exit 127
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo 'cargo not found; install it to build the Quinn interop fixture' >&2
  exit 127
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo 'openssl not found; install it to create the test identity' >&2
  exit 127
fi
actual_quinn_commit=$(git -C "$quinn_root" rev-parse HEAD)
if [[ "$actual_quinn_commit" != "$expected_quinn_commit" ]]; then
  echo "Quinn must be checked out at $expected_quinn_commit (found $actual_quinn_commit)" >&2
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

openssl ecparam -name prime256v1 -genkey -noout -out "$work/quinn-ca-key.pem"
openssl req -new -x509 -key "$work/quinn-ca-key.pem" \
  -out "$work/quinn-ca.pem" -days 1 -sha256 -subj '/CN=netz Quinn interop CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl ecparam -name prime256v1 -genkey -noout -out "$work/quinn-key.pem"
openssl req -new -key "$work/quinn-key.pem" -out "$work/quinn.csr" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
cat >"$work/quinn-leaf.ext" <<'EOF'
subjectAltName=DNS:localhost
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$work/quinn.csr" -CA "$work/quinn-ca.pem" \
  -CAkey "$work/quinn-ca-key.pem" -CAcreateserial \
  -out "$work/quinn-cert.pem" -days 1 -sha256 \
  -extfile "$work/quinn-leaf.ext"

cargo build --quiet --release --locked --manifest-path "$fixture_manifest"
quinn_peer="$repo_root/tools/interop/quic_quinn/target/release/netz-quic-quinn-interop"

port=$(free_udp_port)
"$quinn_peer" server "$port" "$work/quinn-cert.pem" \
  "$work/quinn-key.pem" >"$work/quinn-server.log" 2>&1 &
server_pid=$!
: >"$work/netz-client.log"
for _ in $(seq 1 200); do
  grep -q 'Quinn interop server listening=' "$work/quinn-server.log" && break
  kill -0 "$server_pid" 2>/dev/null || exit 1
  sleep 0.05
done
grep -q 'Quinn interop server listening=' "$work/quinn-server.log" || {
  echo 'timed out waiting for Quinn server' >&2
  exit 1
}
timeout 20s "$netz_client" "$port" "$work/quinn-ca.pem" \
  --peer=quinn --scenario=datagram >"$work/netz-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq \
  'netz QUIC client interoperated with Quinn: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes=1171 quinn_boundary_bytes=55 oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls' \
  "$work/netz-client.log"
grep -Fq \
  'Quinn server interoperated with netz: verified=true version=1 alpn=hq-interop sni=localhost datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes=1171 quinn_boundary_bytes=55 oversized_rejected=true stream_sibling=4 peer_close=57 client_io=zio-std-io server_io=quinn-tokio-rustls' \
  "$work/quinn-server.log"
cat "$work/netz-client.log"
cat "$work/quinn-server.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

port=$(free_udp_port)
"$netz_server" "$port" quinn_datagram >"$work/netz-server.log" 2>&1 &
server_pid=$!
: >"$work/quinn-client.log"
for _ in $(seq 1 200); do
  grep -q 'netz QUIC interop server listening' "$work/netz-server.log" && break
  kill -0 "$server_pid" 2>/dev/null || exit 1
  sleep 0.05
done
grep -q 'netz QUIC interop server listening' "$work/netz-server.log" || {
  echo 'timed out waiting for netz QUIC server' >&2
  exit 1
}
timeout 20s "$quinn_peer" client "$port" "$work/netz-ca.pem" \
  >"$work/quinn-client.log" 2>&1
wait "$server_pid"
server_pid=
grep -Fq \
  'Quinn client interoperated with netz: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes=1171 quinn_boundary_bytes=55 oversized_rejected=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io' \
  "$work/quinn-client.log"
grep -Fq \
  'netz QUIC server interoperated with Quinn: verified=true version=1 alpn=hq-interop datagram=true bidirectional=true small_datagrams=2 netz_boundary_bytes=1171 quinn_boundary_bytes=55 oversized_rejected=true stream_sibling=4 peer_close=58 client_io=quinn-tokio-rustls server_io=zio-std-io' \
  "$work/netz-server.log"
cat "$work/quinn-client.log"
cat "$work/netz-server.log"
