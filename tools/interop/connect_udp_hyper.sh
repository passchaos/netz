#!/usr/bin/env bash
set -euo pipefail

netz_peer=${1:?netz CONNECT-UDP peer executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
hyper_peer="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-connect-udp"
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

cargo build --release --offline --locked \
  --manifest-path "$manifest" \
  --bin netz-hyper-connect-udp

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
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

for protocol in h1 h2; do
  http_label=HTTP/1
  if [[ "$protocol" == h2 ]]; then
    http_label=HTTP/2
  fi
  for transport in cleartext tls; do
    port=$(free_tcp_port)
    hyper_server_args=("$hyper_peer" "$protocol-server" "$port")
    netz_client_args=("$netz_peer" "$protocol-client" "$port")
    if [[ "$transport" == tls ]]; then
      hyper_server_args+=("$work/cert.pem" "$work/key.pem")
      netz_client_args+=("$work/cert.pem")
    fi
    hyper_server_log="$work/$protocol-$transport-hyper-server.log"
    netz_client_log="$work/$protocol-$transport-netz-client.log"
    "${hyper_server_args[@]}" >"$hyper_server_log" 2>&1 &
    server_pid=$!
    wait_for_marker \
      "$hyper_server_log" \
      "Hyper $http_label CONNECT-UDP server listening transport=$transport"
    if ! timeout 20s "${netz_client_args[@]}" \
        >"$netz_client_log" 2>&1; then
      cat "$netz_client_log" >&2
      cat "$hyper_server_log" >&2
      exit 1
    fi
    wait "$server_pid"
    server_pid=
    grep -Fq \
      "netz $http_label CONNECT-UDP client interoperated with Hyper: transport=$transport sent=513 received=777" \
      "$netz_client_log"
    grep -Fq \
      "Hyper $http_label CONNECT-UDP server interoperated with netz: transport=$transport received=513 sent=777" \
      "$hyper_server_log"
    cat "$netz_client_log"
    cat "$hyper_server_log"
    echo "netz $http_label client -> Hyper $transport server CONNECT-UDP passed"

    port=$(free_tcp_port)
    netz_server_args=("$netz_peer" "$protocol-server" "$port")
    hyper_client_args=("$hyper_peer" "$protocol-client" "$port")
    if [[ "$transport" == tls ]]; then
      netz_server_args+=(--tls)
      hyper_client_args+=("$work/cert.pem")
    fi
    netz_server_log="$work/$protocol-$transport-netz-server.log"
    hyper_client_log="$work/$protocol-$transport-hyper-client.log"
    "${netz_server_args[@]}" >"$netz_server_log" 2>&1 &
    server_pid=$!
    wait_for_marker \
      "$netz_server_log" \
      "netz $http_label CONNECT-UDP server listening transport=$transport"
    if ! timeout 20s "${hyper_client_args[@]}" \
        >"$hyper_client_log" 2>&1; then
      cat "$hyper_client_log" >&2
      cat "$netz_server_log" >&2
      exit 1
    fi
    wait "$server_pid"
    server_pid=
    grep -Fq \
      "Hyper $http_label CONNECT-UDP client interoperated with netz: transport=$transport sent=513 received=777" \
      "$hyper_client_log"
    grep -Fq \
      "netz $http_label CONNECT-UDP server interoperated with Hyper: transport=$transport received=513 sent=777" \
      "$netz_server_log"
    cat "$hyper_client_log"
    cat "$netz_server_log"
    echo "Hyper $http_label client -> netz $transport server CONNECT-UDP passed"
  done
done

echo 'Hyper/netz CONNECT-UDP interoperability matrix passed: versions=HTTP/1,HTTP/2 transports=cleartext,tls directions=client,server'
