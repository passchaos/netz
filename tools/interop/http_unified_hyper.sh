#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz unified client executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/tools/hyper_http2_flow/Cargo.toml"
server="$repo_root/tools/hyper_http2_flow/target/release/netz-hyper-unified-server"
work=$(mktemp -d)
server_pid=
cleanup() {
  local status=$?
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    local artifact_root=${NETZ_HTTP_UNIFIED_ARTIFACT_DIR:-"$repo_root/docs/evidence/http_unified_shared/$(date -u +%Y-%m-%d)"}
    if mkdir -p "$artifact_root"; then
      local retained
      retained=$(mktemp -d "$artifact_root/failed.XXXXXXXX")
      cp -a "$work/." "$retained/"
      printf 'Retained failed unified Hyper artifacts: %s\n' "$retained" >&2
    else
      printf 'Retained failed unified Hyper work directory: %s\n' "$work" >&2
      return
    fi
  fi
  rm -rf "$work"
}
trap cleanup EXIT

free_tcp_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for_server() {
  local log=$1
  local protocol=$2
  for _ in $(seq 1 200); do
    if grep -Fq "Hyper unified server listening protocol=$protocol" "$log"; then
      return
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$log" >&2
      exit 1
    fi
    sleep 0.05
  done
  cat "$log" >&2
  exit 1
}

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
  --bin netz-hyper-unified-server

for protocol in h1 h2 h2-shared; do
  port=$(free_tcp_port)
  "$server" "$port" "$work/cert.pem" "$work/key.pem" "$protocol" \
    >"$work/server-$protocol.log" 2>&1 &
  server_pid=$!
  wait_for_server "$work/server-$protocol.log" "$protocol"
  if timeout 15s "$client" "$port" "$protocol" \
      >"$work/client-$protocol.log" 2>&1; then
    :
  else
    client_status=$?
    cat "$work/client-$protocol.log" >&2
    cat "$work/server-$protocol.log" >&2
    exit "$client_status"
  fi
  wait "$server_pid"
  server_pid=
  expected_alpn=http/1.1
  if [[ $protocol == h2 || $protocol == h2-shared ]]; then expected_alpn=h2; fi
  if [[ $protocol == h2-shared ]]; then
    grep -Fq \
      "netz unified HTTP shared Hyper protocol=h2 alpn=h2 requests=7 connections=1 late_sibling=true canceled_first=true surviving_second=true later_reuse=true shared_budget=1 tls=pinned client_io=zio-std-io server_io=hyper-tokio" \
      "$work/client-$protocol.log"
    grep -Fq \
      "Hyper unified shared server completed protocol=h2 alpn=h2 requests=7 connections=1 late_sibling=true cancellations=1 surviving_second=true later_reuse=true tls=pinned client_io=zio-std-io server_io=hyper-tokio" \
      "$work/server-$protocol.log"
    cat "$work/client-$protocol.log"
    cat "$work/server-$protocol.log"
    continue
  fi
  grep -Fq \
    "netz unified HTTP pool selected Hyper protocol=$protocol alpn=$expected_alpn requests=2 connections=1 reusable=true admission_timeout=isolated queued_timeout=isolated failed_retirement=isolated completed_return=isolated collector_timeout=retained setup_cache_timeout=retained close_deadline=complete client_io=zio-std-io server_io=hyper-tokio" \
    "$work/client-$protocol.log"
  grep -Fq \
    "Hyper unified server completed protocol=$protocol alpn=$expected_alpn requests=2 connections=1 client_io=zio-std-io server_io=hyper-tokio" \
    "$work/server-$protocol.log"
  cat "$work/client-$protocol.log"
  cat "$work/server-$protocol.log"
done
