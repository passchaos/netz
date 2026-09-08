#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz RFC 9220 client executable path}
server=${2:?netz RFC 9220 server executable path}
quicz_root=${QUICZ_ROOT:-"$HOME/Work/quicz"}
fixture_dir="$quicz_root/examples/interop/go_echo_client"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
version=${NETZ_WEBSOCKET_H3_INTEROP_VERSION:-1}
if [[ "$version" != 1 && "$version" != 2 ]]; then
  echo "invalid WebSocket-over-H3 QUIC version: $version" >&2
  exit 2
fi
go_version_args=()
netz_version_args=()
if [[ "$version" == 2 ]]; then
  go_version_args=(-v2-only)
  netz_version_args=(--version=2)
fi
if [[ ! -f "$fixture_dir/go.mod" ]]; then
  echo "audited quic-go fixture module not found under $fixture_dir" >&2
  exit 127
fi
if ! command -v go >/dev/null 2>&1; then
  echo 'go not found; install it to build the quic-go RFC 9220 peer' >&2
  exit 127
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
    while IFS= read -r log_file; do
      echo "===== $log_file =====" >&2
      cat "$log_file" >&2
    done < <(find "$work" -type f \
      \( -name '*.log' -o -name '*.rss' \) -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

# Build inside the external module so its pinned quic-go version supplies the
# HTTP/3 implementation, without modifying that checkout.
(cd "$fixture_dir" && go build \
  -o "$work/quic-go-rfc9220-peer" \
  "$repo_root/tools/interop/websocket_h3_quic_go.go")

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

if [[ ${3:-} == --bench ]]; then
  shift 3
  mapfile -t bench_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
  )
  if [[ ${#bench_cpus[@]} -lt 2 ]]; then
    echo 'WebSocket-over-H3 comparison requires two available CPUs' >&2
    exit 1
  fi
  client_cpu=${bench_cpus[0]}
  server_cpu=${bench_cpus[1]}
  stats=false
  warmup=20
  iterations=1000
  payload_bytes=4096
  go_args=()
  for arg in "$@"; do
    go_args+=("-${arg#--}")
    case "$arg" in
      --stats) stats=true ;;
      --warmup=*) warmup=${arg#--warmup=} ;;
      --iterations=*) iterations=${arg#--iterations=} ;;
      --payload-bytes=*) payload_bytes=${arg#--payload-bytes=} ;;
    esac
  done
  time_bin=${TIME_BIN:-/usr/bin/time}
  if [[ $stats == true && ! -x $time_bin ]]; then
    echo "GNU time not found at $time_bin" >&2
    exit 127
  fi

  wait_for_line() {
    local pid=$1 log=$2 prefix=$3
    local value=
    for _ in $(seq 1 600); do
      value=$(sed -n "s/^${prefix}=//p" "$log" | head -1)
      if [[ -n $value ]]; then printf '%s\n' "$value"; return 0; fi
      if ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; return 1; fi
      sleep 0.05
    done
    echo "timed out waiting for $prefix" >&2
    return 1
  }

  check_result() {
    local check_args=(python3 \
      "$repo_root/tools/interop/websocket_h3_benchmark_check.py" \
      --role-pair="$1" --warmup="$warmup" --iterations="$iterations" \
      --payload-bytes="$payload_bytes" --client-log="$2" --server-log="$3")
    if [[ -n ${4:-} ]]; then
      check_args+=(--client-rss="$4" --server-rss="$5")
    fi
    "${check_args[@]}"
  }

  echo "benchmark_cpu_layout=client:$client_cpu,server:$server_cpu"
  cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF
  port=$(free_udp_port)
  if [[ $stats == true ]]; then
    timeout 180s "$time_bin" -f '%M' -o "$work/quic-go-bench-server.rss" \
      taskset -c "$server_cpu" "$work/quic-go-rfc9220-peer" \
      -mode bench-server -addr "127.0.0.1:$port" \
      -ca-out "$work/quic-go-bench-ca.pem" "${go_args[@]}" \
      >"$work/quic-go-bench-server.log" 2>&1 &
  else
    timeout 180s taskset -c "$server_cpu" "$work/quic-go-rfc9220-peer" \
      -mode bench-server -addr "127.0.0.1:$port" \
      -ca-out "$work/quic-go-bench-ca.pem" "${go_args[@]}" \
      >"$work/quic-go-bench-server.log" 2>&1 &
  fi
  server_pid=$!
  wait_for_line "$server_pid" "$work/quic-go-bench-server.log" \
    QUIC_GO_WEBSOCKET_H3_BENCH_ADDR >/dev/null
  sleep 0.05
  if [[ $stats == true ]]; then
    timeout 180s "$time_bin" -f '%M' -o "$work/netz-bench-client.rss" \
      taskset -c "$client_cpu" "$client" \
      bench-client "$port" "$work/quic-go-bench-ca.pem" "$@" \
      >"$work/netz-bench-client.log" 2>&1
  else
    timeout 180s taskset -c "$client_cpu" "$client" \
      bench-client "$port" "$work/quic-go-bench-ca.pem" "$@" \
      >"$work/netz-bench-client.log" 2>&1
  fi
  wait "$server_pid"
  server_pid=
  if [[ $stats == true ]]; then
    check_result netz-client+quic-go-server "$work/netz-bench-client.log" \
      "$work/quic-go-bench-server.log" "$work/netz-bench-client.rss" \
      "$work/quic-go-bench-server.rss"
  else
    check_result netz-client+quic-go-server "$work/netz-bench-client.log" \
      "$work/quic-go-bench-server.log"
  fi
  cat "$work/quic-go-bench-server.log"
  cat "$work/netz-bench-client.log"

  port=$(free_udp_port)
  if [[ $stats == true ]]; then
    timeout 180s "$time_bin" -f '%M' -o "$work/netz-bench-server.rss" \
      taskset -c "$server_cpu" "$server" bench-server "$port" "$@" \
      >"$work/netz-bench-server.log" 2>&1 &
  else
    timeout 180s taskset -c "$server_cpu" "$server" \
      bench-server "$port" "$@" >"$work/netz-bench-server.log" 2>&1 &
  fi
  server_pid=$!
  wait_for_line "$server_pid" "$work/netz-bench-server.log" \
    NETZ_WEBSOCKET_H3_BENCH_PORT >/dev/null
  if [[ $stats == true ]]; then
    timeout 180s "$time_bin" -f '%M' -o "$work/quic-go-bench-client.rss" \
      taskset -c "$client_cpu" "$work/quic-go-rfc9220-peer" \
      -mode bench-client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
      "${go_args[@]}" >"$work/quic-go-bench-client.log" 2>&1
  else
    timeout 180s taskset -c "$client_cpu" "$work/quic-go-rfc9220-peer" \
      -mode bench-client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
      "${go_args[@]}" >"$work/quic-go-bench-client.log" 2>&1
  fi
  wait "$server_pid"
  server_pid=
  if [[ $stats == true ]]; then
    check_result quic-go-client+netz-server "$work/quic-go-bench-client.log" \
      "$work/netz-bench-server.log" "$work/quic-go-bench-client.rss" \
      "$work/netz-bench-server.rss"
  else
    check_result quic-go-client+netz-server "$work/quic-go-bench-client.log" \
      "$work/netz-bench-server.log"
  fi
  cat "$work/netz-bench-server.log"
  cat "$work/quic-go-bench-client.log"
  exit 0
fi

port=$(free_udp_port)
"$work/quic-go-rfc9220-peer" \
  -mode server -addr "127.0.0.1:$port" \
  -ca-out "$work/quic-go-ca.pem" \
  "${go_version_args[@]}" \
  >"$work/quic-go-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -s "$work/quic-go-ca.pem" ]] &&
      grep -q 'quic-go RFC 9220 server listening=' \
        "$work/quic-go-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/quic-go-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if [[ ! -s "$work/quic-go-ca.pem" ]] || ! \
    grep -q 'quic-go RFC 9220 server listening=' \
      "$work/quic-go-server.log"; then
  echo 'timed out waiting for quic-go RFC 9220 server' >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
if ! timeout 20s "$client" "$port" "$work/quic-go-ca.pem" \
    "${netz_version_args[@]}" >"$work/netz-client.log" 2>&1; then
  cat "$work/netz-client.log" >&2
  cat "$work/quic-go-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "netz RFC 9220 client interoperated with quic-go: version=$version extended_connect=true tls_verified=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/netz-client.log"
if [[ "$version" == 2 ]]; then
  grep -Eq 'local_key_updates=[1-9][0-9]* peer_key_updates=[1-9][0-9]*$' \
    "$work/netz-client.log"
fi
grep -Fq \
  "quic-go RFC 9220 server interoperated with netz: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/quic-go-server.log"
cat "$work/netz-client.log"
cat "$work/quic-go-server.log"

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

port=$(free_udp_port)
"$server" "$port" "${netz_version_args[@]}" \
  >"$work/netz-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
  if grep -q 'netz RFC 9220 quic-go interop server listening' \
      "$work/netz-server.log"; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/netz-server.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'netz RFC 9220 quic-go interop server listening' \
    "$work/netz-server.log"; then
  echo 'timed out waiting for netz RFC 9220 server' >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
if ! timeout 20s "$work/quic-go-rfc9220-peer" \
    -mode client -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
    "${go_version_args[@]}" >"$work/quic-go-client.log" 2>&1; then
  cat "$work/quic-go-client.log" >&2
  cat "$work/netz-server.log" >&2
  exit 1
fi
wait "$server_pid"
server_pid=
grep -Fq \
  "quic-go RFC 9220 client interoperated with netz: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/quic-go-client.log"
grep -Fq \
  "netz RFC 9220 server interoperated with quic-go: version=$version extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done" \
  "$work/netz-server.log"
if [[ "$version" == 2 ]]; then
  grep -Eq 'local_key_updates=[1-9][0-9]* peer_key_updates=[1-9][0-9]*$' \
    "$work/netz-server.log"
fi
cat "$work/quic-go-client.log"
cat "$work/netz-server.log"

if [[ "$version" == 1 ]]; then
  NETZ_WEBSOCKET_H3_INTEROP_VERSION=2 "$0" "$client" "$server"
fi
