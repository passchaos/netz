#!/usr/bin/env bash
set -euo pipefail

server=${1:?netz HTTP/3 server executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_dir="$repo_root/tools/interop/quic_go_module"
work=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
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
    done < <(find "$work" -type f -name '*.log' -size +0c | sort)
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

go_bin=${GO_BIN:-}
if [[ -z $go_bin ]]; then
  go_bin=$(command -v go 2>/dev/null || true)
fi
if [[ -z $go_bin && -x /tmp/go/bin/go ]]; then
  go_bin=/tmp/go/bin/go
fi
if [[ -z $go_bin || ! -x $go_bin ]]; then
  echo 'go not found; install it to build the quic-go HTTP/3 fixture' >&2
  exit 127
fi

(cd "$fixture_dir" && GOTOOLCHAIN=local "$go_bin" build -mod=readonly \
  -o "$work/quic-go-http3-handlers" .)

cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

for version in 1 2; do
  port=$(free_udp_port)
  version_args=()
  go_args=()
  if [[ $version == 2 ]]; then
    version_args=(--version=2)
    go_args=(-v2-only)
  fi
  "$server" "$port" --handler-supervisor "${version_args[@]}" \
    >"$work/netz-server-v$version.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 200); do
    if grep -q 'netz HTTP/3 quic-go interop server listening' \
      "$work/netz-server-v$version.log"; then
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$work/netz-server-v$version.log" >&2
      exit 1
    fi
    sleep 0.05
  done
  if ! grep -q 'netz HTTP/3 quic-go interop server listening' \
    "$work/netz-server-v$version.log"; then
    echo "timed out waiting for netz HTTP/3 handler server v$version" >&2
    exit 1
  fi
  timeout 20s "$work/quic-go-http3-handlers" \
    -addr "127.0.0.1:$port" -ca "$work/netz-ca.pem" \
    "${go_args[@]}" >"$work/quic-go-client-v$version.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq \
    "quic-go HTTP/3 clients verified netz handler supervisor: version=$version connections=2 responses=2 bodies=2 trailers=2 concurrent=true client_io=quic-go-netpoll" \
    "$work/quic-go-client-v$version.log"
  grep -Fq \
    "netz HTTP/3 endpoint handler supervisor served quic-go: version=$version connections=2 handlers=2 concurrent=true bodies=2 trailers=2 server_io=zio-std-io" \
    "$work/netz-server-v$version.log"
  cat "$work/quic-go-client-v$version.log"
  cat "$work/netz-server-v$version.log"
done
