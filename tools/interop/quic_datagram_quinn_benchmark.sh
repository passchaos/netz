#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz DATAGRAM benchmark client path}
netz_server=${2:?netz DATAGRAM benchmark server path}
build_mode=${3:?netz build mode}
shift 3

samples=5
warmup=200
iterations=5000
payload_bytes=32
window=1
timeout_ms=30000
client_cpu=
server_cpu=
for argument in "$@"; do
  case $argument in
    --samples=*) samples=${argument#*=} ;;
    --warmup=*) warmup=${argument#*=} ;;
    --iterations=*) iterations=${argument#*=} ;;
    --payload-bytes=*) payload_bytes=${argument#*=} ;;
    --window=*) window=${argument#*=} ;;
    --timeout-ms=*) timeout_ms=${argument#*=} ;;
    --client-cpu=*) client_cpu=${argument#*=} ;;
    --server-cpu=*) server_cpu=${argument#*=} ;;
    *) echo "unsupported DATAGRAM benchmark argument: $argument" >&2; exit 2 ;;
  esac
done
if [[ $build_mode != ReleaseFast ]]; then
  echo 'bench-quic-datagram-quinn requires -Doptimize=ReleaseFast' >&2
  exit 2
fi
for value in "$samples" "$warmup" "$iterations" "$payload_bytes" "$window" "$timeout_ms"; do
  if ! [[ $value =~ ^[0-9]+$ ]]; then
    echo 'DATAGRAM benchmark arguments must be non-negative integers' >&2
    exit 2
  fi
done
if (( samples == 0 || samples % 2 == 0 || warmup > 100000 ||
      iterations == 0 || iterations > 1000000 || payload_bytes < 12 ||
      payload_bytes > 1024 || window == 0 || window > 64 ||
      timeout_ms == 0 || timeout_ms > 600000 )); then
  echo 'invalid DATAGRAM benchmark configuration' >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
quinn_root="$repo_root/../../Work/quinn"
quinn_revision=d9c8c4c695fc64292d9b117844ea6924ca0d0815
manifest="$repo_root/tools/interop/quic_quinn/Cargo.toml"
if [[ $(git -C "$quinn_root" rev-parse HEAD) != "$quinn_revision" ]]; then
  echo "Quinn must be checked out at $quinn_revision" >&2
  exit 1
fi
if [[ -n $(git -C "$quinn_root" status --short) ]]; then
  echo 'Quinn checkout must be clean' >&2
  exit 1
fi
for command in cargo openssl python3 sha256sum taskset; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required for the DATAGRAM benchmark" >&2
    exit 127
  }
done

mapfile -t benchmark_cpus < <(python3 - <<'PY'
import os
for cpu in sorted(os.sched_getaffinity(0))[:2]:
    print(cpu)
PY
)
if [[ -z $client_cpu ]]; then client_cpu=${benchmark_cpus[0]:-}; fi
if [[ -z $server_cpu ]]; then server_cpu=${benchmark_cpus[1]:-}; fi
if ! [[ $client_cpu =~ ^[0-9]+$ && $server_cpu =~ ^[0-9]+$ ]] ||
   [[ $client_cpu == "$server_cpu" ]] ||
   ! taskset -c "$client_cpu" true || ! taskset -c "$server_cpu" true; then
  echo 'DATAGRAM benchmark requires two distinct available CPUs' >&2
  exit 2
fi

cargo build --release --offline --locked --manifest-path "$manifest" >&2
quinn_peer="$repo_root/tools/interop/quic_quinn/target/release/netz-quic-quinn-interop"
checker="$repo_root/tools/interop/quic_datagram_benchmark_check.py"
python3 "$repo_root/tools/interop/quic_datagram_benchmark_check_test.py" >&2

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
  if (( status != 0 )); then
    for log in "$work"/*.log; do
      [[ ! -s $log ]] || { echo "===== $log =====" >&2; sed -n '1,260p' "$log" >&2; }
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
wait_for_line() {
  local pid=$1 log=$2 prefix=$3
  for _ in $(seq 1 200); do
    grep -q "$prefix" "$log" && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.05
  done
  return 1
}
sha256() { sha256sum "$1" | cut -d' ' -f1; }

openssl ecparam -name prime256v1 -genkey -noout -out "$work/quinn-ca-key.pem"
openssl req -new -x509 -key "$work/quinn-ca-key.pem" \
  -out "$work/quinn-ca.pem" -days 1 -sha256 \
  -subj '/CN=netz Quinn DATAGRAM benchmark CA' \
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
cat >"$work/netz-ca.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=
-----END CERTIFICATE-----
EOF

common=(
  "--warmup=$warmup" "--iterations=$iterations"
  "--payload-bytes=$payload_bytes" "--window=$window"
  "--timeout-ms=$timeout_ms"
)
mode=$([[ $window == 1 ]] && echo pingpong || echo windowed-pingpong)
results="$work/results.log"
printf '%s\n' \
  "record=environment protocol=quic-datagram mode=$mode samples=$samples schedule=abba client_cpu=$client_cpu server_cpu=$server_cpu warmup=$warmup iterations=$iterations payload_bytes=$payload_bytes window=$window timeout_ms=$timeout_ms host=$(hostname) arch=$(uname -m) kernel=$(uname -r) zig=$(zig version) rustc=$(rustc --version | awk '{print $2}') netz_build_mode=$build_mode quinn_revision=$quinn_revision netz_client_sha256=$(sha256 "$netz_client") netz_server_sha256=$(sha256 "$netz_server") quinn_binary_sha256=$(sha256 "$quinn_peer") quinn_lock_sha256=$(sha256 "$repo_root/tools/interop/quic_quinn/Cargo.lock") complete=true" \
  >"$results"

run_pair() {
  local sample=$1 role_pair=$2
  local client_impl=${role_pair%%-client+*}
  local server_impl=${role_pair#*+}
  server_impl=${server_impl%-server}
  local port
  port=$(free_udp_port)
  local client_log="$work/client.log" server_log="$work/server.log"
  : >"$client_log"; : >"$server_log"
  if [[ $server_impl == quinn ]]; then
    timeout 120s taskset -c "$server_cpu" "$quinn_peer" bench-server \
      "$port" "$work/quinn-cert.pem" "$work/quinn-key.pem" "$role_pair" \
      "${common[@]}" >"$server_log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$server_log" QUINN_DATAGRAM_BENCH_PORT || return 1
    ca="$work/quinn-ca.pem"
  else
    timeout 120s taskset -c "$server_cpu" "$netz_server" bench-server \
      "$port" "$role_pair" "${common[@]}" >"$server_log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$server_log" NETZ_QUIC_DATAGRAM_BENCH_PORT || return 1
    ca="$work/netz-ca.pem"
  fi
  if [[ $client_impl == netz ]]; then
    timeout 120s taskset -c "$client_cpu" "$netz_client" bench-client \
      "$port" "$ca" "$role_pair" "${common[@]}" >"$client_log" 2>&1
  else
    timeout 120s taskset -c "$client_cpu" "$quinn_peer" bench-client \
      "$port" "$ca" "$role_pair" "${common[@]}" >"$client_log" 2>&1
  fi
  wait "$server_pid"; server_pid=
  printf 'record=run protocol=quic-datagram mode=%s sample=%d role_pair=%s implementation=%s fixed_server=%s schedule=abba client_cpu=%d server_cpu=%d\n' \
    "$mode" \
    "$sample" "$role_pair" "$client_impl" "$server_impl" \
    "$client_cpu" "$server_cpu" >>"$results"
  grep '^record=config ' "$client_log" >>"$results"
  grep '^record=result ' "$client_log" >>"$results"
  grep '^record=config ' "$server_log" >>"$results"
  grep '^record=server-complete ' "$server_log" >>"$results"
}

odd=(
  netz-client+quinn-server quinn-client+quinn-server
  quinn-client+netz-server netz-client+netz-server
)
even=(
  quinn-client+quinn-server netz-client+quinn-server
  netz-client+netz-server quinn-client+netz-server
)
for ((sample = 1; sample <= samples; sample++)); do
  if (( sample % 2 )); then order=("${odd[@]}"); else order=("${even[@]}"); fi
  for role_pair in "${order[@]}"; do
    run_pair "$sample" "$role_pair"
  done
done
python3 "$checker" --log "$results" --samples "$samples" \
  --client-cpu "$client_cpu" --server-cpu "$server_cpu" \
  --warmup "$warmup" --iterations "$iterations" \
  --payload-bytes "$payload_bytes" --window "$window" \
  --timeout-ms "$timeout_ms"
