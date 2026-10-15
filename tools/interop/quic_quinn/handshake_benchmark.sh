#!/usr/bin/env bash
set -euo pipefail

netz_bench=${1:?netz handshake benchmark executable path}
build_mode=${2:?netz build mode}
shift 2

samples=5
warmup=10
iterations=100
timeout_ms=10000
client_cpu=
server_cpu=
netz_prepared_p256=disabled
for argument in "$@"; do
  case $argument in
    --samples=*) samples=${argument#*=} ;;
    --warmup=*) warmup=${argument#*=} ;;
    --iterations=*) iterations=${argument#*=} ;;
    --timeout-ms=*) timeout_ms=${argument#*=} ;;
    --client-cpu=*) client_cpu=${argument#*=} ;;
    --server-cpu=*) server_cpu=${argument#*=} ;;
    --netz-prepared-p256=*) netz_prepared_p256=${argument#*=} ;;
    *) echo "unsupported Quinn handshake benchmark argument: $argument" >&2; exit 2 ;;
  esac
done
if [[ $netz_prepared_p256 != enabled && $netz_prepared_p256 != disabled ]]; then
  echo 'netz prepared P-256 mode must be enabled or disabled' >&2
  exit 2
fi
if [[ $build_mode != ReleaseFast ]]; then
  echo 'bench-quic-handshake-quinn requires -Doptimize=ReleaseFast' >&2
  exit 2
fi
for value in "$samples" "$warmup" "$iterations" "$timeout_ms"; do
  if ! [[ $value =~ ^[0-9]+$ ]]; then
    echo 'handshake benchmark arguments must be non-negative integers' >&2
    exit 2
  fi
done
if (( samples == 0 || samples % 2 == 0 || warmup > 4096 ||
      iterations == 0 || iterations > 4096 || timeout_ms == 0 ||
      timeout_ms > 600000 )); then
  echo 'invalid Quinn handshake benchmark configuration' >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
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
for command in cargo openssl python3 sha256sum taskset xxd; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required for the Quinn handshake benchmark" >&2
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
  echo 'Quinn handshake benchmark requires two distinct available CPUs' >&2
  exit 2
fi

cargo test --release --offline --locked --manifest-path "$manifest" >&2
cargo build --release --offline --locked --manifest-path "$manifest" >&2
python3 "$repo_root/tools/interop/quic_handshake_benchmark_check_test.py" >&2
quinn_peer="$repo_root/tools/interop/quic_quinn/target/release/netz-quic-quinn-interop"
checker="$repo_root/tools/interop/quic_handshake_benchmark_check.py"
matrix_checker="$repo_root/tools/interop/quic_quinn/handshake_benchmark_check.py"

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
    find "$work" -type f -name '*.log' -size +0c -print0 | sort -z |
      while IFS= read -r -d '' log; do
        echo "===== $log =====" >&2
        sed -n '1,260p' "$log" >&2
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
  for _ in $(seq 1 600); do
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
  -subj '/CN=netz Quinn handshake benchmark CA' \
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
openssl x509 -in "$work/quinn-cert.pem" -outform der \
  -out "$work/quinn-cert.der"
openssl ec -in "$work/quinn-key.pem" -text -noout 2>/dev/null |
  awk '/priv:/{capture=1;next}/pub:/{capture=0} capture {gsub(/[: ]/,""); printf "%s",$0}' |
  xxd -r -p >"$work/quinn-key.scalar"
if [[ $(wc -c <"$work/quinn-key.scalar") -ne 32 ]]; then
  echo 'failed to extract the shared P-256 private scalar' >&2
  exit 1
fi

results="$work/results.log"
printf '%s\n' \
  "record=environment protocol=quic-v1 mode=handshake peer=quinn samples=$samples schedule=abba client_cpu=$client_cpu server_cpu=$server_cpu host=$(hostname) arch=$(uname -m) kernel=$(uname -r) zig=$(zig version) rustc=$(rustc --version | awk '{print $2}') netz_build_mode=$build_mode quinn_revision=$quinn_revision netz_binary_sha256=$(sha256 "$netz_bench") quinn_binary_sha256=$(sha256 "$quinn_peer") quinn_lock_sha256=$(sha256 "$repo_root/tools/interop/quic_quinn/Cargo.lock") server_identity=shared-ca-signed-p256-leaf server_certificate_chain_entries=1 server_certificate_der_bytes=$(wc -c <"$work/quinn-cert.der") server_certificate_sha256=$(sha256 "$work/quinn-cert.der") netz_certificate_verify=$(if [[ $netz_prepared_p256 == enabled ]]; then printf prepared-p256; else printf fresh-p256; fi) complete=true" \
  >"$results"

run_pair() {
  local sample=$1 role_pair=$2
  local client_impl=${role_pair%%-client+*}
  local server_impl=${role_pair#*+}
  server_impl=${server_impl%-server}
  local pair_dir="$work/$sample-$role_pair"
  mkdir -p "$pair_dir"
  local port=$(free_udp_port)
  local common=("--warmup=$warmup" "--iterations=$iterations" \
    "--run=$sample" "--timeout-ms=$timeout_ms")
  if [[ $server_impl == quinn ]]; then
    timeout 300s taskset -c "$server_cpu" "$quinn_peer" \
      handshake-bench-server "$port" "$work/quinn-cert.pem" \
      "$work/quinn-key.pem" "$role_pair" "${common[@]}" \
      >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/server.log" \
      QUINN_HANDSHAKE_BENCH_PORT
    ca="$work/quinn-ca.pem"
  else
    timeout 300s taskset -c "$server_cpu" "$netz_bench" server "$port" \
      "$work/quinn-cert.der" "$work/quinn-key.scalar" \
      "--role-pair=$role_pair" "${common[@]}" \
      >"$pair_dir/server.log" 2>&1 &
    server_pid=$!
    wait_for_line "$server_pid" "$pair_dir/server.log" \
      NETZ_HANDSHAKE_BENCH_PORT
    ca="$work/quinn-ca.pem"
  fi
  if [[ $client_impl == quinn ]]; then
    timeout 300s taskset -c "$client_cpu" "$quinn_peer" \
      handshake-bench-client "$port" "$ca" "$role_pair" \
      "${common[@]}" >"$pair_dir/client.log" 2>&1
  else
    local netz_client_extra=()
    if [[ $netz_prepared_p256 == enabled ]]; then
      netz_client_extra+=("--prepared-p256-certificate=$work/quinn-cert.der")
    fi
    timeout 300s taskset -c "$client_cpu" "$netz_bench" client "$port" \
      "$ca" "--role-pair=$role_pair" "${common[@]}" \
      "${netz_client_extra[@]}" \
      >"$pair_dir/client.log" 2>&1
  fi
  wait "$server_pid"
  server_pid=
  printf 'record=run protocol=quic-v1 mode=handshake sample=%d role_pair=%s implementation=%s fixed_server=%s schedule=abba client_cpu=%d server_cpu=%d\n' \
    "$sample" "$role_pair" "$client_impl" "$server_impl" \
    "$client_cpu" "$server_cpu" >>"$results"
  cat "$pair_dir/client.log" >>"$results"
  cat "$pair_dir/server.log" >>"$results"
  cat "$pair_dir/client.log" >>"$work/$role_pair-client.log"
  cat "$pair_dir/server.log" >>"$work/$role_pair-server.log"
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

summaries="$work/summaries.log"
: >"$summaries"
for role_pair in "${odd[@]}"; do
  python3 "$checker" \
    "--role-pair=$role_pair" "--samples=$samples" "--warmup=$warmup" \
    "--iterations=$iterations" "--timeout-ms=$timeout_ms" \
    "--client-log=$work/$role_pair-client.log" \
    "--server-log=$work/$role_pair-server.log" >>"$summaries"
done
python3 "$matrix_checker" --log "$results" --summaries "$summaries" \
  --samples "$samples" --client-cpu "$client_cpu" \
  --server-cpu "$server_cpu" --warmup "$warmup" \
  --iterations "$iterations" --timeout-ms "$timeout_ms"
