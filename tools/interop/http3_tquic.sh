#!/usr/bin/env bash
set -euo pipefail

netz_client=${1:?netz HTTP/3 client executable path}
netz_server=${2:?netz HTTP/3 server executable path}
tquic_root=${TQUIC_ROOT:-"$HOME/Work/tquic"}
tquic_client="$tquic_root/target/release/tquic_client"
tquic_server="$tquic_root/target/release/tquic_server"

if [[ ! -f "$tquic_root/tools/Cargo.toml" ]]; then
  echo "tquic checkout not found under $tquic_root" >&2
  exit 127
fi
if [[ ! -f "$tquic_root/deps/boringssl/CMakeLists.txt" ]]; then
  git -C "$tquic_root" submodule update --init --depth 1 deps/boringssl
fi
(cd "$tquic_root" && cargo build --manifest-path tools/Cargo.toml \
  --release --bin tquic_client --bin tquic_server)

work=$(mktemp -d)
server_pid=
client_pid=
cleanup() {
  if [[ -n "$client_pid" ]]; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

free_udp_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
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
mkdir -p "$work/www" "$work/downloads"
printf 'tquic-one' >"$work/www/one.txt"
printf 'tquic-two' >"$work/www/two.txt"

run_netz_client_case() {
  local retry=$1
  local port
  port=$(free_udp_port)
  local server_args=() client_args=()
  if [[ "$retry" == true ]]; then
    server_args+=(--enable-retry)
    client_args+=(--expect-retry)
  fi
  "$tquic_server" -l "127.0.0.1:$port" -c "$work/cert.pem" \
    -k "$work/key.pem" -r "$work/www" --log-level OFF \
    "${server_args[@]}" >"$work/tquic-server-$retry.log" 2>&1 &
  server_pid=$!
  sleep 0.2
  timeout 20s "$netz_client" "$port" "$work/cert.pem" \
    "${client_args[@]}" \
    >"$work/netz-client-$retry.log" 2>&1
  grep -Fq "netz HTTP/3 client interoperated with tquic: verified=true retry=$retry requests=3 connection_reused=true get=9 range=206/5 post_md5=32" \
    "$work/netz-client-$retry.log"
  cat "$work/netz-client-$retry.log"
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
}

run_netz_client_graceful_case() {
  local retry=$1
  local port
  port=$(free_udp_port)
  local server_args=() client_args=(--graceful)
  if [[ "$retry" == true ]]; then
    server_args+=(--enable-retry)
    client_args+=(--expect-retry)
  fi
  "$tquic_server" -l "127.0.0.1:$port" -c "$work/cert.pem" \
    -k "$work/key.pem" -r "$work/www" --log-level OFF \
    "${server_args[@]}" >"$work/tquic-server-graceful-$retry.log" 2>&1 &
  server_pid=$!
  sleep 0.2
  timeout 20s "$netz_client" "$port" "$work/cert.pem" \
    "${client_args[@]}" \
    >"$work/netz-client-graceful-$retry.log" 2>&1
  grep -Fq "netz HTTP/3 client gracefully drained tquic: retry=$retry goaway=0 active_stream=0 active_drained=true next_rejected=true" \
    "$work/netz-client-graceful-$retry.log"
  cat "$work/netz-client-graceful-$retry.log"
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
}

run_tquic_client_graceful_case() {
  local retry=$1
  local port
  port=$(free_udp_port)
  local graceful_downloads="$work/downloads-graceful-$retry"
  mkdir -p "$graceful_downloads"
  local server_args=(--graceful)
  if [[ "$retry" == true ]]; then
    server_args+=(--retry)
  fi
  "$netz_server" "$port" "${server_args[@]}" \
    >"$work/netz-server-graceful-$retry.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    grep -q "netz HTTP/3 tquic interop server listening" \
      "$work/netz-server-graceful-$retry.log" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$work/netz-server-graceful-$retry.log" >&2
      exit 1
    fi
    sleep 0.05
  done
  "$tquic_client" -c "127.0.0.1:$port" -a h3 \
    --max-concurrent-requests 1 --max-requests-per-conn 2 \
    --total-requests-per-thread 2 --dump-dir "$graceful_downloads" \
    --log-level DEBUG "https://localhost:$port/one.txt" \
    "https://localhost:$port/two.txt" \
    >"$work/tquic-client-graceful-$retry.log" 2>&1 &
  client_pid=$!
  # The stock CLI retries a refused stream forever. Stop it only after its
  # independent log and body output prove both GOAWAY boundaries, active-stream
  # completion, and the post-GOAWAY stream_new() rejection.
  for _ in $(seq 1 100); do
    if grep -Fq "got GOAWAY with ID 4611686018427387900" \
        "$work/tquic-client-graceful-$retry.log" && \
      grep -Fq "got GOAWAY with ID 4" \
        "$work/tquic-client-graceful-$retry.log" && \
      grep -Eq "send request error .*error: IdError" \
        "$work/tquic-client-graceful-$retry.log" && \
      [[ "$(cat "$graceful_downloads/one.txt" 2>/dev/null)" == \
        "netz-tquic-one" ]]; then
      break
    fi
    if ! kill -0 "$client_pid" 2>/dev/null; then
      cat "$work/tquic-client-graceful-$retry.log" >&2
      exit 1
    fi
    sleep 0.05
  done
  # Repeat the conditions outside the polling loop so exhausting all retries
  # cannot fall through as a false pass.
  grep -Fq "got GOAWAY with ID 4611686018427387900" \
    "$work/tquic-client-graceful-$retry.log"
  grep -Fq "got GOAWAY with ID 4" \
    "$work/tquic-client-graceful-$retry.log"
  grep -Eq "send request error .*error: IdError" \
    "$work/tquic-client-graceful-$retry.log"
  test "$(cat "$graceful_downloads/one.txt")" = "netz-tquic-one"
  kill "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true
  client_pid=
  wait "$server_pid"
  server_pid=
  grep -Fq "netz HTTP/3 server gracefully drained tquic: retry=$retry initial_goaway=max final_goaway=4 active_stream=0 active_drained=true next_rejected=true" \
    "$work/netz-server-graceful-$retry.log"
  # tquic creates the dump file before stream_new(), so rejection leaves an
  # empty placeholder rather than no file at all.
  test ! -s "$graceful_downloads/two.txt"
  echo "tquic HTTP/3 client gracefully drained by netz: retry=$retry initial_goaway=max final_goaway=4 active_stream=0 active_drained=true next_rejected=true"
  cat "$work/netz-server-graceful-$retry.log"
}

run_tquic_client_case() {
  local retry=$1
  local port
  port=$(free_udp_port)
  local server_args=()
  if [[ "$retry" == true ]]; then
    server_args+=(--retry)
  fi
  "$netz_server" "$port" "${server_args[@]}" \
    >"$work/netz-server-$retry.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    grep -q 'netz HTTP/3 tquic interop server listening' \
      "$work/netz-server-$retry.log" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then
      cat "$work/netz-server-$retry.log" >&2
      exit 1
    fi
    sleep 0.05
  done
  timeout 20s "$tquic_client" -c "127.0.0.1:$port" -a h3 \
    --max-concurrent-requests 2 --max-requests-per-conn 2 \
    --total-requests-per-thread 2 --dump-dir "$work/downloads" \
    --log-level OFF "https://localhost:$port/one.txt" \
    "https://localhost:$port/two.txt" \
    >"$work/tquic-client-$retry.log" 2>&1
  wait "$server_pid"
  server_pid=
  grep -Fq 'requests: sent 2, finish 2, success 2' \
    "$work/tquic-client-$retry.log"
  grep -Fq "netz HTTP/3 server interoperated with tquic: retry=$retry requests=2 connection_reused=true bodies=14,14" \
    "$work/netz-server-$retry.log"
  test "$(cat "$work/downloads/one.txt")" = 'netz-tquic-one'
  test "$(cat "$work/downloads/two.txt")" = 'netz-tquic-two'
  cat "$work/tquic-client-$retry.log"
  cat "$work/netz-server-$retry.log"
}

run_netz_client_case false
run_netz_client_case true
run_netz_client_graceful_case false
run_netz_client_graceful_case true
run_tquic_client_case false
run_tquic_client_case true
run_tquic_client_graceful_case false
run_tquic_client_graceful_case true
