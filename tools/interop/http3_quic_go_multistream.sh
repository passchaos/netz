#!/usr/bin/env bash
set -euo pipefail

client=${1:?netz HTTP/3 benchmark client executable path}
server=${2:?netz HTTP/3 benchmark server executable path}
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
runs=${NETZ_HTTP3_MULTISTREAM_ITERATIONS:-5}
warmup=${NETZ_HTTP3_MULTISTREAM_WARMUP:-2}
stream_values=${NETZ_HTTP3_MULTISTREAM_COUNTS:-"4 16"}
version_values=${NETZ_HTTP3_MULTISTREAM_VERSIONS:-"1 2"}
body_bytes=${NETZ_HTTP3_MULTISTREAM_BODY_BYTES:-262144}
chunk_bytes=${NETZ_HTTP3_MULTISTREAM_CHUNK_BYTES:-16384}
stream_window=${NETZ_HTTP3_MULTISTREAM_WINDOW:-1048576}
timeout_ms=${NETZ_HTTP3_MULTISTREAM_TIMEOUT_MS:-30000}

if (( runs < 1 || warmup < 1 || body_bytes < 1 || chunk_bytes < 1 ||
      chunk_bytes > body_bytes || stream_window < 1 || timeout_ms < 1 )); then
  echo 'invalid HTTP/3 multi-stream benchmark configuration' >&2
  exit 2
fi

for version in $version_values; do
  if [[ $version != 1 && $version != 2 ]]; then
    echo "unsupported HTTP/3 multi-stream QUIC version: $version" >&2
    exit 2
  fi
  for streams in $stream_values; do
    if [[ $streams != 4 && $streams != 16 ]]; then
      echo "unsupported HTTP/3 multi-stream count: $streams" >&2
      exit 2
    fi
    NETZ_HTTP3_INTEROP_VERSION="$version" \
      "$repo_root/tools/interop/http3_quic_go.sh" \
      "$client" "$server" --bench \
      "--warmup=$warmup" "--iterations=$runs" "--streams=$streams" \
      "--body-bytes=$body_bytes" "--chunk-bytes=$chunk_bytes" \
      "--stream-window=$stream_window" "--timeout-ms=$timeout_ms"
  done
done
