#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <http3-fetch-executable>" >&2
    exit 2
fi

fetch=$1
timeout_seconds=${NETZ_HTTP3_PUBLIC_TIMEOUT_SECONDS:-45}

run_fetch() {
    label=$1
    shift
    echo "HTTP/3 public interop: $label"
    timeout "${timeout_seconds}s" "$fetch" "$@"
}

run_fetch "ByteDance/Tengine verified HEAD" \
    '--alt-svc=h3=":443"; ma=2592000' \
    --verify --head --expect-status=200 \
    https://robotics.bytedance.com/

run_fetch "Cloudflare verified GET and cross-signed anchor" \
    '--alt-svc=h3=":443"; ma=86400' \
    --verify --expect-status=200 --min-body-bytes=100000 \
    https://cloudflare-quic.com/

run_fetch "quiche verified GET on UDP/8443" \
    '--alt-svc=h3=":8443"; ma=86400' \
    --verify --expect-status=200 --min-body-bytes=400 \
    https://quic.tech/

run_fetch "Meta verified redirect" \
    '--alt-svc=h3=":443"; ma=86400' \
    --verify --head --expect-status=302 \
    https://www.facebook.com/
