#!/usr/bin/env bash
set -euo pipefail

bridge=${1:?netz outbound bridge executable path}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

. "$repo_root/tools/interop/mosquitto_build.sh"
mosquitto=$(resolve_mosquitto)
python3 "$repo_root/tools/interop/mqtt_outbound_bridge_mosquitto.py" \
  "$bridge" "$mosquitto" \
  --mosquitto-test-root "$mosquitto_root/test"
