#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
firefox=${FIREFOX:-firefox}

BROWSER_NAME=Firefox \
  BROWSER_PRODUCT=firefox \
  BROWSER_EXECUTABLE="$firefox" \
  BROWSER_CLIENT_IO=firefox-necko \
  "$repo_root/tools/interop/webtransport_chrome.sh" "$@"
