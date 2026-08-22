#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/tools/hyper_http1_body/Cargo.toml"

features=()
for argument in "$@"; do
    if [[ "$argument" == "--stats" ]]; then
        features=(--features allocation-stats)
        break
    fi
done

cargo build --release --offline --locked --manifest-path "$manifest" "${features[@]}"
exec "$repo_root/tools/hyper_http1_body/target/release/netz-hyper-http1-body" "$@"
