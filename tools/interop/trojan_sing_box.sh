#!/usr/bin/env bash
# Independent Trojan gate: sing-box client -> netz TLS server -> HTTP target.
set -euo pipefail

server_bin=${1:?netz Trojan server executable}
sing_box=${SING_BOX_BIN:-$(command -v sing-box || true)}
if [[ -z $sing_box || ! -x $sing_box ]]; then
  echo 'sing-box not found; set SING_BOX_BIN' >&2
  exit 127
fi

password=netz-trojan-interop
transport=${TROJAN_TRANSPORT:-tls}
if [[ $transport != tls && $transport != ws ]]; then
  echo 'TROJAN_TRANSPORT must be tls or ws' >&2
  exit 2
fi
transport_json=
if [[ $transport == ws ]]; then
  transport_json=', "transport": { "type": "ws", "path": "/" }'
fi
work=$(mktemp -d)
http_pid=
server_pid=
sing_pid=
cleanup() {
  [[ -n $sing_pid ]] && kill "$sing_pid" 2>/dev/null || true
  [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null || true
  [[ -n $http_pid ]] && kill "$http_pid" 2>/dev/null || true
  wait "$sing_pid" "$server_pid" "$http_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

printf 'netz-trojan-interop-ok\n' >"$work/test.txt"
(cd "$work" && exec python3 -m http.server 18445 --bind 127.0.0.1 >/dev/null 2>&1) &
http_pid=$!
"$server_bin" \
  --bind=127.0.0.1:18443 \
  --password="$password" \
  --transport="$transport" \
  --allow-all >/dev/null 2>&1 &
server_pid=$!
cat >"$work/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 18444 }
  ],
  "outbounds": [
    {
      "type": "trojan",
      "tag": "trojan-out",
      "server": "127.0.0.1",
      "server_port": 18443,
      "password": "$password",
      "tls": {
        "enabled": true,
        "server_name": "localhost",
        "insecure": true
      }$transport_json
    }
  ]
}
EOF
"$sing_box" run -c "$work/sing-box.json" >/dev/null 2>&1 &
sing_pid=$!

for _ in $(seq 1 50); do
  if curl -sS --max-time 1 --socks5-hostname 127.0.0.1:18444 \
    http://127.0.0.1:18445/test.txt >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
body=$(curl -sS --max-time 5 --socks5-hostname 127.0.0.1:18444 \
  http://127.0.0.1:18445/test.txt)
expected='netz-trojan-interop-ok'
if [[ $body != "$expected" ]]; then
  echo "unexpected Trojan response: $body" >&2
  exit 1
fi
echo "record=verified protocol=trojan transport=$transport role_pair=sing-box-client+netz-server bytes=${#expected} complete=true"
