#!/usr/bin/env bash
# Independent TUIC v5 gate: sing-box client -> netz QUIC server -> HTTP/UDP target.
set -euo pipefail

server_bin=${1:?netz TUIC server executable}
sing_box=${SING_BOX_BIN:-$(command -v sing-box || true)}
if [[ -z $sing_box || ! -x $sing_box ]]; then
  echo 'sing-box not found; set SING_BOX_BIN' >&2
  exit 127
fi

uuid=00000000-0000-4000-8000-000000000003
password=netz-tuic-interop
udp_mode=${TUIC_UDP_RELAY_MODE:-native}
if [[ $udp_mode != native && $udp_mode != quic ]]; then
  echo 'TUIC_UDP_RELAY_MODE must be native or quic' >&2
  exit 2
fi
work=$(mktemp -d)
http_pid=
udp_pid=
server_pid=
sing_pid=
cleanup() {
  [[ -n $sing_pid ]] && kill "$sing_pid" 2>/dev/null || true
  [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null || true
  [[ -n $udp_pid ]] && kill "$udp_pid" 2>/dev/null || true
  [[ -n $http_pid ]] && kill "$http_pid" 2>/dev/null || true
  wait "$sing_pid" "$server_pid" "$udp_pid" "$http_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

printf 'netz-tuic-interop-ok\n' >"$work/test.txt"
python3 - "$work/large.bin" <<'PYFILE'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes(range(256)) * 512)
PYFILE
cat >"$work/http_target.py" <<'PYTARGET'
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
ThreadingHTTPServer(('127.0.0.1',18451),Handler).serve_forever()
PYTARGET
(cd "$work" && exec python3 http_target.py >/dev/null 2>&1) &
http_pid=$!

cat >"$work/udp_echo.py" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 18453))
while True:
    data, peer = sock.recvfrom(65535)
    sock.sendto(data, peer)
PY
python3 "$work/udp_echo.py" >/dev/null 2>&1 &
udp_pid=$!

"$server_bin" \
  --bind=127.0.0.1:18452 \
  --uuid="$uuid" \
  --password="$password" \
  --allow-all >/dev/null 2>&1 &
server_pid=$!

cat >"$work/sing-box.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 18450 }
  ],
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-out",
      "server": "127.0.0.1",
      "server_port": 18452,
      "uuid": "$uuid",
      "password": "$password",
      "udp_relay_mode": "$udp_mode",
      "tls": {
        "enabled": true,
        "server_name": "localhost",
        "insecure": true,
        "alpn": ["h3"]
      }
    }
  ]
}
EOF
"$sing_box" run -c "$work/sing-box.json" >/dev/null 2>&1 &
sing_pid=$!

for _ in $(seq 1 80); do
  if curl -sS --max-time 1 --socks5-hostname 127.0.0.1:18450 \
    http://127.0.0.1:18451/test.txt >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
body=$(curl -sS --max-time 5 --socks5-hostname 127.0.0.1:18450 \
  http://127.0.0.1:18451/test.txt)
expected='netz-tuic-interop-ok'
if [[ $body != "$expected" ]]; then
  echo "unexpected TUIC TCP response: $body" >&2
  exit 1
fi

curl -sS --max-time 15 --socks5-hostname 127.0.0.1:18450 \
  http://127.0.0.1:18451/large.bin -o "$work/large.reply"
cmp "$work/large.bin" "$work/large.reply"
for sample in $(seq 1 9); do
  curl -sS --max-time 15 --socks5-hostname 127.0.0.1:18450 \
    http://127.0.0.1:18451/large.bin -o "$work/large.reply" \
    -w "record=tuic-transfer direction=download sample=$sample time_total=%{time_total} size_download=%{size_download}\n"
  cmp "$work/large.bin" "$work/large.reply"
done
for sample in $(seq 1 9); do
  curl -sS --max-time 15 --socks5-hostname 127.0.0.1:18450 \
    --data-binary "@$work/large.bin" http://127.0.0.1:18451/echo \
    -o "$work/large.reply" \
    -w "record=tuic-transfer direction=upload_echo sample=$sample time_total=%{time_total} size_download=%{size_download}\n"
  cmp "$work/large.bin" "$work/large.reply"
done

cat >"$work/socks_udp.py" <<'PY'
import socket
import struct
import sys

proxy = ("127.0.0.1", 18450)
target = ("127.0.0.1", 18453)
payload = b"netz-tuic-udp-ok"

tcp = socket.create_connection(proxy, timeout=5)
tcp.sendall(b"\x05\x01\x00")
reply = tcp.recv(2)
if reply != b"\x05\x00":
    sys.exit("socks greeting failed: %r" % (reply,))
tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
reply = tcp.recv(10)
if len(reply) < 10 or reply[0] != 5 or reply[1] != 0:
    sys.exit("socks udp associate failed: %r" % (reply,))
relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(5)
packet = b"\x00\x00\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]) + payload
udp.sendto(packet, relay)
data, _ = udp.recvfrom(65535)
if len(data) < 10 or data[3] != 1 or data[10:] != payload:
    sys.exit("socks udp payload mismatch: %r" % (data,))
print("udp-ok")
PY
udp_body=$(python3 "$work/socks_udp.py")
if [[ $udp_body != "udp-ok" ]]; then
  echo "unexpected TUIC UDP result: $udp_body" >&2
  exit 1
fi

echo "record=verified protocol=tuic transport=quic udp_relay_mode=$udp_mode role_pair=sing-box-client+netz-server tcp_bytes=${#expected} large_tcp_bytes=131072 udp_bytes=17 complete=true"
