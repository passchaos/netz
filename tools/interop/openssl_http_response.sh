#!/usr/bin/env bash
# Shared application response for OpenSSL TLS interoperability servers.

write_openssl_http_response() {
  local directory=${1:?fixture directory}
  local body=${2:?response body}
  local LC_ALL=C
  printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "${#body}" "$body" >"$directory/interop-response.http"
}
