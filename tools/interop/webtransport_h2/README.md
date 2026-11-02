# Independent WebTransport over HTTP/2 peer

Run the bidirectional draft-15 gate with:

```sh
zig build interop-webtransport-h2-python -Doptimize=ReleaseFast --summary all
```

`uv`, Python 3.10 or newer, and OpenSSL must be available. The script pins
hyper-h2 4.3.0, hpack 4.1.0, and hyperframe 6.1.0 through PEP 723; uv resolves
them in its isolated cache. OpenSSL creates a one-day CA and server identity.
Both directions require certificate-verified TLS 1.3 and `h2` ALPN. The Netz
driver obtains `std.Io` from the production zio runtime.

To save the verified transcript, binary digest, and source digests:

```sh
zig build interop-webtransport-h2-python -Doptimize=ReleaseFast -- \
  --report /tmp/webtransport-h2-result.json
```

`wire.py` implements Capsule integers and envelopes directly from sections 6
and 11 of [draft-ietf-webtrans-http2-15](https://www.ietf.org/archive/id/draft-ietf-webtrans-http2-15.txt).
Fixed vectors check all integer-width boundaries, non-minimal integers,
every split of a STREAM/FIN capsule, truncated CONNECT FIN, and 16-bit SETTINGS.
The Python peer uses hyper-h2 for HTTP/2 stream state, HPACK and HTTP/2 flow
control. Hyperframe 6.1.0 masks outgoing SETTINGS identifiers to eight bits;
the peer independently encodes its initial SETTINGS frame with the full
RFC 9113 identifier while retaining hyper-h2's settings and ACK state.

For each Netz client/server direction, one TLS connection carries:

1. A rejected CONNECT with a complete 429 body and trailers. The Python client
   sends optimistic request DATA and checks `RST_STREAM(NO_ERROR)` after the
   response, as permitted by RFC 9113 section 8.1.
2. An accepted Session with exact application protocol and asymmetric Init
   limits. A 200-byte write exhausts both initial Session and virtual-stream
   credit, then resumes after separate MAX_DATA and MAX_STREAM_DATA grants.
   An unrelated DATAGRAM remains available during that wait. The peer splits
   Capsule envelopes and payloads across independent HTTP/2 DATA frames and
   inserts unknown capsules and non-zero PADDING.
3. Bidirectional streams initiated by both roles, unidirectional delivery,
   DATAGRAM, RESET code 42 with Reliable Size 6, STOP code `0xffffffff` with
   a matching RESET, stream-count grants, DRAIN, and exact Unicode CLOSE/FIN.
4. A second accepted Session with a deliberately wrong RESET Reliable Size.
   Netz must return StreamStateError and reset only that CONNECT. A third
   accepted Session then exchanges DATAGRAM and CLOSE on the same connection.
   In the Netz client direction this final Session uses the background
   `EndpointClient` command queue, checking queued CONNECT, DATAGRAM, receive,
   owned results and continued reuse after the preceding Session error.

The runner fails on missing transcript steps, wrong payloads/codes, incomplete
capsules, unexpected connection termination, failed subprocesses, or Python
assertions disabled by optimization. This is an independent scripted protocol
peer; broader draft conformance and browser/proxy deployment matrices remain
separate evidence requirements.
