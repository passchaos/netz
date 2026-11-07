# WebTransport application-protocol negotiation

WebTransport CONNECT owns the offered application-protocol identifiers and
selects the first client preference supported by the server. Responses encode
the selection as a structured-field string in `WT-Protocol`. Required
negotiation with no overlap returns HTTP 406 before admitting application
streams or DATAGRAMs.

The independent `interop-webtransport-protocol` gate uses the reviewed
`web-transport-quinn` reference client. Its `Session.protocol()` validates the
actual negotiated value after CONNECT. Both peers exchange application data
for the accepted cases and capture the encoded negotiation fields.

| Case | Required result |
| --- | --- |
| Offers `p2`, `p1`, with overlapping server support | Select `p2` at both endpoints |
| Identifier containing quote and backslash | Exact decoded identifier and structured-field escaping |
| Required negotiation without overlap | HTTP 406, zero application streams/DATAGRAMs |
| Successful response missing a required selection | CONNECT reset/stop with `WT_ALPN_ERROR` |
| Successful response selecting an unoffered protocol | Same scoped error, existing sibling remains usable |

An independent Quinn peer deliberately emits the two invalid successful
responses on a reused HTTP/3 connection. It observes exact CONNECT reset/stop
code `0x0817b3dd` and optimistic unidirectional-stream stop code `0x170d7b68`
before echoing the healthy sibling's next barrier DATAGRAM. The same connection
then admits escaped and new protocol-bearing Sessions. The native endpoint
retains one Session after each rejection and completes five DATAGRAM exchanges
and one bidirectional stream exchange.

The reference transport profile is legacy WebTransport. These checks establish
application-protocol negotiation and scoped rejection on that profile;
draft-16 flow-control coverage remains in its dedicated native/runtime gates.
The reference commit, locked Cargo dependencies, executable/source hashes,
raw QPACK field bytes and decoded strings are recorded under
`docs/evidence/webtransport_protocol/2026-11-07/`. The fixture's independent
field decoder uses pinned `hpack` Huffman decoding for static/literal QPACK
representations. The gate runner accepts prebuilt native/reference peers.
Both Debug and ReleaseSafe native peers passed the independent negotiation and
rejection scenarios against the same locked release Rust peer.
