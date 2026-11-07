# C-Core xDS target and template wire oracle

This fixture compares the native owned `client_target.Resolved` with **grpcio
1.76.0 C-Core**, using actual ADS LDS subscriptions and the HTTP/2 `:authority`
received by a raw gRPC echo backend. A transparent TCP proxy captures HEADERS
before Node validates them, and pinned python-hyper `hpack` 4.1.0 independently
decodes the captured header blocks. JavaScript only encodes official Envoy
protobufs and serves the control and data planes. It does not parse targets or
implement a reference resolver.

Prepare a dedicated environment outside the source tree:

```sh
python3 -m venv /tmp/netz-grpc-client-target-venv
/tmp/netz-grpc-client-target-venv/bin/python -m pip install -r tools/interop/grpc_client_target/requirements.txt
```

The fixture reuses the pinned Node dependencies and official Envoy schemas in
`tools/interop/grpc_locality/node_modules`; prepare those separately with that
directory's lock file if necessary. The runner performs no installs or builds.
Build `emit.zig` as a native executable with the repository's `netz` module,
then pass its location and the venv interpreter explicitly:

```sh
python3 tools/interop/grpc_client_target/run.py \
  --native /path/to/prebuilt/grpc-client-target \
  --reference-python /tmp/netz-grpc-client-target-venv/bin/python \
  --output /tmp/netz-grpc-target-first/report.json
```

Each vector gets fresh Node peers and a fresh C-Core process. Both clients
consume the exact same bootstrap file containing ordinary `host:port` or
`dns:///host:port` server targets with localhost insecure credentials. Distinct
authority control ports make LDS routing observable. An authority without an
explicit server also checks fallback to the top-level server.

The explicit golden vectors cover unqualified and authority targets, custom,
repeated, constant and empty templates, percent decoding and re-encoding,
preserved colon and at-sign, query and fragment exclusion, nested decoded
paths, top-level `xdstp` templates, and a channel default-authority override.
Negative vectors require native rejection, each vector's exact C-Core status
and details, no ADS requests and no backend TCP connections. Malformed paths,
queries and fragments fail channel construction with `UNKNOWN`; an unknown
authority fails resolution with `UNAVAILABLE`. The resolver oracle requires
the expected LDS name and scope, the full LDS/inline-RDS/CDS/EDS chain with
successful ACKs and agreement on independently decoded `:authority`.

Three vectors preserve a literal `@` in data authority. C-Core emits those
headers, and Node rejects their userinfo authority before calling the backend
application. These cases require the exact emitted authority, a captured
HTTP/2 `PROTOCOL_ERROR` rejection, no backend callback, and C-Core's exact
`UNAVAILABLE`/`Socket closed` result. The other resolved vectors require one
echoed payload and no HTTP/2 rejection. Reports distinguish successful echo,
authority rejection after LDS, and invalid-target rejection.

RPCs have a 5-second default deadline (negative RPCs at most 2 seconds), peer
startup and shutdown have fixed deadlines, and each peer has a watchdog.
`--case` selects individual vectors; repeat it for several. `--timeout` accepts
1 to 10 seconds. Each output path must have a fresh sibling case directory so
old evidence cannot be reused accidentally.

The report records all failures, native and reference outputs, ADS and backend
transcripts, exact bootstraps, native/Python/Node executable hashes, the C-Core
extension hash, raw TCP/HPACK evidence and decoder dependency hashes,
repository and fixture source hashes, Node dependency versions
and metadata hashes, and the imported official protobuf schema closure hashes.
Case files remain available even after a failed assertion. A passing run is
limited to target/template resolution and the C-Core data authority; native
federated runtime transport is covered by its own production gates.
