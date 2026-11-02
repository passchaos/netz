# Selected-cluster admission interop

Run `zig build interop-grpc-cluster-impl --summary all`, optionally with
`-- --output <report.json>`.

The gate executes actual grpc-js-xds cluster-impl pickers, then native ordinary
and shared channels against grpc-js A/B backends. It verifies independent
cluster admission, a quota raise while a stream holds capacity, EDS category
precedence, pre-wire stream/unary drops and terminal permit release. Each mode
must deliver exactly five RPCs; shared updates preserve two A transports and
one B transport, while ordinary replacement channel instances use three A
transports and one B transport.
