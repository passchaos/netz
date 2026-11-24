# Shared system DNS scheduling — 2026-11-25

Common, proxy and HTTP/3 full-address lookup each owned separate copies of the
same DNS queue/deadline algorithm. Their `async` calls could execute lookup or
collection inline when async quota was exhausted, delaying admission of the
timeout task. Inline DNS production could also fill the 16-result queue before
its consumer ran. Native Threaded DNS backends emit addresses through
`Queue.putOne`, including each address returned by Darwin's `getaddrinfo` list.

Nine deterministic tests use an ordinary Threaded executor with zero async
quota and a controlled `netLookup` implementation, keeping clocks, cancellation
and task scheduling on the real executor. For each of the three entry points:

- A 600-ms cancellable lookup under an 80-ms deadline returns
  `UnknownHostName` on the baseline instead of `Timeout` / `HandshakeTimeout`.
- A producer emits 41 records containing 40 unique addresses. The baseline
  blocks on its result queue; a 250-ms watchdog cancels and joins it so the
  failed regression remains bounded.
- With concurrent admission disabled, the baseline still enters DNS and
  returns `UnknownHostName` instead of `ConcurrencyUnavailable`.

All nine fail on the baseline: 52/61 selected tests pass. After the fix all
61/61 pass. The common resolver owns the timeout/collection competition and
explicitly admits its tasks concurrently. A shared lookup module owns the
producer, queue consumer and cancellation/drain cleanup. Proxy resolution is a
thin alias and H3 retains only its timeout mapping and URI identity handling.
The original H3 stack-first collector is extracted unchanged in algorithm and
reused by the common/proxy paths, including spill OOM and complete-result checks.

Additional checks reject foreign-clock deadlines before DNS and retain H3
literal routing when concurrency is unavailable. A composition regression
delegates an application resolver to system DNS and verifies both concurrent
admission failure and HTTP/3 timeout mapping. The common application/system
resolver error contract includes `ConcurrencyUnavailable`. Native Linux/Windows
CI includes the new cases in
the existing H3 resolver/acquisition step.

```sh
zig build test-http3 '-Dtest-filter=HTTP3 system resolver' -j1 --summary all
zig build test-http3 test-http1 test-http2 test-websocket test-proxy '-Dtest-filter=HTTP3 system resolver' '-Dtest-filter=HTTP/3 URI address collection' '-Dtest-filter=HTTP/3 URI lookup collector' '-Dtest-filter=HTTP/3 URI hostname resolution' '-Dtest-filter=HTTP3 application resolver' '-Dtest-filter=HTTP3 address attempt timeout' '-Dtest-filter=HTTP/3 shared acquisition deadline' '-Dtest-filter=HTTP/3 shared synchronous acquire' '-Dtest-filter=client connects by host name' '-Dtest-filter=WebSocket URI resolver' '-Dtest-filter=WebSocket redirect chain retains resolver' '-Dtest-filter=resolve localhost' '-Dtest-filter=resolve rejects' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline zero-async scheduling regressions | 52/61 passed; all 9 new cases fail | [before.log](before.log) |
| Shared concurrent DNS implementation | 61/61 passed | [after.log](after.log) |
| Final callback delegation, H3 collection/budgets and H1/H2/WS/proxy overlap | 215/215 passed | [Debug.log](Debug.log) |
