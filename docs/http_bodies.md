# Unified HTTP request bodies and replay

`http.Client`, `http.Connection` and `http.Pool` use the same
`http.RequestOptions` body source. `body_source` takes precedence over `body`
for H1, H2 and H3, including ordinary shared H2 Pool requests.

```zig
var reader = std.Io.Reader.fixed("request content");
var response = try pool.requestUriWithTimeout(uri, .{
    .method = "POST",
    .body_source = .{ .reader = .{
        .reader = &reader,
        .length = "request content".len,
    } },
}, .fromSeconds(10));
defer response.deinit();
```

Use `body` or `body_source.slice` for borrowed bytes. Use
`body_source.reader` for incremental production; omit `length` when it is
unknown. A declared length must match the produced content. Trailers remain
available with either source. `RequestOptions.bodySource()` resolves precedence,
and `bodyLength()` additionally applies a manual duplex length declaration.

Ordinary shared H2 requests retain at most one source chunk per active Reader,
capped at 16 KiB and the configured upload quantum. Source I/O runs in its own
task while one connection owner retains frame/HPACK/output ownership. A blocked
Reader therefore permits later sibling requests. Partial flow-control writes
retain the unsent source suffix; a later read cannot overwrite it. Cancellation
and early response cleanup join the producer before returning to the caller.
Readers doing I/O must cooperate with `std.Io` cancellation, and their backing
storage must outlive the request call. Sharing one Reader between simultaneous
requests is not supported.

## Explicit replay

A slice can be replayed. A Reader is single-pass by default: classifying PUT or
GET as idempotent does not reconstruct consumed bytes. Automatic stale-socket
retry and H3-to-TCP fallback therefore require a replayable body in addition
to their existing method/error policy.

Provide `ReaderBody.replay` only when the complete content can be reproduced:

```zig
const Source = struct {
    bytes: []const u8,

    fn rewind(context: ?*anyopaque, reader: *std.Io.Reader) std.Io.Reader.Error!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        reader.* = .fixed(self.bytes);
    }
};

var source = Source{ .bytes = "repeatable content" };
var reader = std.Io.Reader.fixed(source.bytes);
const request: http.RequestOptions = .{
    .method = "PUT",
    .body_source = .{ .reader = .{
        .reader = &reader,
        .length = source.bytes.len,
        .replay = .{ .context = &source, .rewind = Source.rewind },
    } },
};
```

The runtime calls `rewind` only after the prior attempt has stopped reading,
and before another attempt can consume the source. The callback must restore
the complete original content and length, including any state behind the
Reader. A callback error is returned without opening the replacement attempt.
`BodySource.isReplayable()` reports the declaration; `prepareReplay()` performs
that reset for application adapters following their own retry policy.

Reader-backed redirect following accepts the same explicit replay declaration.
Preserving 307/308-style hops reset the source, while a rewrite-to-GET clears
the body without replay. A single-pass Reader is rejected before the initial
redirect-following operation, retaining the existing deterministic preflight.
Reader I/O failures are reported as `RequestBodyReadFailed`, separately from
transport failures. They do not trigger a stale retry, H3 fallback or failed
alternative backoff. Inspect the Reader implementation for its detailed error.

Method safety, credential isolation, downgrade and whole-chain deadline rules
continue to apply independently.

## Duplex writes

`startRequest` declares a manual body length and returns a streaming handle.
The caller writes bytes, then ends with `finishBody` or `finishTrailers` and
consumes the response through `ResponseSink`. The same `http.Header` type is
used for ordinary fields, trailer declarations, finishing trailers and response
callbacks; `DuplexHeader` remains an alias. See [streaming](http_streaming.md)
for the connection/pool ownership and callback lifetime contracts.

Manual `writeBodyFromReaderWithDeadline`/`WithTimeout` calls cover both source
waits and output. They retain an unaccepted suffix inside the handle, so a later
call with the same Reader can continue a usable writer without losing source
bytes. Ordinary complete-request calls end their attempt on failure; automatic
replay still requires the explicit rewind declaration above. Response bodies
can stream directly into `ResponseSink.toWriter(&writer)` or be drained through
`ResponseSink.discard()`.

The fixed HTTP/1 forward-proxy path currently rejects Reader and duplex
uploads. The supported native direct/pool paths and replay declaration do not
bypass proxy routing or change that separate transport boundary.
