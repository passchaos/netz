# HTTP forms and streaming request bodies

Netz provides two application-layer form encoders:

- `netz.http.form` for `application/x-www-form-urlencoded`
- `netz.http.multipart` for streaming `multipart/form-data`

Both are bounded and allocation-explicit. Multipart bodies can be streamed
through the high-level client without buffering a file in memory.

## URL-encoded forms

```zig
const form = netz.http.form;

var buffer: [1024]u8 = undefined;
const body = try form.encode(&buffer, &.{
    .{ .name = "name", .value = "a b" },
    .{ .name = "plus", .value = "+&=%" },
});
```

`encode` returns `error.BufferTooSmall` instead of allocating. `encodeAlloc` is
available when the caller wants an owned buffer. `decodeAlloc` returns one
owned storage block for all decoded names and values and enforces
`DecodeOptions` limits.

Decoding rejects malformed `%XX` escapes; `+` decodes to a space.

## Multipart writer

```zig
var storage: [4096]u8 = undefined;
var writer = std.Io.Writer.fixed(&storage);

const parts = [_]netz.http.multipart.Part{
    .{ .name = "field", .body = .{ .slice = "value" } },
    .{
        .name = "upload",
        .filename = "a.txt",
        .content_type = "text/plain",
        .body = .{ .slice = "hello" },
    },
};

try netz.http.multipart.write(&writer, "----netz-boundary", &parts);
```

For streaming files, use `Body.reader`:

```zig
var file_reader = ...;
const parts = [_]netz.http.multipart.Part{.{
    .name = "upload",
    .filename = "large.bin",
    .body = .{ .reader = &file_reader },
}};
```

`multipart.contentLength` returns the exact length when every part is a slice,
and `null` when any part is reader-backed. `multipart.Reader` is a pull-based
`std.Io.Reader` that produces the same bytes as `multipart.write`.

## Sending a multipart form

```zig
var form_reader = try netz.http.multipart.Reader.init(&parts, boundary);
var content_type_buffer: [128]u8 = undefined;
const content_type = try netz.http.multipart.contentType(
    &content_type_buffer,
    boundary,
);

var response = try client.requestUri(uri, .{
    .method = "POST",
    .headers = &.{.{ .name = "content-type", .value = content_type }},
    .body_source = .{ .reader = .{ .reader = &form_reader.reader } },
});
```

`body_source` takes precedence over `body`. HTTP/1 uses chunked framing when
the reader length is unknown; HTTP/2 streams DATA frames. The HTTP/3 pool does
not stream reader bodies directly: it returns
`error.StreamingBodyUnsupported` before opening a stream and falls back to TCP
when the pool's fallback policy allows it. With fallback disabled, use a slice
body.

Reader-backed bodies are also rejected by redirect following and by the
HTTP/1 forward-proxy path, because those paths may need to replay or rewrite
the request body. Use a slice body, or drive the redirect/proxy manually.

The reader and its backing storage must outlive the request call. A
`multipart.Reader` reports encoding failures as `error.ReadFailed`; call
`takeError()` on the reader to inspect the specific encoder error.


## Parsing multipart forms

```zig
var parsed = try netz.http.multipart.parseAlloc(
    allocator,
    request.body,
    request.header("content-type").?,
    .{ .max_part_bytes = 8 * 1024 * 1024 },
);
defer parsed.deinit();

for (parsed.parts) |part| {
    // part.name, part.filename, part.content_type, part.body
}
```

The parser borrows part bodies from the input slice and owns only the
`Part`/`Header` arrays plus unescaped disposition values. It enforces limits on
part count, headers per part, header bytes, part size, total body size, preamble,
epilogue, and name/filename length. `filename*` is rejected as an unsupported
parameter, and nested `multipart/*` parts are rejected unless
`allow_nested = true`.

`multipart.parseWithBoundary` skips Content-Type parsing when the caller already
has the boundary. `multipart.contentTypeBoundary` parses only the boundary
parameter. The parser is exercised by the `fuzz-parsers` target with a
dedicated multipart seed.

## Limits and validation

Multipart encoding rejects:

- CR, LF, or NUL in names, filenames, content types, or extra header values;
- invalid header names;
- boundaries outside 1-70 printable ASCII bytes, or containing `"`/`\`;
- part headers larger than `max_part_header_bytes` when using the pull reader.

Names and filenames are quoted and backslash-escaped. Server-side filename
sanitization and a multipart parser are deliberately not part of this encoder.
