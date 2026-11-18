const std = @import("std");
const http1_root = @import("mod.zig");
const early_data = @import("../http/early_data.zig");
const wire = @import("../internal/wire.zig");

const BodyFraming = http1_root.BodyFraming;
const Error = http1_root.Error;
const Header = http1_root.Header;
const LineIterator = http1_root.LineIterator;
const Method = http1_root.Method;
const Version = http1_root.Version;
const absoluteFormAuthority = http1_root.absoluteFormAuthority;
const bodyFraming = http1_root.bodyFraming;
const decodeChunked = http1_root.decodeChunked;
const encodeChunked = http1_root.encodeChunked;
const max_chunk_extension_bytes = http1_root.max_chunk_extension_bytes;
const max_chunk_size_line_bytes = http1_root.max_chunk_size_line_bytes;
const parseChunkSize = http1_root.parseChunkSize;
const parseCompatibleHeadLines = http1_root.parseCompatibleHeadLines;
const parseHeaderLinesNoFold = http1_root.parseHeaderLinesNoFold;
const parseRequest = http1_root.parseRequest;
const parseRequestHead = http1_root.parseRequestHead;
const parseResponse = http1_root.parseResponse;
const parseResponseForRequest = http1_root.parseResponseForRequest;
const parseResponseHead = http1_root.parseResponseHead;
const parseStrictHeadLines = http1_root.parseStrictHeadLines;
const parseTrailerFields = http1_root.parseTrailerFields;
const requestAcceptsTrailers = http1_root.requestAcceptsTrailers;
const responseTransferEncodingIsCloseDelimited = http1_root.responseTransferEncodingIsCloseDelimited;
const statusCodeForbidsBody = http1_root.statusCodeForbidsBody;
const validateConnectTarget = http1_root.validateConnectTarget;
const validateHeader = http1_root.validateHeader;
const validateHostValue = http1_root.validateHostValue;
const validateReasonPhrase = http1_root.validateReasonPhrase;
const validateRequestHead = http1_root.validateRequestHead;
const validateRequestHost = http1_root.validateRequestHost;
const validateRequestTarget = http1_root.validateRequestTarget;
const validateRequestTargetForMethod = http1_root.validateRequestTargetForMethod;
const validateStatusCode = http1_root.validateStatusCode;
const validateTrailers = http1_root.validateTrailers;
const validHeaderNameByte = http1_root.validHeaderNameByte;
const writeRequest = http1_root.writeRequest;
const writeRequestChecked = http1_root.writeRequestChecked;
const writeResponse = http1_root.writeResponse;
const writeResponseChecked = http1_root.writeResponseChecked;

test "HTTP/1 request parse and serialize" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nContent-Length: 5\r\n\r\nhello";
    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expect(req.method == .GET);
    try std.testing.expectEqualStrings("/chat", req.target);
    try std.testing.expectEqual(BodyFraming.content_length, req.body_framing);
    try std.testing.expectEqualStrings("hello", req.body);
    try std.testing.expect(wire.containsToken(req.header("connection").?, "upgrade"));
    try std.testing.expectEqualStrings("websocket", req.upgradeProtocol().?);

    var no_alloc_parse = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    var get_no_body = try parseRequest(no_alloc_parse.allocator(), "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", .{});
    defer get_no_body.deinit(no_alloc_parse.allocator());
    try std.testing.expect(!no_alloc_parse.has_induced_failure);
    try std.testing.expectEqualStrings("example.com", get_no_body.header("host").?);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writeRequest(&out, allocator, req.method, req.target, req.version, req.headers, req.body);
    try std.testing.expectEqualStrings(raw, out.items);

    var no_alloc_out: std.ArrayList(u8) = .empty;
    defer no_alloc_out.deinit(allocator);
    try no_alloc_out.ensureTotalCapacity(allocator, raw.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeRequest(&no_alloc_out, no_alloc.allocator(), req.method, req.target, req.version, req.headers, req.body);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(raw, no_alloc_out.items);

    var one_alloc_out: std.ArrayList(u8) = .empty;
    var one_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const one_alloc_allocator = one_alloc.allocator();
    defer one_alloc_out.deinit(one_alloc_allocator);
    try writeRequest(&one_alloc_out, one_alloc_allocator, req.method, req.target, req.version, req.headers, req.body);
    try std.testing.expect(!one_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(raw, one_alloc_out.items);
}

test "HTTP/1 methods accept case-sensitive RFC token extensions" {
    const allocator = std.testing.allocator;

    const query = try Method.parse("QUERY");
    try std.testing.expect(query == .QUERY);
    try std.testing.expect(query.safe());
    try std.testing.expect(query.idempotent());

    const lowercase_get = try Method.parse("get");
    try std.testing.expectEqualStrings("get", lowercase_get.string());
    try std.testing.expect(!lowercase_get.safe());
    try std.testing.expect(!lowercase_get.idempotent());
    switch (lowercase_get) {
        .extension => {},
        else => return error.TestUnexpectedResult,
    }

    const all_token_symbols = try Method.parse("!#$%&'*+-.^_`|~Az09");
    try std.testing.expectEqualStrings(
        "!#$%&'*+-.^_`|~Az09",
        all_token_symbols.string(),
    );

    const invalid = [_][]const u8{
        "",
        "BAD METHOD",
        "BAD:METHOD",
        "BAD/METHOD",
        "BAD\tMETHOD",
        "BAD\x7fMETHOD",
        "M\xc3\x89THOD",
    };
    for (invalid) |bytes| {
        try std.testing.expectError(error.InvalidMethod, Method.parse(bytes));
    }

    const raw =
        "PURGE /cache HTTP/1.1\r\n" ++
        "Host: example.com\r\n\r\n";
    var request = try parseRequest(allocator, raw, .{});
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("PURGE", request.method.string());
    switch (request.method) {
        .extension => |bytes| try std.testing.expectEqualStrings("PURGE", bytes),
        else => return error.TestUnexpectedResult,
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeRequestChecked(
        &encoded,
        allocator,
        request.method,
        request.target,
        request.version,
        request.headers,
        request.body,
    );
    try std.testing.expectEqualStrings(raw, encoded.items);

    try std.testing.expectError(
        error.InvalidMethod,
        validateRequestTargetForMethod(.{ .extension = "GET" }, "/"),
    );
    try std.testing.expectError(
        error.MalformedStartLine,
        validateRequestTargetForMethod(lowercase_get, "*"),
    );
}

test "HTTP/1 low-level request writers validate framing before output" {
    const allocator = std.testing.allocator;
    const prefix = "already-written";
    const invalid_cases = [_]struct {
        expected: Error,
        method: Method = .POST,
        target: []const u8 = "/upload",
        version: Version,
        headers: []const Header,
        body: []const u8,
    }{
        .{
            .expected = error.InvalidHost,
            .version = .http_1_1,
            .headers = &.{},
            .body = "",
        },
        .{
            .expected = error.InvalidHost,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Host", .value = "example.com" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{.{ .name = "Host", .value = "example.com" }},
            .body = "body",
        },
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Content-Length", .value = "5" },
            },
            .body = "body",
        },
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Content-Length", .value = "5" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "0\r\n\r\n",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "gzip token" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Connection", .value = "close,,upgrade" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Connection", .value = "Content-Length" },
                .{ .name = "Content-Length", .value = "0" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Upgrade", .value = "websocket" },
            },
            .body = "",
        },
        .{
            .expected = error.BufferTooShort,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "5\r\nhello\r\n",
        },
        .{
            .expected = error.InvalidChunk,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "0\r\n\r\nnext",
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "0\r\nContent-Length: 0\r\n\r\n",
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Trailer", .value = "Digest" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Trailer", .value = "Digest" },
            },
            .body = "0\r\nX-Other: value\r\n\r\n",
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Trailer", .value = "Content-Length" },
            },
            .body = "0\r\n\r\n",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "TE", .value = "trailers" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "TE", .value = "chunked" },
                .{ .name = "Connection", .value = "TE" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "TE", .value = "trailers; q=1" },
                .{ .name = "Connection", .value = "TE" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidHost,
            .method = .CONNECT,
            .target = "example.com:443",
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Host",
                .value = "other.example:443",
            }},
            .body = "",
        },
        .{
            .expected = error.InvalidContentLength,
            .method = .CONNECT,
            .target = "example.com:443",
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com:443" },
                .{ .name = "Content-Length", .value = "0" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .method = .CONNECT,
            .target = "example.com:443",
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com:443" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "0\r\n\r\n",
        },
        .{
            .expected = error.InvalidContentLength,
            .method = .TRACE,
            .target = "/trace",
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Content-Length", .value = "4" },
            },
            .body = "body",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .method = .TRACE,
            .target = "/trace",
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
            .body = "0\r\n\r\n",
        },
        .{
            .expected = error.InvalidTrailer,
            .method = .TRACE,
            .target = "/trace",
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Trailer", .value = "Digest" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidExpectation,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Expect", .value = "100-continue" },
            },
            .body = "",
        },
        .{
            .expected = error.InvalidExpectation,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Host", .value = "example.com" },
                .{ .name = "Content-Length", .value = "4" },
                .{ .name = "Expect", .value = "100-continue, custom" },
            },
            .body = "body",
        },
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    for (invalid_cases) |case| {
        encoded.clearRetainingCapacity();
        try encoded.appendSlice(allocator, prefix);
        try std.testing.expectError(
            case.expected,
            writeRequest(
                &encoded,
                allocator,
                case.method,
                case.target,
                case.version,
                case.headers,
                case.body,
            ),
        );
        try std.testing.expectEqualStrings(prefix, encoded.items);

        try std.testing.expectError(
            case.expected,
            writeRequestChecked(
                &encoded,
                allocator,
                case.method,
                case.target,
                case.version,
                case.headers,
                case.body,
            ),
        );
        try std.testing.expectEqualStrings(prefix, encoded.items);
    }

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .GET,
        "/trailers",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "TE", .value = "trailers" },
            .{ .name = "Connection", .value = "keep-alive, TE" },
        },
        "",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        "TE: trailers\r\nConnection: keep-alive, TE\r\n",
    ) != null);

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .POST,
        "/expect",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Content-Length", .value = "4" },
            .{ .name = "Expect", .value = "100-continue" },
        },
        "body",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        "Expect: 100-continue\r\n",
    ) != null);

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .GET,
        "/upgrade",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Upgrade", .value = "websocket" },
        },
        "",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        "Connection: Upgrade\r\nUpgrade: websocket\r\n",
    ) != null);

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .CONNECT,
        "example.com:443",
        .http_1_1,
        &.{.{ .name = "Host", .value = "example.com:443" }},
        "",
    );
    try std.testing.expectEqualStrings(
        "CONNECT example.com:443 HTTP/1.1\r\n" ++
            "Host: example.com:443\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .TRACE,
        "/trace",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Content-Length", .value = "0" },
        },
        "",
    );
    try std.testing.expectEqualStrings(
        "TRACE /trace HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 0\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .POST,
        "/upload",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Content-Length", .value = "5" },
        },
        "hello",
    );
    try std.testing.expectEqualStrings(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "hello",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeRequest(
        &encoded,
        allocator,
        .POST,
        "/upload",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
        },
        "5\r\nhello\r\n0\r\n\r\n",
    );
    try std.testing.expectEqualStrings(
        "POST /upload HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "5\r\nhello\r\n0\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeRequestChecked(
        &encoded,
        allocator,
        .POST,
        "/upload",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Trailer", .value = "Digest" },
        },
        "5\r\nhello\r\n0\r\nDigest: sha-256=demo\r\n\r\n",
    );
    try std.testing.expect(std.mem.endsWith(
        u8,
        encoded.items,
        "5\r\nhello\r\n0\r\nDigest: sha-256=demo\r\n\r\n",
    ));
}

test "HTTP/1 low-level response writers validate framing before output" {
    const allocator = std.testing.allocator;
    const prefix = "already-written";
    const invalid_cases = [_]struct {
        expected: Error,
        status: u16 = 200,
        version: Version,
        headers: []const Header,
        body: []const u8 = "",
    }{
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Content-Length", .value = "0" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "gzip; note=\"unterminated",
            }},
        },
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Content-Length",
                .value = "not-a-number",
            }},
        },
        .{
            .expected = error.ConflictingContentLength,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Content-Length", .value = "4" },
                .{ .name = "Content-Length", .value = "5" },
            },
        },
        .{
            .expected = error.InvalidContentLength,
            .version = .http_1_1,
            .headers = &.{.{ .name = "Content-Length", .value = "5" }},
            .body = "body",
        },
        .{
            .expected = error.BufferTooShort,
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
            .body = "4\r\npong\r\n",
        },
        .{
            .expected = error.InvalidChunk,
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
            .body = "0\r\n\r\nnext",
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Transfer-Encoding", .value = "gzip" },
                .{ .name = "Trailer", .value = "Digest" },
            },
        },
        .{
            .expected = error.InvalidTrailer,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Trailer", .value = "Digest" },
            },
            .body = "0\r\nX-Other: value\r\n\r\n",
        },
        .{
            .expected = error.InvalidTransferEncoding,
            .version = .http_1_1,
            .headers = &.{.{ .name = "TE", .value = "trailers" }},
        },
        .{
            .expected = error.InvalidExpectation,
            .version = .http_1_1,
            .headers = &.{.{ .name = "Expect", .value = "100-continue" }},
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{.{
                .name = "Connection",
                .value = "keep-alive,",
            }},
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{
                .{ .name = "Connection", .value = "Transfer-Encoding" },
                .{ .name = "Transfer-Encoding", .value = "chunked" },
            },
        },
        .{
            .expected = error.InvalidConnection,
            .version = .http_1_1,
            .headers = &.{.{ .name = "Upgrade", .value = "websocket" }},
        },
        .{
            .expected = error.InvalidResponse,
            .status = 101,
            .version = .http_1_1,
            .headers = &.{},
        },
    };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    for (invalid_cases) |case| {
        encoded.clearRetainingCapacity();
        try encoded.appendSlice(allocator, prefix);
        try std.testing.expectError(
            case.expected,
            writeResponse(
                &encoded,
                allocator,
                case.version,
                case.status,
                "OK",
                case.headers,
                case.body,
            ),
        );
        try std.testing.expectEqualStrings(prefix, encoded.items);

        try std.testing.expectError(
            case.expected,
            writeResponseChecked(
                &encoded,
                allocator,
                case.version,
                case.status,
                "OK",
                case.headers,
                case.body,
            ),
        );
        try std.testing.expectEqualStrings(prefix, encoded.items);
    }

    encoded.clearRetainingCapacity();
    // Without request-method context this can be a HEAD response describing
    // the selected GET representation, so its metadata length need not equal
    // the bytes supplied to this serializer.
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        200,
        "OK",
        &.{.{ .name = "Content-Length", .value = "5" }},
        "",
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeResponse(
        &encoded,
        allocator,
        .http_1_1,
        200,
        "OK",
        &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
        "4\r\npong\r\n0\r\n\r\n",
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "4\r\npong\r\n0\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        200,
        "OK",
        &.{
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Trailer", .value = "Digest" },
        },
        "4\r\npong\r\n0\r\nDigest: sha-256=demo\r\n\r\n",
    );
    try std.testing.expect(std.mem.endsWith(
        u8,
        encoded.items,
        "4\r\npong\r\n0\r\nDigest: sha-256=demo\r\n\r\n",
    ));

    encoded.clearRetainingCapacity();
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        200,
        "OK",
        &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
        "",
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        encoded.items,
    );

    encoded.clearRetainingCapacity();
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        101,
        "Switching Protocols",
        &.{
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Upgrade", .value = "websocket" },
        },
        "",
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: websocket\r\n\r\n",
        encoded.items,
    );
}

test "HTTP/1 owned headers cross the single-pass stack boundary" {
    const common =
        "x-00: 00\r\n" ++
        "x-01: 01\r\n" ++
        "x-02: 02\r\n" ++
        "x-03: 03\r\n" ++
        "x-04: 04\r\n" ++
        "x-05: 05\r\n" ++
        "x-06: 06\r\n" ++
        "x-07: 07\r\n" ++
        "x-08: 08\r\n" ++
        "x-09: 09\r\n" ++
        "x-10: 10\r\n" ++
        "x-11: 11\r\n" ++
        "x-12: 12\r\n" ++
        "x-13: 13\r\n" ++
        "x-14: 14\r\n" ++
        "x-15: 15\r\n";
    const common_lines = LineIterator.init(common);
    var inline_headers = try parseHeaderLinesNoFold(
        std.testing.allocator,
        common_lines,
        .{ .max_headers = 17 },
        .{},
    );
    defer inline_headers.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 16), inline_headers.headers.len);
    try std.testing.expectEqualStrings(
        "15",
        inline_headers.headers[15].value,
    );

    const fallback = common ++ "x-16: 16\r\n";
    const fallback_lines = LineIterator.init(fallback);
    var fallback_headers = try parseHeaderLinesNoFold(
        std.testing.allocator,
        fallback_lines,
        .{ .max_headers = 17 },
        .{},
    );
    defer fallback_headers.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 17), fallback_headers.headers.len);
    try std.testing.expectEqualStrings(
        "16",
        fallback_headers.headers[16].value,
    );
}

test "HTTP/1 borrowed request heads parse pipelines without allocation" {
    const pipeline =
        "POST /one HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 5\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n" ++
        "hello" ++
        "GET /two HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    var headers: [8]Header = undefined;
    const first = try parseRequestHead(pipeline, &headers, .{});
    try std.testing.expect(first.method == .POST);
    try std.testing.expectEqualStrings("/one", first.target);
    try std.testing.expectEqualStrings("example.com", first.header("host").?);
    try std.testing.expect(first.keepAlive());
    try std.testing.expectEqual(BodyFraming.content_length, first.body_framing);
    const first_len = (try first.messageLength()).?;
    try std.testing.expectEqualStrings("hello", pipeline[first.head_len..first_len]);

    var second_headers: [4]Header = undefined;
    const second = try parseRequestHead(pipeline[first_len..], &second_headers, .{});
    try std.testing.expect(second.method == .GET);
    try std.testing.expectEqualStrings("/two", second.target);
    try std.testing.expectEqual(BodyFraming.none, second.body_framing);
    try std.testing.expectEqual(second.head_len, (try second.messageLength()).?);

    // There is no allocator parameter and caller-provided storage contains all
    // descriptors, so the same parse remains valid under a no-allocation policy.
    var no_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    _ = no_alloc.allocator();
    _ = try parseRequestHead(pipeline, &headers, .{});
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/1 repeated Connection fields all affect message semantics" {
    const allocator = std.testing.allocator;

    const close_request =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: keep-alive\r\n" ++
        "cOnNeCtIoN: close\r\n" ++
        "\r\n";
    var borrowed_headers: [4]Header = undefined;
    const request_head = try parseRequestHead(
        close_request,
        &borrowed_headers,
        .{},
    );
    // Generic lookup intentionally retains first-field behavior. Only token
    // consumers combine repeated list-valued fields.
    try std.testing.expectEqualStrings(
        "keep-alive",
        request_head.header("connection").?,
    );
    try std.testing.expect(!request_head.keepAlive());

    var request = try parseRequest(allocator, close_request, .{});
    defer request.deinit(allocator);
    try std.testing.expect(!request.keepAlive());

    const upgrade_request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "\r\n";
    var upgrading_request = try parseRequest(
        allocator,
        upgrade_request,
        .{},
    );
    defer upgrading_request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "websocket",
        upgrading_request.upgradeProtocol().?,
    );

    const close_response =
        "HTTP/1.1 204 No Content\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: close\r\n" ++
        "\r\n";
    var response = try parseResponse(allocator, close_response, .{});
    defer response.deinit(allocator);
    try std.testing.expect(!response.keepAlive());

    const upgrade_response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Upgrade: websocket\r\n" ++
        "\r\n";
    var switching = try parseResponse(allocator, upgrade_response, .{});
    defer switching.deinit(allocator);
    try std.testing.expectEqualStrings(
        "websocket",
        switching.upgradeProtocol().?,
    );
}

test "HTTP/1 request trailer capability combines repeated TE fields" {
    const headers = [_]Header{
        .{ .name = "TE", .value = "gzip" },
        .{ .name = "te", .value = "deflate, Trailers" },
        .{ .name = "Connection", .value = "keep-alive, TE" },
    };
    try std.testing.expect(requestAcceptsTrailers(.http_1_1, &headers));
    try std.testing.expect(!requestAcceptsTrailers(.http_1_1, &.{ .{
        .name = "TE",
        .value = "gzip, trailers;q=1",
    }, .{
        .name = "Connection",
        .value = "TE",
    } }));
    try std.testing.expect(!requestAcceptsTrailers(.http_1_1, &.{.{
        .name = "TE",
        .value = "trailers",
    }}));
    try std.testing.expect(!requestAcceptsTrailers(.http_1_1, &.{
        .{ .name = "TE", .value = "chunked, trailers" },
        .{ .name = "Connection", .value = "TE" },
    }));
}

test "HTTP/1 parser preserves exact header-name spelling across borrowed and owned heads" {
    const allocator = std.testing.allocator;

    const request_raw =
        "GET /case HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-BREAD: baguette\r\n" ++
        "\r\n";
    var borrowed_request_headers: [4]Header = undefined;
    const borrowed_request = try parseRequestHead(
        request_raw,
        &borrowed_request_headers,
        .{},
    );
    try std.testing.expectEqualStrings("Host", borrowed_request.headers[0].name);
    try std.testing.expectEqualStrings(
        "X-BREAD",
        borrowed_request.headers[1].name,
    );
    try std.testing.expectEqualStrings(
        "baguette",
        borrowed_request.header("x-bread").?,
    );

    var owned_request = try parseRequest(allocator, request_raw, .{});
    defer owned_request.deinit(allocator);
    try std.testing.expectEqualStrings("Host", owned_request.headers[0].name);
    try std.testing.expectEqualStrings("X-BREAD", owned_request.headers[1].name);
    try std.testing.expectEqualStrings(
        "example.com",
        owned_request.header("host").?,
    );

    const response_raw =
        "HTTP/1.1 200 OK\r\n" ++
        "ETag: \"abc\"\r\n" ++
        "x-trace-ID: 42\r\n" ++
        "\r\n";
    var borrowed_response_headers: [4]Header = undefined;
    const borrowed_response = try parseResponseHead(
        response_raw,
        &borrowed_response_headers,
        .{},
        .{},
    );
    try std.testing.expectEqualStrings(
        "ETag",
        borrowed_response.headers[0].name,
    );
    try std.testing.expectEqualStrings(
        "x-trace-ID",
        borrowed_response.headers[1].name,
    );
    try std.testing.expectEqualStrings(
        "\"abc\"",
        borrowed_response.header("etag").?,
    );

    var owned_response = try parseResponse(allocator, response_raw, .{});
    defer owned_response.deinit(allocator);
    try std.testing.expectEqualStrings("ETag", owned_response.headers[0].name);
    try std.testing.expectEqualStrings(
        "x-trace-ID",
        owned_response.headers[1].name,
    );
    try std.testing.expectEqualStrings("42", owned_response.header("X-TRACE-id").?);
}

test "HTTP/1 borrowed response heads honor method context" {
    const head_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 123\r\n" ++
        "\r\n" ++
        "HTTP/1.1 204 No Content\r\n\r\n";
    var headers: [4]Header = undefined;
    const head = try parseResponseHead(head_response, &headers, .{}, .{ .request_method = .HEAD });
    try std.testing.expectEqual(BodyFraming.none, head.body_framing);
    try std.testing.expectEqual(@as(?usize, 123), head.content_length);
    try std.testing.expectEqual(head.head_len, (try head.messageLength()).?);

    var second_headers: [1]Header = undefined;
    const no_content = try parseResponseHead(head_response[head.head_len..], &second_headers, .{}, .{});
    try std.testing.expectEqual(@as(u16, 204), no_content.status);
    try std.testing.expectEqual(no_content.head_len, (try no_content.messageLength()).?);

    const connect = "HTTP/1.1 200 Connection Established\r\n\r\ntunnel";
    const tunnel = try parseResponseHead(connect, &second_headers, .{}, .{ .request_method = .CONNECT });
    try std.testing.expectEqual(BodyFraming.none, tunnel.body_framing);
    try std.testing.expectEqualStrings("Connection Established", tunnel.reason);

    const invalid_length_204 = try parseResponseHead(
        "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\n",
        &headers,
        .{},
        .{},
    );
    try std.testing.expectEqual(BodyFraming.none, invalid_length_204.body_framing);
    try std.testing.expectEqual(invalid_length_204.head_len, (try invalid_length_204.messageLength()).?);
}

test "HTTP/1 borrowed heads expose unknown chunked and close-delimited lengths" {
    var headers: [4]Header = undefined;
    const chunked =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nx\r\n0\r\n\r\n";
    const chunked_head = try parseResponseHead(chunked, &headers, .{}, .{});
    try std.testing.expectEqual(BodyFraming.chunked, chunked_head.body_framing);
    try std.testing.expectEqual(@as(?usize, null), try chunked_head.messageLength());

    const close_delimited =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: gzip\r\n\r\npayload";
    const close_head = try parseResponseHead(close_delimited, &headers, .{}, .{});
    try std.testing.expectEqual(BodyFraming.close_delimited, close_head.body_framing);
    try std.testing.expectEqual(@as(?usize, null), try close_head.messageLength());
}

test "HTTP/1 borrowed heads validate storage host and folding" {
    var no_headers: [0]Header = .{};
    try std.testing.expectError(
        error.TooManyHeaders,
        parseRequestHead("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", &no_headers, .{}),
    );

    var headers: [4]Header = undefined;
    try std.testing.expectError(
        error.InvalidHost,
        parseRequestHead("GET / HTTP/1.1\r\n\r\n", &headers, .{}),
    );
    try std.testing.expectError(
        error.MalformedHeader,
        parseRequestHead(
            "GET / HTTP/1.1\r\nHost: example.com\r\nFold: one\r\n two\r\n\r\n",
            &headers,
            .{ .allow_obs_fold = true },
        ),
    );
    try std.testing.expectError(
        error.ConflictingContentLength,
        parseRequestHead(
            "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            &headers,
            .{},
        ),
    );
}

test "HTTP/1 strict borrowed heads defer malformed fields until line completion" {
    var headers: [4]Header = undefined;
    const prefix = "GET / HTTP/1.1\r\nHost: example.com\r\n";

    try std.testing.expectError(
        error.BufferTooShort,
        parseRequestHead(prefix ++ "Bad Header", &headers, .{}),
    );
    try std.testing.expectError(
        error.MalformedHeader,
        parseRequestHead(prefix ++ "Bad Header\r\n", &headers, .{}),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        parseRequestHead(prefix ++ "X-Test: bad\x00value", &headers, .{}),
    );
    try std.testing.expectError(
        error.MalformedHeader,
        parseRequestHead(
            prefix ++ "X-Test: bad\x00value\r\n",
            &headers,
            .{},
        ),
    );
}

test "HTTP/1 strict borrowed field scan matches compatibility parser" {
    const prefix = "GET / HTTP/1.1\r\n";
    const Compare = struct {
        fn run(bytes: []const u8) !void {
            const first_line_end = std.mem.indexOf(u8, bytes, "\r\n") orelse
                return error.TestUnexpectedResult;
            const start_line = bytes[0..first_line_end];
            const initial_pos = first_line_end + 2;
            var strict_storage: [8]Header = undefined;
            var compatible_storage: [8]Header = undefined;
            const strict_result = parseStrictHeadLines(
                bytes,
                &strict_storage,
                .{},
                start_line,
                initial_pos,
            );
            const compatible_result = parseCompatibleHeadLines(
                bytes,
                &compatible_storage,
                .{},
                .{},
                start_line,
                initial_pos,
            );
            if (strict_result) |strict| {
                const compatible = try compatible_result;
                try std.testing.expectEqual(
                    compatible.head_len,
                    strict.head_len,
                );
                try std.testing.expectEqualStrings(
                    compatible.start_line,
                    strict.start_line,
                );
                try std.testing.expectEqual(
                    compatible.headers.len,
                    strict.headers.len,
                );
                for (strict.headers, compatible.headers) |
                    strict_header,
                    compatible_header,
                | {
                    try std.testing.expectEqualStrings(
                        compatible_header.name,
                        strict_header.name,
                    );
                    try std.testing.expectEqualStrings(
                        compatible_header.value,
                        strict_header.value,
                    );
                }
            } else |strict_error| {
                try std.testing.expectError(
                    strict_error,
                    compatible_result,
                );
            }
        }
    };

    const valid = prefix ++
        "Host: example.com\r\n" ++
        "X-Whitespace:\t value \t\r\n" ++
        "Empty:\r\n\r\n";
    for (prefix.len..valid.len + 1) |end| {
        try Compare.run(valid[0..end]);
    }

    const name_suffix = ": value\r\n\r\n";
    var name_case: [prefix.len + 2 + name_suffix.len]u8 = undefined;
    @memcpy(name_case[0..prefix.len], prefix);
    name_case[prefix.len] = 'X';
    @memcpy(name_case[prefix.len + 2 ..], name_suffix);
    for (0..256) |raw| {
        name_case[prefix.len + 1] = @intCast(raw);
        try Compare.run(&name_case);
    }

    const value_lead = "X-Test: a";
    const value_suffix = "b\r\n\r\n";
    var value_case: [prefix.len + value_lead.len + 1 + value_suffix.len]u8 =
        undefined;
    @memcpy(value_case[0..prefix.len], prefix);
    @memcpy(
        value_case[prefix.len .. prefix.len + value_lead.len],
        value_lead,
    );
    @memcpy(value_case[prefix.len + value_lead.len + 1 ..], value_suffix);
    for (0..256) |raw| {
        value_case[prefix.len + value_lead.len] = @intCast(raw);
        try Compare.run(&value_case);
    }
}

test "HTTP/1 validates header field syntax" {
    const allocator = std.testing.allocator;
    const bad_name = "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n";
    try std.testing.expectError(error.MalformedHeader, parseRequest(allocator, bad_name, .{}));

    const bad_value = [_]Header{.{ .name = "x-test", .value = "ok\r\nInjected: yes" }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.MalformedHeader, writeResponseChecked(&encoded, allocator, .http_1_1, 200, "OK", &bad_value, ""));

    try validateHeader(.{ .name = "X-Custom_123", .value = "text\tvalue" });
    try std.testing.expectError(error.MalformedHeader, validateHeader(.{ .name = "bad:name", .value = "value" }));
    try std.testing.expectError(error.MalformedHeader, validateHeader(.{ .name = "x-test", .value = "bad\x7fvalue" }));
}

test "HTTP/1 header name lookup table matches RFC token grammar" {
    for (0..256) |raw| {
        const byte: u8 = @intCast(raw);
        const expected = std.ascii.isAlphanumeric(byte) or switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
        try std.testing.expectEqual(expected, validHeaderNameByte(byte));
    }
}

test "HTTP/1 optionally unfolds obsolete folded fields" {
    const allocator = std.testing.allocator;
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Fold: just\r\n" ++
        " some\r\n" ++
        "\t folding\r\n" ++
        "\r\n";
    try std.testing.expectError(error.MalformedHeader, parseRequest(allocator, raw, .{}));

    var req = try parseRequest(allocator, raw, .{ .allow_obs_fold = true });
    defer req.deinit(allocator);
    try std.testing.expectEqualStrings("just some folding", req.header("fold").?);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);

    const chunked =
        "POST /trailers HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "0\r\n" ++
        "Digest: sha-256=abc\r\n" ++
        "\tdef\r\n" ++
        "\r\n";
    var with_trailer = try parseRequest(allocator, chunked, .{ .allow_obs_fold = true });
    defer with_trailer.deinit(allocator);
    try std.testing.expectEqualStrings("sha-256=abc def", with_trailer.trailers[0].value);
}

test "HTTP/1 validates start-line components" {
    const allocator = std.testing.allocator;
    const bad_target = "GET /bad\tpath HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, bad_target, .{}));
    try std.testing.expectError(error.MalformedStartLine, validateRequestTarget("/evil\r\nInjected: yes"));
    try std.testing.expectError(error.MalformedStartLine, validateRequestTarget(""));
    try validateConnectTarget("example.com:443");
    try validateConnectTarget("[2001:db8::1]:443");
    try validateRequestTargetForMethod(.OPTIONS, "*");
    try validateRequestTargetForMethod(.OPTIONS, "/server-wide");
    try validateRequestTargetForMethod(.GET, "https://example.com/path");
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "CONNECT /path HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "GET relative-token HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "GET example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "OPTIONS example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "GET /path#fragment HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, "GET http://example.com/path#fragment HTTP/1.1\r\nHost: example.com\r\n\r\n", .{}));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("/path"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("2001:db8::1:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("[]:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("[2001:db8::1]"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com:"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com:65536"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("https://example.com:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("user@example.com:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com:443/path"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com?port=443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com:443, other.example:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("example.com[::1]:443"));
    try std.testing.expectError(error.MalformedStartLine, validateConnectTarget("[2001:db8::1]:443/path"));

    const bad_reason = "HTTP/1.1 200 OK\x01\r\nContent-Length: 0\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseResponse(allocator, bad_reason, .{}));
    try std.testing.expectError(error.MalformedStartLine, validateReasonPhrase("OK\r\nInjected: yes"));
    try std.testing.expectError(error.InvalidStatus, validateStatusCode(99));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.MalformedStartLine, writeRequestChecked(&encoded, allocator, .GET, "/\r\nHost: evil", .http_1_1, &.{}, ""));
    try std.testing.expectError(error.MalformedStartLine, writeResponseChecked(&encoded, allocator, .http_1_1, 200, "OK\r\nX: evil", &.{}, ""));
    try std.testing.expectError(error.InvalidStatus, writeResponseChecked(&encoded, allocator, .http_1_1, 42, "Nope", &.{}, ""));
}

test "HTTP/1 response status lines require the reason separator" {
    const allocator = std.testing.allocator;
    const canonical = "HTTP/1.1 204 \r\n\r\n";

    var response = try parseResponse(allocator, canonical, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);
    try std.testing.expectEqualStrings("", response.reason);

    var header_storage: [1]Header = undefined;
    const head = try parseResponseHead(canonical, &header_storage, .{}, .{});
    try std.testing.expectEqual(@as(u16, 204), head.status);
    try std.testing.expectEqualStrings("", head.reason);

    const missing_separator = "HTTP/1.1 204\r\n\r\n";
    try std.testing.expectError(
        error.MalformedStartLine,
        parseResponse(allocator, missing_separator, .{}),
    );
    try std.testing.expectError(
        error.MalformedStartLine,
        parseResponseHead(missing_separator, &header_storage, .{}, .{}),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeResponse(&encoded, allocator, .http_1_1, 204, "", &.{}, "");
    try std.testing.expectEqualStrings(canonical, encoded.items);
    encoded.clearRetainingCapacity();
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        204,
        "",
        &.{},
        "",
    );
    try std.testing.expectEqualStrings(canonical, encoded.items);
}

test "HTTP/1 request target length is caller-configurable" {
    const allocator = std.testing.allocator;
    const raw = "GET /long-path HTTP/1.1\r\nHost: example.com\r\n\r\n";

    var accepted = try parseRequest(allocator, raw, .{});
    defer accepted.deinit(allocator);
    try std.testing.expectEqualStrings("/long-path", accepted.target);

    try std.testing.expectError(
        error.UriTooLong,
        parseRequest(allocator, raw, .{
            .max_request_target_bytes = 8,
        }),
    );
    var headers: [4]Header = undefined;
    try std.testing.expectError(
        error.UriTooLong,
        parseRequestHead(raw, &headers, .{
            .max_request_target_bytes = 8,
        }),
    );
}

test "HTTP/1 Hyper-shaped parser compatibility switches remain scoped" {
    const allocator = std.testing.allocator;
    const spaced_request =
        "GET  /echo  HTTP/1.1\r\nHost: hyper.rs\r\n\r\n";
    try std.testing.expectError(
        error.MalformedStartLine,
        parseRequest(allocator, spaced_request, .{}),
    );
    var request = try parseRequest(allocator, spaced_request, .{
        .allow_multiple_spaces_in_request_line_delimiters = true,
    });
    defer request.deinit(allocator);
    try std.testing.expect(request.method == .GET);
    try std.testing.expectEqualStrings("/echo", request.target);

    var request_headers: [2]Header = undefined;
    const borrowed_request = try parseRequestHead(
        spaced_request,
        &request_headers,
        .{ .allow_multiple_spaces_in_request_line_delimiters = true },
    );
    try std.testing.expectEqualStrings("/echo", borrowed_request.target);

    const spaced_response =
        "HTTP/1.1 204 No Content\r\n" ++
        "Access-Control-Allow-Credentials \t: true\r\n\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseResponse(allocator, spaced_response, .{}),
    );
    var response = try parseResponse(allocator, spaced_response, .{
        .allow_spaces_after_header_name_in_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "true",
        response.header("access-control-allow-credentials").?,
    );

    var response_headers: [2]Header = undefined;
    const borrowed_response = try parseResponseHead(
        spaced_response,
        &response_headers,
        .{ .allow_spaces_after_header_name_in_responses = true },
        .{},
    );
    try std.testing.expectEqualStrings(
        "Access-Control-Allow-Credentials",
        borrowed_response.headers[0].name,
    );

    // Hyper deliberately exposes this tolerance only for responses. A server
    // must still reject whitespace before the colon in requests, and trailer
    // parsing remains strict for the same request-smuggling reason.
    const bad_request =
        "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseRequest(allocator, bad_request, .{
            .allow_spaces_after_header_name_in_responses = true,
        }),
    );
    try std.testing.expectError(
        error.MalformedHeader,
        decodeChunked(
            allocator,
            "0\r\nDigest : value\r\n\r\n",
            .{ .allow_spaces_after_header_name_in_responses = true },
        ),
    );
}

test "HTTP/1 invalid-header compatibility skips only non-fatal lines" {
    const allocator = std.testing.allocator;
    const request_bytes =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Bad Header: ignored\r\n" ++
        "X-Bad: value\x01ignored\r\n" ++
        "Bread: baguette\r\n\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseRequest(allocator, request_bytes, .{}),
    );
    var request = try parseRequest(allocator, request_bytes, .{
        .ignore_invalid_headers_in_requests = true,
    });
    defer request.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), request.headers.len);
    try std.testing.expectEqualStrings(
        "example.com",
        request.header("host").?,
    );
    try std.testing.expectEqualStrings("baguette", request.header("bread").?);

    var request_headers: [2]Header = undefined;
    const borrowed_request = try parseRequestHead(
        request_bytes,
        &request_headers,
        .{ .ignore_invalid_headers_in_requests = true },
    );
    try std.testing.expectEqual(@as(usize, 2), borrowed_request.headers.len);

    const response_bytes =
        "HTTP/1.1 204 No Content\r\n" ++
        "Missing-Colon\r\n" ++
        "Bread: baguette\r\n\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseResponse(allocator, response_bytes, .{}),
    );
    var response = try parseResponse(allocator, response_bytes, .{
        .ignore_invalid_headers_in_responses = true,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), response.headers.len);
    try std.testing.expectEqualStrings(
        "baguette",
        response.header("bread").?,
    );

    var response_headers: [1]Header = undefined;
    const borrowed_response = try parseResponseHead(
        response_bytes,
        &response_headers,
        .{ .ignore_invalid_headers_in_responses = true },
        .{},
    );
    try std.testing.expectEqual(@as(usize, 1), borrowed_response.headers.len);

    try std.testing.expectError(
        error.MalformedHeader,
        parseRequest(allocator, request_bytes, .{
            .ignore_invalid_headers_in_responses = true,
        }),
    );
    try std.testing.expectError(
        error.MalformedHeader,
        parseResponse(allocator, response_bytes, .{
            .ignore_invalid_headers_in_requests = true,
        }),
    );

    const nul_response =
        "HTTP/1.1 204 No Content\r\nBad\x00Name: value\r\n\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseResponse(allocator, nul_response, .{
            .ignore_invalid_headers_in_responses = true,
        }),
    );
}

test "HTTP/1 validates Host authority rules" {
    const allocator = std.testing.allocator;
    const valid = "GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    var req = try parseRequest(allocator, valid, .{});
    defer req.deinit(allocator);
    try validateRequestHost(req);

    const missing = "GET / HTTP/1.1\r\nUser-Agent: demo\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        parseRequest(allocator, missing, .{}),
    );

    const duplicate = "GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        parseRequest(allocator, duplicate, .{}),
    );

    const matching_connect =
        "CONNECT example.com:443 HTTP/1.1\r\n" ++
        "Host: example.com:443\r\n\r\n";
    var connect_req = try parseRequest(allocator, matching_connect, .{});
    defer connect_req.deinit(allocator);
    try validateRequestHost(connect_req);

    const mismatched_connect =
        "CONNECT example.com:443 HTTP/1.1\r\n" ++
        "Host: other.example:443\r\n\r\n";
    var normalized_connect = try parseRequest(
        allocator,
        mismatched_connect,
        .{},
    );
    defer normalized_connect.deinit(allocator);
    try std.testing.expectEqualStrings(
        "example.com:443",
        normalized_connect.header("host").?,
    );
    var borrowed_headers: [2]Header = undefined;
    const borrowed_connect = try parseRequestHead(
        mismatched_connect,
        &borrowed_headers,
        .{},
    );
    try std.testing.expectEqualStrings(
        "example.com:443",
        borrowed_connect.header("host").?,
    );
    try validateRequestHead(allocator, mismatched_connect, .{});

    var invalid_connect_write: std.ArrayList(u8) = .empty;
    defer invalid_connect_write.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHost,
        writeRequestChecked(
            &invalid_connect_write,
            allocator,
            .CONNECT,
            "example.com:443",
            .http_1_1,
            &.{.{ .name = "Host", .value = "other.example:443" }},
            "",
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), invalid_connect_write.items.len);

    try writeRequestChecked(
        &invalid_connect_write,
        allocator,
        .CONNECT,
        "example.com:443",
        .http_1_1,
        &.{.{ .name = "Host", .value = "example.com" }},
        "",
    );
    invalid_connect_write.clearRetainingCapacity();
    try writeRequestChecked(
        &invalid_connect_write,
        allocator,
        .CONNECT,
        "[2001:db8::1]:443",
        .http_1_1,
        &.{.{ .name = "Host", .value = "[2001:db8::1]" }},
        "",
    );

    try std.testing.expectError(error.InvalidHost, validateHostValue(""));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com:"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com:65536"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("http://example.com"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("user@example.com"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com, other.example"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com?query"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com#fragment"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("2001:db8::1"));
    try std.testing.expectError(error.InvalidHost, validateHostValue("example.com[::1]:443"));
    try validateHostValue("[2001:db8::1]:443");
}

test "HTTP/1 parses absolute-form authority as the effective Host" {
    const allocator = std.testing.allocator;

    const matching = "GET http://example.com:8080/proxy?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    var req = try parseRequest(allocator, matching, .{});
    defer req.deinit(allocator);
    try validateRequestHost(req);
    try std.testing.expectEqualStrings("example.com:8080", absoluteFormAuthority(req.target).?);

    const mismatch = "GET http://example.com/proxy HTTP/1.1\r\nHost: other.example\r\n\r\n";
    var normalized = try parseRequest(allocator, mismatch, .{});
    defer normalized.deinit(allocator);
    try std.testing.expectEqualStrings(
        "example.com",
        normalized.header("host").?,
    );
    try validateRequestHost(normalized);
    var borrowed_storage: [1]Header = undefined;
    const borrowed = try parseRequestHead(
        mismatch,
        &borrowed_storage,
        .{},
    );
    try std.testing.expectEqualStrings(
        "example.com",
        borrowed.header("host").?,
    );
    try validateRequestHead(allocator, mismatch, .{});

    var rejected_write: std.ArrayList(u8) = .empty;
    defer rejected_write.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHost,
        writeRequestChecked(
            &rejected_write,
            allocator,
            .GET,
            "http://example.com/proxy",
            .http_1_1,
            &.{.{ .name = "Host", .value = "other.example" }},
            "",
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_write.items.len);

    const invalid_authority = "GET http://user@example.com/proxy HTTP/1.1\r\nHost: user@example.com\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, invalid_authority, .{}));

    const missing_authority = "GET http:///proxy HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, missing_authority, .{}));

    const empty_authority = "GET http://?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, empty_authority, .{}));

    const origin_with_colon_slashes = "GET /cache/http://example.com/object HTTP/1.1\r\nHost: proxy.local\r\n\r\n";
    var origin_req = try parseRequest(allocator, origin_with_colon_slashes, .{});
    defer origin_req.deinit(allocator);
    try validateRequestHost(origin_req);
    try std.testing.expect(absoluteFormAuthority(origin_req.target) == null);

    const scheme_must_start_alpha = "GET 1http://example.com/proxy HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expectError(error.MalformedStartLine, parseRequest(allocator, scheme_must_start_alpha, .{}));

    var non_alpha = [_]u8{0} ++ "http://example.com/path".*;
    for (0..256) |value| {
        const first: u8 = @intCast(value);
        if (std.ascii.isAlphabetic(first)) continue;
        non_alpha[0] = first;
        try std.testing.expect(absoluteFormAuthority(&non_alpha) == null);
    }
    try std.testing.expectEqualStrings(
        "example.com",
        absoluteFormAuthority("HTTP://example.com/path").?,
    );
}

test "HTTP/1 writers reject forbidden response bodies" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var no_alloc_response: std.ArrayList(u8) = .empty;
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    const no_alloc_allocator = no_alloc.allocator();
    defer no_alloc_response.deinit(no_alloc_allocator);
    try writeResponseChecked(&no_alloc_response, no_alloc_allocator, .http_1_1, 200, "OK", &.{.{ .name = "Content-Length", .value = "4" }}, "pong");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong", no_alloc_response.items);

    try std.testing.expectError(error.InvalidContentLength, writeResponseChecked(&encoded, allocator, .http_1_1, 204, "No Content", &.{}, "body"));
    try std.testing.expectError(error.InvalidTransferEncoding, writeResponseChecked(&encoded, allocator, .http_1_1, 204, "No Content", &.{.{
        .name = "Transfer-Encoding",
        .value = "chunked",
    }}, ""));
    try std.testing.expectError(error.InvalidContentLength, writeResponseChecked(&encoded, allocator, .http_1_1, 204, "No Content", &.{.{
        .name = "Content-Length",
        .value = "0",
    }}, ""));
    try std.testing.expectError(error.InvalidContentLength, writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        205,
        "Reset Content",
        &.{},
        "body",
    ));
    try std.testing.expectError(error.InvalidContentLength, writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        205,
        "Reset Content",
        &.{.{ .name = "Content-Length", .value = "1" }},
        "",
    ));
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        205,
        "Reset Content",
        &.{.{ .name = "Content-Length", .value = "0" }},
        "",
    );
    try std.testing.expect(!statusCodeForbidsBody(205));
    var received_205 = try parseResponse(
        allocator,
        "HTTP/1.1 205 Reset Content\r\nContent-Length: 4\r\n\r\nbody",
        .{},
    );
    defer received_205.deinit(allocator);
    try std.testing.expectEqualStrings("body", received_205.body);

    try writeResponseChecked(&encoded, allocator, .http_1_1, 304, "Not Modified", &.{.{
        .name = "Content-Length",
        .value = "123",
    }}, "");
    try std.testing.expect(std.mem.indexOf(u8, encoded.items, "Content-Length: 123\r\n") != null);
}

test "HTTP/1 304 responses may describe transfer coding without a body" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const expected =
        "HTTP/1.1 304 Not Modified\r\n" ++
        "Transfer-Encoding: gzip, chunked\r\n" ++
        "\r\n";
    try writeResponseChecked(
        &encoded,
        allocator,
        .http_1_1,
        304,
        "Not Modified",
        &.{.{
            .name = "Transfer-Encoding",
            .value = "gzip, chunked",
        }},
        "",
    );
    try std.testing.expectEqualStrings(expected, encoded.items);

    var response = try parseResponse(
        allocator,
        expected ++ "next response",
        .{},
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.none, response.body_framing);
    try std.testing.expectEqual(expected.len, response.consumed);
    try std.testing.expectEqualStrings("", response.body);

    try std.testing.expectError(
        error.InvalidContentLength,
        writeResponseChecked(
            &encoded,
            allocator,
            .http_1_1,
            304,
            "Not Modified",
            &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
            "body",
        ),
    );
}

test "HTTP/1 chunked codec" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const chunks = [_][]const u8{ "hello", " world" };
    const trailers = [_]Header{.{ .name = "Digest", .value = "sha-256=demo" }};
    try encodeChunked(&encoded, allocator, &chunks, &trailers);

    var decoded = try decodeChunked(allocator, encoded.items, .{});
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("hello world", decoded.body);
    try std.testing.expectEqualStrings("sha-256=demo", decoded.trailers[0].value);
    const encoded_with_trailer = try allocator.dupe(u8, encoded.items);
    defer allocator.free(encoded_with_trailer);

    var sparse: std.ArrayList(u8) = .empty;
    defer sparse.deinit(allocator);
    try sparse.ensureTotalCapacityPrecise(
        allocator,
        encoded_with_trailer.len,
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try encodeChunked(
        &sparse,
        no_alloc.allocator(),
        &.{ "", "hello", "", " world", "" },
        &trailers,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(encoded_with_trailer, sparse.items);

    encoded.clearRetainingCapacity();
    try encoded.ensureTotalCapacity(allocator, encoded_with_trailer.len);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try encodeChunked(&encoded, no_alloc.allocator(), &chunks, &trailers);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(encoded_with_trailer, encoded.items);

    encoded.clearRetainingCapacity();
    try encoded.ensureTotalCapacity(allocator, "0\r\n\r\n".len);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try encodeChunked(&encoded, no_alloc.allocator(), &.{}, &.{});
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("0\r\n\r\n", encoded.items);

    encoded.clearRetainingCapacity();
    try encodeChunked(&encoded, allocator, &.{ "", "", "" }, &trailers);
    try std.testing.expectEqualStrings(
        "0\r\nDigest: sha-256=demo\r\n\r\n",
        encoded.items,
    );
    var all_empty = try decodeChunked(allocator, encoded.items, .{});
    defer all_empty.deinit(allocator);
    try std.testing.expectEqualStrings("", all_empty.body);
    try std.testing.expectEqualStrings(
        "sha-256=demo",
        all_empty.trailers[0].value,
    );

    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var empty_decoded = try decodeChunked(no_alloc.allocator(), "0\r\n\r\nnext", .{});
    defer empty_decoded.deinit(no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, "0\r\n\r\n".len), empty_decoded.consumed);
    try std.testing.expectEqualStrings("", empty_decoded.body);
    try std.testing.expectEqual(@as(usize, 0), empty_decoded.trailers.len);

    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    var body_only = try decodeChunked(no_alloc.allocator(), "5\r\nhello\r\n0\r\n\r\nnext", .{});
    defer body_only.deinit(no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("hello", body_only.body);
    try std.testing.expectEqual(@as(usize, "5\r\nhello\r\n0\r\n\r\n".len), body_only.consumed);
}

test "HTTP/1 duplicate trailers survive aggregate chunked codec at exact limit" {
    const allocator = std.testing.allocator;
    const trailers = [_]Header{
        .{ .name = "X-Trace", .value = "first" },
        .{ .name = "x-trace", .value = "second" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encodeChunked(&encoded, allocator, &.{"body"}, &trailers);
    try std.testing.expectEqualStrings(
        "4\r\nbody\r\n0\r\n" ++
            "X-Trace: first\r\n" ++
            "x-trace: second\r\n\r\n",
        encoded.items,
    );

    var decoded = try decodeChunked(
        allocator,
        encoded.items,
        .{ .max_headers = trailers.len },
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("body", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.trailers.len);
    try std.testing.expectEqualStrings("X-Trace", decoded.trailers[0].name);
    try std.testing.expectEqualStrings("first", decoded.trailers[0].value);
    try std.testing.expectEqualStrings("x-trace", decoded.trailers[1].name);
    try std.testing.expectEqualStrings("second", decoded.trailers[1].value);

    try std.testing.expectError(
        error.TooManyHeaders,
        decodeChunked(allocator, encoded.items, .{ .max_headers = 1 }),
    );

    var parsed = try parseTrailerFields(
        allocator,
        "X-Trace: first\r\nx-trace: second\r\n",
        .{ .max_headers = trailers.len },
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.headers.len);
    try std.testing.expectEqualStrings("first", parsed.headers[0].value);
    try std.testing.expectEqualStrings("second", parsed.headers[1].value);
}

test "HTTP/1 chunked trailers reject forbidden fields" {
    const allocator = std.testing.allocator;
    try validateTrailers(&.{
        .{ .name = "ETag", .value = "\"dynamic\"" },
        .{ .name = "X-Application-Digest", .value = "sha-256=demo" },
    });
    const malformed = [_]Header{
        .{ .name = "", .value = "empty-name" },
        .{ .name = "Bad Trailer", .value = "space-in-name" },
        .{ .name = "X-Injected", .value = "ok\r\nInjected: yes" },
    };
    for (malformed) |trailer| {
        try std.testing.expectError(
            error.MalformedHeader,
            validateTrailers(&.{trailer}),
        );
    }
    const invalid = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Trailer", .value = "Digest" },
        .{ .name = "Host", .value = "example.com" },
        .{ .name = "Connection", .value = "close" },
        .{ .name = "Keep-Alive", .value = "timeout=5" },
        .{ .name = "Proxy-Connection", .value = "keep-alive" },
        .{ .name = "Upgrade", .value = "websocket" },
    };
    for (invalid) |trailer| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.InvalidTrailer, encodeChunked(&encoded, allocator, &[_][]const u8{"hello"}, &.{trailer}));

        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(allocator);
        try raw.appendSlice(allocator, "5\r\nhello\r\n0\r\n");
        try raw.appendSlice(allocator, trailer.name);
        try raw.appendSlice(allocator, ": ");
        try raw.appendSlice(allocator, trailer.value);
        try raw.appendSlice(allocator, "\r\n\r\n");
        try std.testing.expectError(
            error.InvalidTrailer,
            decodeChunked(allocator, raw.items, .{}),
        );
    }
}

test "HTTP/1 chunked extensions are bounded" {
    const allocator = std.testing.allocator;
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try raw.append(allocator, '1');
    try raw.appendNTimes(allocator, ' ', max_chunk_size_line_bytes - 2);
    try raw.appendSlice(allocator, "\r\nx\r\n0\r\n\r\n");
    var exact = try decodeChunked(allocator, raw.items, .{});
    defer exact.deinit(allocator);
    try std.testing.expectEqualStrings("x", exact.body);

    raw.clearRetainingCapacity();
    try raw.appendSlice(allocator, "1;");
    try raw.appendNTimes(allocator, 'a', max_chunk_extension_bytes + 1);
    try raw.appendSlice(allocator, "\r\nx\r\n0\r\n\r\n");
    try std.testing.expectError(error.ChunkExtensionTooLarge, decodeChunked(allocator, raw.items, .{}));

    raw.clearRetainingCapacity();
    try raw.append(allocator, '1');
    try raw.appendNTimes(allocator, ' ', max_chunk_size_line_bytes - 1);
    try raw.appendSlice(allocator, "\r\nx\r\n0\r\n\r\n");
    try std.testing.expectError(
        error.ChunkExtensionTooLarge,
        decodeChunked(allocator, raw.items, .{}),
    );

    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, "\r\n0\r\n\r\n", .{}));
    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, "+1\r\nx\r\n0\r\n\r\n", .{}));
    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, " 1\r\nx\r\n0\r\n\r\n", .{}));
    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, "1 1\r\nxxxxxxxxxxx\r\n0\r\n\r\n", .{}));
    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, "1;bad\next\r\nx\r\n0\r\n\r\n", .{}));
    try std.testing.expectError(error.InvalidChunk, decodeChunked(allocator, "1;bad\rbare\r\nx\r\n0\r\n\r\n", .{}));
    var post_size_lws = try decodeChunked(allocator, "1 \t;ignored\r\nx\r\n0\r\n\r\n", .{});
    defer post_size_lws.deinit(allocator);
    try std.testing.expectEqualStrings("x", post_size_lws.body);
    try std.testing.expectError(error.InvalidChunk, parseChunkSize("+a"));
    try std.testing.expectError(error.InvalidChunk, parseChunkSize(" 1A "));
    try std.testing.expectError(error.InvalidChunk, parseChunkSize("1A "));
    try std.testing.expectEqual(@as(usize, 0x1a), try parseChunkSize("1A"));
}

test "HTTP/1 aggregate chunked parser validates extension grammar" {
    const allocator = std.testing.allocator;
    var decoded = try decodeChunked(
        allocator,
        "1; foo = bar ; quoted = \"one,two;three\\\"\"\r\nx\r\n" ++
            "0; final\r\n\r\n",
        .{},
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("x", decoded.body);

    for ([_][]const u8{
        "1;bad/name=value\r\nx\r\n0\r\n\r\n",
        "1;name=\r\nx\r\n0\r\n\r\n",
        "1;name=\"unterminated\r\nx\r\n0\r\n\r\n",
        "1;name=value;;next=ok\r\nx\r\n0\r\n\r\n",
    }) |invalid| {
        try std.testing.expectError(
            error.InvalidChunk,
            decodeChunked(allocator, invalid, .{}),
        );
    }
}

test "HTTP/1 parser decodes chunked transfer bodies" {
    const allocator = std.testing.allocator;
    const raw = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nDigest: sha-256=demo\r\n\r\nnext";
    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);

    try std.testing.expectEqual(BodyFraming.chunked, req.body_framing);
    try std.testing.expect(req.header("content-length") == null);
    try std.testing.expect(req.must_close);
    try std.testing.expect(!req.keepAlive());
    try std.testing.expectEqualStrings("hello world", req.body);
    try std.testing.expectEqualStrings("sha-256=demo", req.trailers[0].value);
    try std.testing.expectEqual(raw.len - "next".len, req.consumed);
}

test "HTTP/1 request TE plus CL is chunked but must close in either order" {
    const allocator = std.testing.allocator;
    const requests = [_][]const u8{
        "POST /cl-first HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 999\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
        "POST /te-first HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Content-Length: 999\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
        "POST /invalid-cl HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: nope\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
    };

    for (requests) |raw| {
        var header_storage: [8]Header = undefined;
        const head = try parseRequestHead(raw, &header_storage, .{});
        try std.testing.expectEqual(BodyFraming.chunked, head.body_framing);
        try std.testing.expect(head.header("content-length") == null);
        try std.testing.expect(head.must_close);
        try std.testing.expect(!head.keepAlive());

        var request = try parseRequest(allocator, raw, .{});
        defer request.deinit(allocator);
        try std.testing.expectEqual(BodyFraming.chunked, request.body_framing);
        try std.testing.expectEqualStrings("ok", request.body);
        try std.testing.expect(request.header("content-length") == null);
        try std.testing.expect(request.must_close);
        try std.testing.expect(!request.keepAlive());
    }
}

test "HTTP/1 parser preserves exact chunked trailer field-name spelling" {
    const allocator = std.testing.allocator;
    const raw =
        "POST /upload HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "0\r\n" ++
        "Digest: sha-256=demo\r\n" ++
        "X-Trace-ID: 42\r\n" ++
        "\r\n";

    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), req.trailers.len);
    try std.testing.expectEqualStrings("Digest", req.trailers[0].name);
    try std.testing.expectEqualStrings("X-Trace-ID", req.trailers[1].name);
    try std.testing.expect(req.trailers[1].eqlName("x-trace-id"));

    var parsed_trailers = try parseTrailerFields(
        allocator,
        "Digest: sha-256=demo\r\nX-Trace-ID: 42\r\n",
        .{},
    );
    defer parsed_trailers.deinit(allocator);
    try std.testing.expectEqualStrings("Digest", parsed_trailers.headers[0].name);
    try std.testing.expectEqualStrings(
        "X-Trace-ID",
        parsed_trailers.headers[1].name,
    );
    try std.testing.expectEqualStrings("42", wire.findHeader(
        parsed_trailers.headers,
        "x-trace-id",
    ).?);
}

test "HTTP/1 parser rejects ambiguous body lengths" {
    const allocator = std.testing.allocator;
    const conflicting = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    try std.testing.expectError(error.ConflictingContentLength, parseRequest(allocator, conflicting, .{}));

    const plus_prefixed = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\n\r\nhello";
    try std.testing.expectError(error.InvalidContentLength, parseRequest(allocator, plus_prefixed, .{}));

    const coalesced = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 5\r\n\r\nhello";
    var req = try parseRequest(allocator, coalesced, .{});
    defer req.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.content_length, req.body_framing);
    try std.testing.expectEqualStrings("hello", req.body);

    const stacked_te = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    var stacked = try parseRequest(allocator, stacked_te, .{});
    defer stacked.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, stacked.body_framing);
    try std.testing.expectEqualStrings("hello", stacked.body);

    const split_stacked_te = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    var split_stacked = try parseRequest(allocator, split_stacked_te, .{});
    defer split_stacked.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, split_stacked.body_framing);
    try std.testing.expectEqualStrings("hello", split_stacked.body);

    const non_final_chunked = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseRequest(allocator, non_final_chunked, .{}));

    const split_non_final_chunked = "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseRequest(allocator, split_non_final_chunked, .{}));
}

test "HTTP/1 Transfer-Encoding grammar is quote aware and strict" {
    const allocator = std.testing.allocator;
    const parameterized =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: gzip; note=\"one,two\", chunked\r\n" ++
        "\r\n" ++
        "2\r\nok\r\n0\r\n\r\n";
    var request = try parseRequest(allocator, parameterized, .{});
    defer request.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, request.body_framing);
    try std.testing.expectEqualStrings("ok", request.body);

    const close_delimited =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: gzip; note=\"one,two\"\r\n" ++
        "\r\n" ++
        "encoded";
    var response = try parseResponse(allocator, close_delimited, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(
        BodyFraming.close_delimited,
        response.body_framing,
    );
    try std.testing.expectEqualStrings("encoded", response.body);

    for ([_][]const u8{
        "gzip token, chunked",
        "gzip; level, chunked",
        "gzip; level=, chunked",
        "gzip; note=\"unterminated, chunked",
        "chunked; level=1",
        "gzi(p, chunked",
        "gzip,,chunked",
    }) |value| {
        const headers = [_]Header{.{
            .name = "Transfer-Encoding",
            .value = value,
        }};
        try std.testing.expectError(
            error.InvalidTransferEncoding,
            bodyFraming(&headers),
        );
        try std.testing.expectError(
            error.InvalidTransferEncoding,
            responseTransferEncodingIsCloseDelimited(&headers),
        );
    }

    const malformed_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: gzip token\r\n" ++
        "\r\n" ++
        "ambiguous";
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        parseResponse(allocator, malformed_response, .{}),
    );
    var header_storage: [2]Header = undefined;
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        parseResponseHead(malformed_response, &header_storage, .{}, .{}),
    );
}

test "HTTP/1 response TE plus CL is sanitized and one-shot in either order" {
    const allocator = std.testing.allocator;
    const responses = [_][]const u8{
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 999\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Content-Length: 999\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: invalid\r\n" ++
            "Transfer-Encoding: chunked\r\n\r\n" ++
            "2\r\nok\r\n0\r\n\r\n",
    };

    for (responses) |raw| {
        var header_storage: [8]Header = undefined;
        const head = try parseResponseHead(
            raw,
            &header_storage,
            .{},
            .{},
        );
        try std.testing.expectEqual(BodyFraming.chunked, head.body_framing);
        try std.testing.expect(head.content_length == null);
        try std.testing.expect(head.header("content-length") == null);
        try std.testing.expect(head.must_close);
        try std.testing.expect(!head.keepAlive());

        var response = try parseResponse(allocator, raw, .{});
        defer response.deinit(allocator);
        try std.testing.expectEqual(BodyFraming.chunked, response.body_framing);
        try std.testing.expectEqualStrings("ok", response.body);
        try std.testing.expect(response.header("content-length") == null);
        try std.testing.expect(response.must_close);
        try std.testing.expect(!response.keepAlive());
    }

    const transfer_only =
        "HTTP/1.1 200 OK\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "2\r\nok\r\n0\r\n\r\n";
    var response = try parseResponse(allocator, transfer_only, .{});
    defer response.deinit(allocator);
    try std.testing.expect(!response.must_close);
    try std.testing.expect(response.keepAlive());
}

test "HTTP/1 response body framing helpers" {
    const allocator = std.testing.allocator;
    const raw = "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    var resp = try parseResponse(allocator, raw, .{});
    defer resp.deinit(allocator);

    try std.testing.expectEqual(BodyFraming.none, resp.body_framing);
    try std.testing.expectEqual(@as(usize, raw.len - "hello".len), resp.consumed);
    try std.testing.expectEqualStrings("", resp.body);
    try std.testing.expect(!resp.keepAlive());

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var empty_head = try parseResponse(no_alloc.allocator(), "HTTP/1.1 204 No Content\r\n\r\nnext", .{});
    defer empty_head.deinit(no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, "HTTP/1.1 204 No Content\r\n\r\n".len), empty_head.consumed);
    try std.testing.expectEqual(@as(usize, 0), empty_head.headers.len);

    const chunked = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npong\r\n0\r\n\r\n";
    var chunked_resp = try parseResponse(allocator, chunked, .{});
    defer chunked_resp.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, chunked_resp.body_framing);
    try std.testing.expect(chunked_resp.header("content-length") == null);
    try std.testing.expectEqualStrings("pong", chunked_resp.body);

    const stacked_final_chunked = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\npong\r\n0\r\n\r\n";
    var stacked_final_chunked_resp = try parseResponse(allocator, stacked_final_chunked, .{});
    defer stacked_final_chunked_resp.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, stacked_final_chunked_resp.body_framing);
    try std.testing.expect(stacked_final_chunked_resp.header("content-length") == null);
    try std.testing.expectEqualStrings("gzip, chunked", stacked_final_chunked_resp.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("pong", stacked_final_chunked_resp.body);

    const stacked_non_final_chunked = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked, gzip\r\n\r\ncompressed-until-close";
    var stacked_non_final_chunked_resp = try parseResponse(allocator, stacked_non_final_chunked, .{});
    defer stacked_non_final_chunked_resp.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.close_delimited, stacked_non_final_chunked_resp.body_framing);
    try std.testing.expect(stacked_non_final_chunked_resp.header("content-length") == null);
    try std.testing.expectEqualStrings("chunked, gzip", stacked_non_final_chunked_resp.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("compressed-until-close", stacked_non_final_chunked_resp.body);

    const non_chunked_te = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nTransfer-Encoding: gzip\r\n\r\ncompressed-until-close";
    var close_delimited_resp = try parseResponse(allocator, non_chunked_te, .{});
    defer close_delimited_resp.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.close_delimited, close_delimited_resp.body_framing);
    try std.testing.expect(close_delimited_resp.header("content-length") == null);
    try std.testing.expectEqualStrings("gzip", close_delimited_resp.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("compressed-until-close", close_delimited_resp.body);
    try std.testing.expectEqual(non_chunked_te.len, close_delimited_resp.consumed);
}

test "HTTP/1 response parsing honors request method body rules" {
    const allocator = std.testing.allocator;

    const head_raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";
    var head_response = try parseResponseForRequest(allocator, head_raw, .{}, .HEAD);
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.none, head_response.body_framing);
    try std.testing.expectEqual(@as(usize, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".len), head_response.consumed);
    try std.testing.expectEqualStrings("", head_response.body);

    const connect_raw = "HTTP/1.1 200 Connection Established\r\nContent-Length: 9\r\n\r\ntunnel bytes";
    var connect_response = try parseResponseForRequest(allocator, connect_raw, .{}, .CONNECT);
    defer connect_response.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.none, connect_response.body_framing);
    try std.testing.expectEqual(@as(usize, "HTTP/1.1 200 Connection Established\r\nContent-Length: 9\r\n\r\n".len), connect_response.consumed);
    try std.testing.expectEqualStrings("", connect_response.body);
}

test "HTTP/1 enforces RFC 8470 Early-Data placement" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeRequest(
        &encoded,
        allocator,
        .GET,
        "/early",
        .http_1_1,
        &.{
            .{ .name = "Host", .value = "example.com" },
            .{ .name = "Early-Data", .value = "1" },
        },
        "",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        "Early-Data: 1\r\n",
    ) != null);

    inline for (.{
        &.{Header{ .name = "early-data", .value = "0" }},
        &.{
            Header{ .name = "early-data", .value = "1" },
            Header{ .name = "Early-Data", .value = "1" },
        },
    }) |invalid| {
        try std.testing.expectError(
            error.MalformedHeader,
            writeRequest(
                &encoded,
                allocator,
                .GET,
                "/early",
                .http_1_1,
                invalid,
                "",
            ),
        );
    }

    const forwarded =
        "GET /forwarded HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Early-Data: invalid\r\n" ++
        "Early-Data: 1\r\n\r\n";
    var request = try parseRequest(allocator, forwarded, .{});
    defer request.deinit(allocator);
    try std.testing.expect(
        early_data.requestMightHaveBeenEarly(request.headers),
    );
    try std.testing.expectEqual(
        early_data.ForwardingAction.set,
        early_data.forwardingAction(request.headers, false),
    );

    const forbidden_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Early-Data: 1\r\n" ++
        "Content-Length: 0\r\n\r\n";
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(allocator, forbidden_response, .{}),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        writeResponse(
            &encoded,
            allocator,
            .http_1_1,
            200,
            "OK",
            &.{.{ .name = "Early-Data", .value = "1" }},
            "",
        ),
    );

    const forbidden_trailer =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Trailer: Early-Data\r\n\r\n" ++
        "0\r\nEarly-Data: 1\r\n\r\n";
    try std.testing.expectError(
        error.InvalidTrailer,
        parseRequest(allocator, forbidden_trailer, .{}),
    );
}
