const std = @import("std");
const http1 = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");

pub const Error = http1.Error || error{InvalidResponse};

/// Controls only the spelling of emitted HTTP/1 field names. Header lookup and
/// validation remain case-insensitive, and `.preserve` retains today's exact
/// caller-provided bytes.
pub const HeaderNameCasing = enum {
    preserve,
    title_case,
};

pub const RequestOptions = struct {
    method: http1.Method = .GET,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
    /// Optional authority used to synthesize Host when the caller did not
    /// provide one explicitly. HTTP/1.1 requires Host on origin-form requests;
    /// keeping it here avoids forcing every caller to construct the field.
    host: ?[]const u8 = null,
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
    header_name_casing: HeaderNameCasing = .preserve,
};

pub const ResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
    /// True only when the associated HTTP/1.1 request contained a
    /// TE: trailers token. Response trailer fields are rejected otherwise.
    request_accepts_trailers: bool = false,
    header_name_casing: HeaderNameCasing = .preserve,
    /// Optional method of the request this response answers. HEAD and
    /// successful CONNECT have method-specific body framing rules that cannot
    /// be inferred from status and headers alone.
    request_method: ?http1.Method = null,
};

pub const StreamingRequestOptions = struct {
    method: http1.Method = .POST,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
    host: ?[]const u8 = null,
    headers: []const http1.Header = &.{},
    /// Exact body size when known. A null size selects chunked framing for
    /// body-capable HTTP/1.1 methods unless Content-Length already fixes it.
    body_length: ?usize = null,
    /// Trailer field names announced in the initial Trailer header. Values are
    /// supplied later to `finishTrailers`; repeated names are announced once.
    trailer_names: []const []const u8 = &.{},
    header_name_casing: HeaderNameCasing = .preserve,
};

pub const StreamingResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    /// Exact body size when known. A null size selects chunked framing for an
    /// ordinary HTTP/1.1 response.
    body_length: ?usize = null,
    trailer_names: []const []const u8 = &.{},
    /// True only when the associated HTTP/1.1 request contained a
    /// TE: trailers token. Announced response trailers are rejected
    /// otherwise.
    request_accepts_trailers: bool = false,
    header_name_casing: HeaderNameCasing = .preserve,
    request_method: ?http1.Method = null,
};

pub const StreamingFraming = union(enum) {
    fixed: usize,
    chunked,
    suppressed,
};

pub const StreamingHead = struct {
    head: []const u8,
    framing: StreamingFraming,
    /// An HTTP/1 writer owns the connection until it finishes. Even after a
    /// syntactically complete body, Connection: close and successful CONNECT
    /// prevent that connection from returning to the reusable state.
    reusable_after_finish: bool,
    /// Optional exact length enforced even when trailers force chunked wire
    /// framing.
    expected_length: ?usize,
    /// Captured from the start options so a later streaming terminator uses
    /// the same field-name policy as its request or response head.
    header_name_casing: HeaderNameCasing,
};

/// Reusable encoder storage owned by a persistent runtime connection.
///
/// Single non-chunked messages keep the application body outside `encoded`,
/// allowing the transport to use vectored I/O. A response batch is different:
/// it must be fully materialized before the first socket write so validation of
/// a later response cannot expose a valid prefix on the wire.
const BatchPart = union(enum) {
    encoded: struct { start: usize, len: usize },
    borrowed: []const u8,
};

const BatchScratch = struct {
    /// Independent contiguous transport staging. This cannot share `encoded`:
    /// prepared message heads may still borrow that storage while a
    /// connection-level flatten policy copies all parts.
    flattened: std.ArrayList(u8) = .empty,
    encoded: std.ArrayList(u8) = .empty,
    parts: std.ArrayList([]const u8) = .empty,
    part_descriptors: std.ArrayList(BatchPart) = .empty,

    fn reset(self: *BatchScratch) void {
        self.encoded.clearRetainingCapacity();
        self.parts.clearRetainingCapacity();
        self.part_descriptors.clearRetainingCapacity();
    }

    fn deinit(self: *BatchScratch, allocator: std.mem.Allocator) void {
        self.flattened.deinit(allocator);
        self.encoded.deinit(allocator);
        self.parts.deinit(allocator);
        self.part_descriptors.deinit(allocator);
        self.* = undefined;
    }
};

const TrailerScratch = struct {
    headers: std.ArrayList(http1.Header) = .empty,
    name_storage: std.ArrayList(u8) = .empty,
    value: std.ArrayList(u8) = .empty,

    fn reset(self: *TrailerScratch) void {
        self.headers.clearRetainingCapacity();
        self.name_storage.clearRetainingCapacity();
        self.value.clearRetainingCapacity();
    }

    fn deinit(self: *TrailerScratch, allocator: std.mem.Allocator) void {
        self.headers.deinit(allocator);
        self.name_storage.deinit(allocator);
        self.value.deinit(allocator);
        self.* = undefined;
    }
};

pub const StreamingChunkScratch = struct {
    descriptors: std.ArrayList(u8) = .empty,
    parts: std.ArrayList([]const u8) = .empty,

    fn reset(self: *StreamingChunkScratch) void {
        self.descriptors.clearRetainingCapacity();
        self.parts.clearRetainingCapacity();
    }

    fn deinit(
        self: *StreamingChunkScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.descriptors.deinit(allocator);
        self.parts.deinit(allocator);
        self.* = undefined;
    }
};

const content_length_buffer_len = std.fmt.count(
    "{d}",
    .{std.math.maxInt(usize)},
);

pub const Scratch = struct {
    encoded: std.ArrayList(u8) = .empty,
    batch: ?*BatchScratch = null,
    headers: std.ArrayList(http1.Header) = .empty,
    request_headers: std.ArrayList(http1.Header) = .empty,
    trailers: ?*TrailerScratch = null,
    streaming_chunks: ?*StreamingChunkScratch = null,
    content_length: [content_length_buffer_len]u8 = undefined,

    fn reset(self: *Scratch) void {
        self.encoded.clearRetainingCapacity();
        self.headers.clearRetainingCapacity();
        self.request_headers.clearRetainingCapacity();
        if (self.trailers) |trailers| trailers.reset();
        if (self.streaming_chunks) |chunks| chunks.reset();
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.encoded.deinit(allocator);
        if (self.batch) |batch| {
            batch.deinit(allocator);
            allocator.destroy(batch);
        }
        self.headers.deinit(allocator);
        self.request_headers.deinit(allocator);
        if (self.trailers) |trailers| {
            trailers.deinit(allocator);
            allocator.destroy(trailers);
        }
        if (self.streaming_chunks) |chunks| {
            chunks.deinit(allocator);
            allocator.destroy(chunks);
        }
        self.* = undefined;
    }

    fn batchScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*BatchScratch {
        if (self.batch) |batch| return batch;
        const batch = try allocator.create(BatchScratch);
        batch.* = .{};
        self.batch = batch;
        return batch;
    }

    pub fn flattenedBuffer(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*std.ArrayList(u8) {
        return &(try self.batchScratch(allocator)).flattened;
    }

    fn trailerScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*TrailerScratch {
        if (self.trailers) |trailers| return trailers;
        const trailers = try allocator.create(TrailerScratch);
        trailers.* = .{};
        self.trailers = trailers;
        return trailers;
    }

    pub fn trailerHeaders(self: *const Scratch) []const http1.Header {
        const trailers = self.trailers orelse return &.{};
        return trailers.headers.items;
    }

    pub fn streamingChunkScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*StreamingChunkScratch {
        if (self.streaming_chunks) |chunks| return chunks;
        const chunks = try allocator.create(StreamingChunkScratch);
        chunks.* = .{};
        self.streaming_chunks = chunks;
        return chunks;
    }
};

pub const MessageParts = struct {
    header: []const u8,
    body: []const u8,
};

/// Validate and encode only a request head for an incremental body writer.
fn prepareStreamingRequest(
    allocator: std.mem.Allocator,
    options: StreamingRequestOptions,
    scratch: *Scratch,
) Error!StreamingHead {
    if (options.version == .http_0_9) return error.InvalidVersion;
    scratch.reset();
    try http1.validateRequestTargetForMethod(options.method, options.target);
    if (options.method == .CONNECT) {
        // CONNECT changes the meaning of all subsequent bytes after its
        // response. Keep that lifecycle on the dedicated tunnel API.
        return error.InvalidContentLength;
    }

    const target_authority = http1.absoluteFormAuthority(options.target);
    try appendRequestHeadersWithHost(
        &scratch.request_headers,
        allocator,
        options.headers,
        options.host orelse target_authority,
    );
    try appendRequiredTeConnectionOption(
        &scratch.request_headers,
        allocator,
    );
    try http1.validateConnectionHeadersForWrite(
        options.version,
        scratch.request_headers.items,
    );
    try http1.validateRequestTeForWrite(
        options.version,
        scratch.request_headers.items,
    );
    try http1.validateHostHeaderBlock(
        options.version,
        scratch.request_headers.items,
    );
    if (target_authority) |authority| {
        const host = wire.findHeader(
            scratch.request_headers.items,
            "host",
        ) orelse return error.InvalidHost;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, host, " \t"),
            authority,
        )) return error.InvalidHost;
    }

    try http1.validateOutgoingRequestFramingForMethod(
        options.method,
        scratch.request_headers.items,
        options.body_length,
        options.trailer_names.len != 0,
    );

    const trailers_requested = hasHeader(
        scratch.request_headers.items,
        "trailer",
    ) or options.trailer_names.len != 0;
    const trailer_headers: []const http1.Header = if (trailers_requested) blk: {
        const trailers = try scratch.trailerScratch(allocator);
        try prepareTrailerNames(
            &trailers.headers,
            &trailers.name_storage,
            allocator,
            scratch.request_headers.items,
            options.trailer_names,
        );
        break :blk trailers.headers.items;
    } else &.{};
    const explicit_chunked = try chunkedWriteFraming(
        options.version,
        scratch.request_headers.items,
        trailer_headers,
    );
    if (trailers_requested and !explicit_chunked) {
        return error.InvalidTrailer;
    }
    const declared_length = try http1.contentLength(
        scratch.request_headers.items,
    );
    const use_chunked = explicit_chunked or
        (declared_length == null and options.body_length == null and
            requestUnknownLengthUsesChunked(options.method));
    if (use_chunked and options.version == .http_1_0) {
        return error.InvalidVersion;
    }
    const fixed_length: usize = if (use_chunked)
        0
    else if (options.body_length) |length|
        length
    else
        declared_length orelse 0;
    if (!use_chunked) {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    }
    const expected_length = if (use_chunked)
        options.body_length
    else
        fixed_length;
    try http1.validateRequestExpectForWrite(
        options.version,
        scratch.request_headers.items,
        if (use_chunked)
            options.body_length == null or options.body_length.? != 0
        else
            fixed_length != 0,
    );

    try appendDefaultedHeaders(
        &scratch.headers,
        allocator,
        scratch.request_headers.items,
        fixed_length,
        trailer_headers,
        use_chunked,
        shouldDefaultRequestContentLength(
            options.method,
            fixed_length,
            trailer_headers,
        ),
        &scratch.content_length,
        scratch,
        null,
    );
    try encodeRequestHead(allocator, options, scratch);
    return .{
        .head = scratch.encoded.items,
        .framing = if (use_chunked)
            .chunked
        else
            .{ .fixed = fixed_length },
        .reusable_after_finish = http1.headersKeepAlive(
            options.version,
            scratch.request_headers.items,
        ),
        .expected_length = expected_length,
        .header_name_casing = options.header_name_casing,
    };
}

/// Validate and encode only a response head for an incremental body writer.
fn prepareStreamingResponse(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    scratch: *Scratch,
) Error!StreamingHead {
    return prepareStreamingResponseWithDefaultDate(
        allocator,
        options,
        null,
        scratch,
    );
}

fn prepareStreamingResponseWithDefaultDate(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!StreamingHead {
    if (options.version == .http_0_9) return error.InvalidVersion;
    scratch.reset();
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        options.headers,
    );
    try http1.validateResponseTeForWrite(options.headers);
    try http1.validateResponseUpgradeForWrite(
        options.status,
        options.headers,
    );
    const trailers_requested = hasHeader(options.headers, "trailer") or
        options.trailer_names.len != 0;
    const trailer_headers: []const http1.Header = if (trailers_requested) blk: {
        const trailers = try scratch.trailerScratch(allocator);
        try prepareTrailerNames(
            &trailers.headers,
            &trailers.name_storage,
            allocator,
            options.headers,
            options.trailer_names,
        );
        break :blk trailers.headers.items;
    } else &.{};
    try http1.validateOutgoingResponseBodyForStatus(
        options.status,
        options.headers,
        &.{},
        trailer_headers,
    );

    const suppress_body = responseWriteSuppressesBody(
        options.status,
        options.request_method,
    );
    const explicit_chunked = try chunkedWriteFraming(
        options.version,
        options.headers,
        trailer_headers,
    );
    if (trailers_requested and !options.request_accepts_trailers) {
        return error.InvalidTrailer;
    }
    if (trailers_requested and !explicit_chunked) {
        return error.InvalidTrailer;
    }
    const head_response = if (options.request_method) |method|
        method == .HEAD
    else
        false;
    const metadata_only_transfer_encoding =
        (head_response or options.status == 304) and explicit_chunked;
    if (suppress_body and explicit_chunked and
        !metadata_only_transfer_encoding)
    {
        return error.InvalidTransferEncoding;
    }
    if (head_response and trailers_requested) return error.InvalidTrailer;
    const declared_length = try http1.contentLength(options.headers);
    const content_forbidden = options.status == 205;
    if (content_forbidden and (options.body_length orelse 0) != 0) {
        return error.InvalidContentLength;
    }
    if (content_forbidden and (declared_length orelse 0) != 0) {
        return error.InvalidContentLength;
    }
    const use_chunked = !suppress_body and
        (explicit_chunked or
            (declared_length == null and options.body_length == null and
                !content_forbidden));
    // A HEAD response may describe the transfer coding a corresponding GET
    // would use, but no chunk terminator follows the head. Preserve an
    // explicitly supplied coding while still returning suppressed framing.
    const header_uses_chunked = use_chunked or
        metadata_only_transfer_encoding;
    if (use_chunked and options.version == .http_1_0) {
        return error.InvalidVersion;
    }
    if (options.request_method != null and
        options.request_method.? == .CONNECT and
        options.status >= 200 and options.status < 300)
    {
        if (declared_length != null) return error.InvalidContentLength;
        if ((options.body_length orelse 0) != 0) {
            return error.InvalidContentLength;
        }
    }
    if (!use_chunked and !suppress_body) {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    }
    if (suppress_body and
        options.request_method != null and
        options.request_method.? == .HEAD)
    {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    } else if (suppress_body and
        http1.statusCodeForbidsBody(options.status) and
        (options.body_length orelse 0) != 0)
    {
        return error.InvalidContentLength;
    }

    const fixed_length: usize = if (use_chunked or suppress_body)
        0
    else
        options.body_length orelse declared_length orelse 0;
    try appendDefaultedHeaders(
        &scratch.headers,
        allocator,
        options.headers,
        if (suppress_body)
            options.body_length orelse 0
        else
            fixed_length,
        trailer_headers,
        header_uses_chunked,
        responseShouldDefaultContentLength(
            options.status,
            options.request_method,
        ),
        &scratch.content_length,
        scratch,
        if (responseStatusIsFinal(options.status)) default_date else null,
    );
    try encodeStreamingResponseHead(allocator, options, scratch);

    const successful_connect = options.request_method != null and
        options.request_method.? == .CONNECT and
        options.status >= 200 and options.status < 300;
    return .{
        .head = scratch.encoded.items,
        .framing = if (suppress_body)
            .suppressed
        else if (use_chunked)
            .chunked
        else
            .{ .fixed = fixed_length },
        .reusable_after_finish = !successful_connect and
            http1.headersKeepAlive(options.version, options.headers),
        .expected_length = if (suppress_body or content_forbidden)
            0
        else if (use_chunked)
            options.body_length
        else
            fixed_length,
        .header_name_casing = options.header_name_casing,
    };
}

test "HTTP/1 streaming framing honors explicit Trailer declarations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .method = .POST,
            .host = "localhost",
            .headers = &.{
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Trailer", .value = "Digest, X-Complete" },
            },
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        request.framing,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        scratch.trailerHeaders().len,
    );

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{
                    .{ .name = "Transfer-Encoding", .value = "chunked" },
                    .{ .name = "Trailer", .value = "Digest" },
                },
                .trailer_names = &.{"X-Complete"},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .trailer_names = &.{"Connection"},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingResponse(
            allocator,
            .{
                .trailer_names = &.{"Upgrade"},
                .request_accepts_trailers = true,
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingResponse(
            allocator,
            .{ .trailer_names = &.{"Digest"} },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareResponse(allocator, .{
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=demo",
            }},
        }, &scratch),
    );
    const response = try prepareStreamingResponse(
        allocator,
        .{
            .headers = &.{.{
                .name = "Trailer",
                .value = "Digest",
            }},
            .request_accepts_trailers = true,
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        response.framing,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            response.head,
            "Transfer-Encoding: chunked\r\n",
        ) != null,
    );

    const head_response = try prepareStreamingResponse(
        allocator,
        .{
            .request_method = .HEAD,
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        head_response.framing,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            head_response.head,
            "Transfer-Encoding: chunked\r\n",
        ) != null,
    );
}

test "HTTP/1 aggregate framing honors explicit Trailer declarations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(
        allocator,
        .{
            .method = .POST,
            .host = "localhost",
            .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=request",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 0), request.body.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        request.header,
        "2\r\nok\r\n0\r\nDigest: sha-256=request\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
                .trailers = &.{.{ .name = "X-Other", .value = "value" }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{.{
                    .name = "Trailer",
                    .value = "Content-Length",
                }},
            },
            &scratch,
        ),
    );

    const response = try prepareResponse(
        allocator,
        .{
            .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=response",
            }},
            .request_accepts_trailers = true,
        },
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 0), response.body.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        response.header,
        "2\r\nok\r\n0\r\nDigest: sha-256=response\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareResponse(
            allocator,
            .{
                .headers = &.{
                    .{ .name = "Transfer-Encoding", .value = "chunked" },
                    .{ .name = "Trailer", .value = "Digest" },
                },
                .trailers = &.{.{ .name = "X-Other", .value = "value" }},
                .request_accepts_trailers = true,
            },
            &scratch,
        ),
    );
}

test "HTTP/1 runtime request writer normalizes TE connection semantics" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{ .name = "TE", .value = "trailers" }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "TE: trailers\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Connection: TE\r\n",
    ) != null);

    const streaming_request = try prepareStreamingRequest(
        allocator,
        .{
            .host = "localhost",
            .body_length = 0,
            .headers = &.{.{ .name = "TE", .value = "trailers" }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_request.head,
        "Connection: TE\r\n",
    ) != null);

    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{ .name = "TE", .value = "chunked" }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareRequest(
            allocator,
            .{
                .version = .http_1_0,
                .headers = &.{.{ .name = "TE", .value = "trailers" }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareResponse(
            allocator,
            .{ .headers = &.{.{ .name = "TE", .value = "trailers" }} },
            &scratch,
        ),
    );
}

test "HTTP/1 runtime writers reject unsafe Connection options" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidConnection,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{
                    .{ .name = "Connection", .value = "Content-Length" },
                    .{ .name = "Content-Length", .value = "0" },
                },
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidConnection,
        prepareStreamingRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close, bad option",
                }},
                .body_length = 0,
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidConnection,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Upgrade",
                    .value = "websocket",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        prepareResponse(
            allocator,
            .{ .status = 101, .reason = "Switching Protocols" },
            &scratch,
        ),
    );

    const switching = try prepareResponse(
        allocator,
        .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = &.{
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Upgrade", .value = "websocket" },
            },
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        switching.header,
        "Connection: Upgrade\r\nUpgrade: websocket\r\n",
    ) != null);
}

test "HTTP/1 response writers enforce empty 205 content" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponse(allocator, .{
            .status = 205,
            .reason = "Reset Content",
            .body = "forbidden",
        }, &scratch),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponse(allocator, .{
            .status = 205,
            .reason = "Reset Content",
            .headers = &.{.{
                .name = "Content-Length",
                .value = "1",
            }},
        }, &scratch),
    );

    const fixed = try prepareResponse(allocator, .{
        .status = 205,
        .reason = "Reset Content",
    }, &scratch);
    try std.testing.expectEqualStrings("", fixed.body);
    try std.testing.expect(std.mem.indexOf(
        u8,
        fixed.header,
        "Content-Length: 0\r\n",
    ) != null);

    const chunked = try prepareResponse(allocator, .{
        .status = 205,
        .reason = "Reset Content",
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
    }, &scratch);
    try std.testing.expectEqualStrings("", chunked.body);
    try std.testing.expect(std.mem.endsWith(
        u8,
        chunked.header,
        "\r\n0\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponseParts(allocator, &.{
            .{ .body = "valid prefix" },
            .{ .status = 205, .body = "forbidden" },
        }, &scratch),
    );

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareStreamingResponse(allocator, .{
            .status = 205,
            .body_length = 1,
        }, &scratch),
    );
    const reset_streaming = try prepareStreamingResponse(allocator, .{
        .status = 205,
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
    }, &scratch);
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        reset_streaming.framing,
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        reset_streaming.expected_length,
    );
}

test "HTTP/1 304 response writers preserve metadata transfer coding" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);
    const headers = [_]http1.Header{
        .{ .name = "Content-Length", .value = "123" },
        .{ .name = "Transfer-Encoding", .value = "gzip, chunked" },
    };

    const aggregate = try prepareResponse(allocator, .{
        .status = 304,
        .reason = "Not Modified",
        .headers = &headers,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        aggregate.header,
        "Transfer-Encoding: gzip, chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        aggregate.header,
        "Content-Length:",
    ) == null);
    try std.testing.expect(std.mem.endsWith(u8, aggregate.header, "\r\n\r\n"));
    try std.testing.expect(!std.mem.endsWith(
        u8,
        aggregate.header,
        "\r\n0\r\n\r\n",
    ));
    try std.testing.expectEqualStrings("", aggregate.body);

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .status = 304,
        .reason = "Not Modified",
        .headers = &headers,
    }, &scratch);
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        streaming_head.framing,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Transfer-Encoding: gzip, chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Content-Length:",
    ) == null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        streaming_head.head,
        "\r\n\r\n",
    ));
}

test "HTTP/1 request writers enforce empty TRACE content" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareRequest(
            allocator,
            .{ .method = .TRACE, .host = "localhost", .body = "body" },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareRequest(
            allocator,
            .{
                .method = .TRACE,
                .host = "localhost",
                .headers = &.{.{
                    .name = "Transfer-Encoding",
                    .value = "chunked",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .TRACE,
                .host = "localhost",
                .body_length = 1,
            },
            &scratch,
        ),
    );

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .method = .TRACE,
            .host = "localhost",
        },
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming{ .fixed = 0 }, request.framing);
    try std.testing.expect(
        std.mem.indexOf(u8, request.head, "Transfer-Encoding:") == null,
    );
}

test "HTTP/1 request writers validate 100-continue expectations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidExpectation,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Expect",
                    .value = "100-continue",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidExpectation,
        prepareStreamingRequest(
            allocator,
            .{
                .host = "localhost",
                .body_length = 0,
                .headers = &.{.{
                    .name = "Expect",
                    .value = "100-continue",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidExpectation,
        prepareResponse(
            allocator,
            .{ .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }} },
            &scratch,
        ),
    );

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming.chunked, request.framing);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.head,
        "Expect: 100-continue\r\n",
    ) != null);

    const extension = try prepareRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "custom=value; mode=fast",
            }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        extension.header,
        "Expect: custom=value; mode=fast\r\n",
    ) != null);
}

test "HTTP/1 runtime response writers preserve an empty reason separator" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const aggregate = try prepareResponse(allocator, .{
        .status = 204,
        .reason = "",
    }, &scratch);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 204 \r\n\r\n",
        aggregate.header,
    );

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .status = 204,
        .reason = "",
    }, &scratch);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 204 \r\n\r\n",
        streaming_head.head,
    );
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        streaming_head.framing,
    );
}

test "HTTP/1 writer preserves or title-cases request and response fields" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const preserved = try prepareRequest(allocator, .{
        .host = "example.com",
        .headers = &.{.{ .name = "x-TRACE-id", .value = "one" }},
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        preserved.header,
        "x-TRACE-id: one\r\n",
    ) != null);

    const request = try prepareRequest(allocator, .{
        .host = "example.com",
        .headers = &.{.{ .name = "x-TRACE-id", .value = "one" }},
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "X-Trace-Id: one\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Host: example.com\r\n",
    ) != null);

    const response = try prepareResponse(allocator, .{
        .headers = &.{.{ .name = "cOnTeNt-TyPe", .value = "text/plain" }},
        .body = "ok",
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.header,
        "Content-Type: text/plain\r\n",
    ) != null);
}

test "HTTP/1 title-case policy applies to merged chunked trailers" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const message = try prepareResponse(allocator, .{
        .headers = &.{.{
            .name = "transfer-encoding",
            .value = "chunked",
        }},
        .body = "ok",
        .trailers = &.{
            .{ .name = "x-checkSUM", .value = "one" },
            .{ .name = "X-CHECKsum", .value = "two" },
        },
        .request_accepts_trailers = true,
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        message.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        message.header,
        "0\r\nX-Checksum: one, two\r\n\r\n",
    ) != null);

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .headers = &.{.{
            .name = "transfer-encoding",
            .value = "chunked",
        }},
        .trailer_names = &.{"x-checksum"},
        .request_accepts_trailers = true,
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    const end = try streaming.prepareEndWithCasing(
        allocator,
        &.{
            .{ .name = "x-checkSUM", .value = "one" },
            .{ .name = "X-CHECKsum", .value = "two" },
        },
        &scratch,
        streaming_head.header_name_casing,
    );
    try std.testing.expectEqualStrings(
        "0\r\nX-Checksum: one, two\r\n\r\n",
        end,
    );
}

test "HTTP/1 streaming terminator rejects malformed trailers before encoding" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);
    try scratch.encoded.appendSlice(allocator, "stale");

    try std.testing.expectError(
        error.MalformedHeader,
        streaming.prepareEnd(
            allocator,
            &.{.{
                .name = "X-Trace",
                .value = "ok\r\nInjected: yes",
            }},
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.encoded.items.len);
}

/// Validate and encode a request, borrowing an unframed body when possible.
pub fn prepareRequest(
    allocator: std.mem.Allocator,
    options: RequestOptions,
    scratch: *Scratch,
) Error!MessageParts {
    if (options.version == .http_0_9) return error.InvalidVersion;
    scratch.reset();
    try http1.validateRequestTargetForMethod(options.method, options.target);
    const target_authority = if (options.method == .CONNECT)
        options.target
    else
        http1.absoluteFormAuthority(options.target);
    const synthesized_host = options.host orelse target_authority;
    try appendRequestHeadersWithHost(
        &scratch.request_headers,
        allocator,
        options.headers,
        synthesized_host,
    );
    try appendRequiredTeConnectionOption(
        &scratch.request_headers,
        allocator,
    );
    try http1.validateConnectionHeadersForWrite(
        options.version,
        scratch.request_headers.items,
    );
    try http1.validateRequestTeForWrite(
        options.version,
        scratch.request_headers.items,
    );
    try http1.validateHostHeaderBlock(
        options.version,
        scratch.request_headers.items,
    );
    if (target_authority) |authority| {
        const host = wire.findHeader(
            scratch.request_headers.items,
            "host",
        ) orelse return error.InvalidHost;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, host, " \t"),
            authority,
        )) {
            return error.InvalidHost;
        }
    }
    try http1.validateOutgoingRequestBodyForMethod(
        options.method,
        scratch.request_headers.items,
        options.body,
        options.trailers,
    );
    try http1.validateTrailerDeclarations(
        scratch.request_headers.items,
        options.trailers,
    );
    const use_chunked = try chunkedWriteFraming(
        options.version,
        scratch.request_headers.items,
        options.trailers,
    );
    try validateDeclaredRequestBodyLength(
        scratch.request_headers.items,
        options.body.len,
        use_chunked,
    );
    try http1.validateRequestExpectForWrite(
        options.version,
        scratch.request_headers.items,
        options.body.len != 0,
    );

    try appendDefaultedHeaders(
        &scratch.headers,
        allocator,
        scratch.request_headers.items,
        options.body.len,
        options.trailers,
        use_chunked,
        shouldDefaultRequestContentLength(
            options.method,
            options.body.len,
            options.trailers,
        ),
        &scratch.content_length,
        scratch,
        null,
    );

    try encodeRequestHead(allocator, options, scratch);
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            &scratch.encoded,
            allocator,
            &chunks,
            options.trailers,
            options.header_name_casing,
        );
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    return .{ .header = scratch.encoded.items, .body = options.body };
}

/// Validate and encode a response, borrowing an unframed body when possible.
pub fn prepareResponse(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    scratch: *Scratch,
) Error!MessageParts {
    return prepareResponseWithDefaultDate(
        allocator,
        options,
        null,
        scratch,
    );
}

/// Runtime-only response preparation with an optional generated Date value.
/// The pure codec entry point above intentionally remains deterministic.
pub fn prepareServerResponse(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!MessageParts {
    return prepareResponseWithDefaultDate(
        allocator,
        options,
        if (responseStatusIsFinal(options.status)) default_date else null,
        scratch,
    );
}

fn prepareResponseWithDefaultDate(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!MessageParts {
    if (options.version == .http_0_9) return error.InvalidVersion;
    scratch.reset();
    const framing = try prepareResponseFraming(
        allocator,
        options,
        default_date,
        scratch,
    );
    try encodeResponseHead(allocator, options, scratch);

    if (framing.suppress_body) {
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    if (framing.use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            &scratch.encoded,
            allocator,
            &chunks,
            options.trailers,
            options.header_name_casing,
        );
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    return .{ .header = scratch.encoded.items, .body = options.body };
}

/// Validate a complete response pipeline and prepare borrowed write slices.
///
/// Heads and chunked messages are retained in `batch.encoded`; ordinary
/// fixed bodies remain borrowed. Descriptors use offsets while encoded storage
/// grows, then resolve to stable slices only after every response validates.
pub fn prepareResponseParts(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    scratch: *Scratch,
) Error![]const []const u8 {
    return prepareResponsePartsWithDefaultDate(
        allocator,
        responses,
        null,
        scratch,
    );
}

/// Runtime-only batch preparation with one cached Date value shared by every
/// final response that does not already provide the field.
pub fn prepareServerResponseParts(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error![]const []const u8 {
    // `default_date` may borrow a thread-local cache. Every encoded head is
    // copied into Scratch before this function returns, so callers can refresh
    // that cache immediately after the synchronous preparation completes.
    return prepareResponsePartsWithDefaultDate(
        allocator,
        responses,
        default_date,
        scratch,
    );
}

fn prepareResponsePartsWithDefaultDate(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error![]const []const u8 {
    const batch = try scratch.batchScratch(allocator);
    batch.reset();
    try batch.part_descriptors.ensureTotalCapacity(
        allocator,
        responses.len *| 2,
    );
    for (responses) |response| {
        scratch.encoded.clearRetainingCapacity();
        scratch.headers.clearRetainingCapacity();
        scratch.request_headers.clearRetainingCapacity();
        if (scratch.trailers) |trailers| {
            trailers.value.clearRetainingCapacity();
        }

        const framing = try prepareResponseFraming(
            allocator,
            response,
            if (responseStatusIsFinal(response.status))
                default_date
            else
                null,
            scratch,
        );
        try encodeResponseHead(allocator, response, scratch);
        const head_start = batch.encoded.items.len;
        try batch.encoded.appendSlice(
            allocator,
            scratch.encoded.items,
        );
        batch.part_descriptors.appendAssumeCapacity(.{
            .encoded = .{
                .start = head_start,
                .len = scratch.encoded.items.len,
            },
        });
        if (!framing.suppress_body) {
            if (framing.use_chunked) {
                scratch.encoded.clearRetainingCapacity();
                const chunks = [_][]const u8{response.body};
                try encodeChunked(
                    &scratch.encoded,
                    allocator,
                    &chunks,
                    response.trailers,
                    response.header_name_casing,
                );
                const chunk_start = batch.encoded.items.len;
                try batch.encoded.appendSlice(
                    allocator,
                    scratch.encoded.items,
                );
                batch.part_descriptors.appendAssumeCapacity(.{
                    .encoded = .{
                        .start = chunk_start,
                        .len = scratch.encoded.items.len,
                    },
                });
            } else {
                batch.part_descriptors.appendAssumeCapacity(.{
                    .borrowed = response.body,
                });
            }
        }
    }
    try batch.parts.ensureTotalCapacity(
        allocator,
        batch.part_descriptors.items.len,
    );
    for (batch.part_descriptors.items) |descriptor| {
        batch.parts.appendAssumeCapacity(switch (descriptor) {
            .encoded => |range| batch.encoded.items[range.start .. range.start + range.len],
            .borrowed => |body| body,
        });
    }
    return batch.parts.items;
}

test "HTTP/1 write scratch allocates batch state lazily" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(BatchScratch));
        try std.testing.expectEqual(@as(usize, 120), @sizeOf(Scratch));
        try std.testing.expectEqual(
            @as(usize, 20),
            @sizeOf(@FieldType(Scratch, "content_length")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "batch")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    try std.testing.expect(scratch.batch == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.batchScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.batch == null);

    const batch = try scratch.batchScratch(allocator);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectEqual(
        @intFromPtr(batch),
        @intFromPtr(try scratch.batchScratch(no_alloc.allocator())),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/1 write scratch allocates multi-chunk state lazily" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @as(usize, 48),
            @sizeOf(StreamingChunkScratch),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "streaming_chunks")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    try std.testing.expect(scratch.streaming_chunks == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.streamingChunkScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.streaming_chunks == null);

    const chunks = try scratch.streamingChunkScratch(allocator);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectEqual(
        @intFromPtr(chunks),
        @intFromPtr(try scratch.streamingChunkScratch(no_alloc.allocator())),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/1 write scratch allocates trailer state only when requested" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 72), @sizeOf(TrailerScratch));
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "trailers")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    _ = try prepareRequest(allocator, .{
        .host = "localhost",
    }, &scratch);
    try std.testing.expect(scratch.trailers == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.trailerScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.trailers == null);

    const options = StreamingRequestOptions{
        .method = .POST,
        .host = "localhost",
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
        .trailer_names = &.{"Digest"},
    };
    const prepared = try prepareStreamingRequest(allocator, options, &scratch);
    try std.testing.expectEqual(StreamingFraming.chunked, prepared.framing);
    try std.testing.expectEqual(@as(usize, 1), scratch.trailerHeaders().len);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const warmed = try prepareStreamingRequest(
        no_alloc.allocator(),
        options,
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming.chunked, warmed.framing);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "HTTP/1 warmed response batch reuses lazy scratch" {
    const allocator = std.testing.allocator;
    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    const responses = [_]ResponseOptions{
        .{ .body = "one" },
        .{ .body = "two" },
    };
    _ = try prepareResponseParts(allocator, &responses, &scratch);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const parts = try prepareResponseParts(
        no_alloc.allocator(),
        &responses,
        &scratch,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), parts.len);
}

const ResponseFraming = struct {
    use_chunked: bool,
    suppress_body: bool,
};

fn prepareResponseFraming(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!ResponseFraming {
    if (options.version == .http_0_9) return error.InvalidVersion;
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        options.headers,
    );
    try http1.validateResponseTeForWrite(options.headers);
    try http1.validateResponseExpectForWrite(options.headers);
    try http1.validateResponseUpgradeForWrite(
        options.status,
        options.headers,
    );
    try http1.validateOutgoingResponseBodyForStatus(
        options.status,
        options.headers,
        options.body,
        options.trailers,
    );
    try http1.validateTrailerDeclarations(
        options.headers,
        options.trailers,
    );
    if ((options.trailers.len != 0 or
        hasHeader(options.headers, "trailer")) and
        !options.request_accepts_trailers)
    {
        return error.InvalidTrailer;
    }
    const use_chunked = try chunkedWriteFraming(
        options.version,
        options.headers,
        options.trailers,
    );
    try validateDeclaredResponseBodyLength(
        options.status,
        options.request_method,
        options.headers,
        options.body.len,
        options.trailers.len,
        use_chunked,
    );
    const suppress_body = responseWriteSuppressesBody(
        options.status,
        options.request_method,
    );
    try appendDefaultedHeaders(
        &scratch.headers,
        allocator,
        options.headers,
        options.body.len,
        options.trailers,
        use_chunked,
        responseShouldDefaultContentLength(
            options.status,
            options.request_method,
        ),
        &scratch.content_length,
        scratch,
        default_date,
    );
    return .{
        .use_chunked = use_chunked,
        .suppress_body = suppress_body,
    };
}

fn encodeResponseHead(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimal(encoded, allocator, options.status);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.reason);
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        scratch.headers.items,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn encodeRequestHead(
    allocator: std.mem.Allocator,
    options: anytype,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.method.string());
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.target);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        scratch.headers.items,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn encodeStreamingResponseHead(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimal(encoded, allocator, options.status);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.reason);
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        scratch.headers.items,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn appendRequestHeadersWithHost(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    host: ?[]const u8,
) Error!void {
    var has_host = false;
    try list.ensureUnusedCapacity(allocator, headers.len + 1);
    for (headers) |header| {
        if (header.eqlName("host")) has_host = true;
        list.appendAssumeCapacity(header);
    }
    if (!has_host) {
        if (host) |value| {
            list.appendAssumeCapacity(.{ .name = "Host", .value = value });
        }
    }
}

fn appendRequiredTeConnectionOption(
    headers: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
) Error!void {
    if (!hasHeader(headers.items, "te") or
        wire.anyHeaderContainsToken(headers.items, "connection", "te"))
    {
        return;
    }
    try headers.append(allocator, .{ .name = "Connection", .value = "TE" });
}

fn prepareTrailerNames(
    headers: *std.ArrayList(http1.Header),
    storage: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    initial_headers: []const http1.Header,
    names: []const []const u8,
) Error!void {
    var candidate_count: usize = names.len;
    var storage_len: usize = 0;
    for (initial_headers) |header| {
        if (!header.eqlName("trailer")) continue;
        var values = std.mem.splitScalar(u8, header.value, ',');
        while (values.next()) |raw_name| {
            const name = std.mem.trim(u8, raw_name, " \t");
            candidate_count = std.math.add(
                usize,
                candidate_count,
                1,
            ) catch return error.InvalidTrailer;
            storage_len = std.math.add(
                usize,
                storage_len,
                name.len,
            ) catch return error.InvalidTrailer;
        }
    }
    for (names) |name| {
        storage_len = std.math.add(
            usize,
            storage_len,
            name.len,
        ) catch return error.InvalidTrailer;
    }
    // The writer retains these descriptors until finishTrailers. Copy the
    // caller's names into connection-owned scratch and reserve once so later
    // appends cannot move bytes underneath earlier Header slices.
    try storage.ensureUnusedCapacity(allocator, storage_len);
    try headers.ensureUnusedCapacity(allocator, candidate_count);

    var explicit_trailer_header = false;
    for (initial_headers) |header| {
        if (!header.eqlName("trailer")) continue;
        explicit_trailer_header = true;
        var values = std.mem.splitScalar(u8, header.value, ',');
        while (values.next()) |raw_name| {
            const name = std.mem.trim(u8, raw_name, " \t");
            try appendTrailerName(headers, storage, name);
        }
    }

    for (names) |name| {
        if (explicit_trailer_header) {
            if (!headerNamePresent(headers.items, name)) {
                // A caller-supplied Trailer header is authoritative. Silently
                // adding a different name to writer state would emit a field
                // that was never announced on the wire.
                return error.InvalidTrailer;
            }
        } else {
            try appendTrailerName(headers, storage, name);
        }
    }
    try http1.validateTrailers(headers.items);
}

fn appendTrailerName(
    headers: *std.ArrayList(http1.Header),
    storage: *std.ArrayList(u8),
    name: []const u8,
) Error!void {
    try http1.validateHeaderName(name);
    if (headerNamePresent(headers.items, name)) return;
    const start = storage.items.len;
    storage.appendSliceAssumeCapacity(name);
    headers.appendAssumeCapacity(.{
        .name = storage.items[start..],
        .value = "",
    });
}

fn headerNamePresent(
    headers: []const http1.Header,
    name: []const u8,
) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn appendDefaultedHeaders(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    add_default_content_length: bool,
    len_buf: *[content_length_buffer_len]u8,
    scratch: *Scratch,
    default_date: ?[]const u8,
) Error!void {
    var has_content_length = false;
    var has_transfer_encoding = false;
    var has_trailer = false;
    try list.ensureUnusedCapacity(allocator, headers.len + 3);
    for (headers) |header| {
        if (header.eqlName("content-length")) has_content_length = true;
        if (header.eqlName("transfer-encoding")) {
            has_transfer_encoding = true;
        }
        if (header.eqlName("trailer")) has_trailer = true;
        if (use_chunked and header.eqlName("content-length")) continue;
        list.appendAssumeCapacity(header);
    }
    if (!use_chunked and trailers.len != 0) return error.InvalidTrailer;
    if (use_chunked) {
        if (!has_transfer_encoding) {
            list.appendAssumeCapacity(.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            });
        }
        if (trailers.len != 0 and !has_trailer) {
            const trailer_scratch = try scratch.trailerScratch(allocator);
            try renderTrailerHeaderValue(
                &trailer_scratch.value,
                allocator,
                trailers,
            );
            list.appendAssumeCapacity(.{
                .name = "Trailer",
                .value = trailer_scratch.value.items,
            });
        }
    } else if (add_default_content_length and !has_content_length) {
        const rendered = std.fmt.bufPrint(
            len_buf,
            "{}",
            .{body_len},
        ) catch unreachable;
        list.appendAssumeCapacity(.{
            .name = "Content-Length",
            .value = rendered,
        });
    }
    if (default_date) |value| {
        if (!hasHeader(headers, "date")) {
            list.appendAssumeCapacity(.{ .name = "Date", .value = value });
        }
    }
}

fn responseStatusIsFinal(status: u16) bool {
    return status == 101 or status >= 200;
}

fn shouldDefaultRequestContentLength(
    method: http1.Method,
    body_len: usize,
    trailers: []const http1.Header,
) bool {
    if (body_len != 0 or trailers.len != 0) return true;
    return switch (method) {
        .GET, .HEAD, .CONNECT => false,
        else => true,
    };
}

fn requestUnknownLengthUsesChunked(method: http1.Method) bool {
    return switch (method) {
        // Match Hyper's conservative default: these methods usually carry no
        // entity, but callers can still opt in with body_length or an explicit
        // Transfer-Encoding header.
        .GET, .HEAD, .CONNECT, .TRACE => false,
        else => true,
    };
}

fn validateDeclaredRequestBodyLength(
    headers: []const http1.Header,
    body_len: usize,
    use_chunked: bool,
) Error!void {
    if (use_chunked) return;
    if (try http1.contentLength(headers)) |len| {
        // Sending a different length would desynchronize the peer and corrupt
        // the next message on a persistent connection.
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn validateDeclaredResponseBodyLength(
    status: u16,
    request_method: ?http1.Method,
    headers: []const http1.Header,
    body_len: usize,
    trailers_len: usize,
    use_chunked: bool,
) Error!void {
    if (request_method) |method| {
        if (method == .CONNECT and status >= 200 and status < 300) {
            if (use_chunked) return error.InvalidTransferEncoding;
            // A successful CONNECT switches to tunnel bytes immediately after
            // the head, so even Content-Length: 0 is ambiguous to middleware.
            if (body_len != 0 or
                (try http1.contentLength(headers)) != null)
            {
                return error.InvalidContentLength;
            }
            return;
        }
        if (method == .HEAD) {
            if (trailers_len != 0) return error.InvalidTrailer;
            if (try http1.contentLength(headers)) |len| {
                if (body_len != 0 and len != body_len) {
                    return error.InvalidContentLength;
                }
            }
            return;
        }
    }
    if (use_chunked or status == 304) return;
    if (try http1.contentLength(headers)) |len| {
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn responseWriteSuppressesBody(
    status: u16,
    request_method: ?http1.Method,
) bool {
    if (http1.statusCodeForbidsBody(status)) return true;
    if (request_method) |method| {
        if (method == .HEAD) return true;
        if (method == .CONNECT and status >= 200 and status < 300) {
            return true;
        }
    }
    return false;
}

fn responseShouldDefaultContentLength(
    status: u16,
    request_method: ?http1.Method,
) bool {
    if (http1.statusCodeForbidsBody(status)) return false;
    if (request_method) |method| {
        // The bytes after a successful CONNECT head are tunnel data, not an
        // HTTP body. Avoid synthesizing framing that intermediaries may reject.
        if (method == .CONNECT and status >= 200 and status < 300) {
            return false;
        }
    }
    return true;
}

fn chunkedWriteFraming(
    version: http1.Version,
    headers: []const http1.Header,
    trailers: []const http1.Header,
) Error!bool {
    var has_transfer_encoding = false;
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) {
            has_transfer_encoding = true;
            break;
        }
    }
    if (has_transfer_encoding) {
        // This runtime only knows how to emit chunked transfer coding. Never
        // put a raw body under a caller-provided unsupported coding.
        if ((try http1.bodyFraming(headers)) != .chunked) {
            return error.InvalidTransferEncoding;
        }
        if (version == .http_1_0) return error.InvalidVersion;
        return true;
    }
    if (trailers.len == 0 and !hasHeader(headers, "trailer")) return false;
    if (version == .http_1_0) return error.InvalidVersion;
    return true;
}

fn renderTrailerHeaderValue(
    value: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    trailers: []const http1.Header,
) Error!void {
    value.clearRetainingCapacity();
    var rendered_len: usize = 0;
    var unique_count: usize = 0;
    for (trailers, 0..) |trailer, index| {
        var duplicate = false;
        for (trailers[0..index]) |prior| {
            if (trailer.eqlName(prior.name)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (unique_count != 0) {
            rendered_len = std.math.add(
                usize,
                rendered_len,
                2,
            ) catch return error.InvalidTrailer;
        }
        rendered_len = std.math.add(
            usize,
            rendered_len,
            trailer.name.len,
        ) catch return error.InvalidTrailer;
        unique_count += 1;
    }
    try value.ensureUnusedCapacity(allocator, rendered_len);

    for (trailers, 0..) |trailer, index| {
        var duplicate = false;
        for (trailers[0..index]) |prior| {
            if (trailer.eqlName(prior.name)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (value.items.len != 0) value.appendSliceAssumeCapacity(", ");
        value.appendSliceAssumeCapacity(trailer.name);
    }
}

fn appendDecimal(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: anytype,
) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(
        &tmp,
        "{}",
        .{value},
    ) catch return error.InvalidResponse;
    try list.appendSlice(allocator, rendered);
}

fn appendHeaderNameAssumeCapacity(
    list: *std.ArrayList(u8),
    name: []const u8,
    casing: HeaderNameCasing,
) void {
    switch (casing) {
        .preserve => list.appendSliceAssumeCapacity(name),
        .title_case => {
            var capitalize = true;
            for (name) |byte| {
                list.appendAssumeCapacity(if (capitalize)
                    std.ascii.toUpper(byte)
                else
                    std.ascii.toLower(byte));
                capitalize = byte == '-';
            }
        },
    }
}

fn writeHeaderLines(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    casing: HeaderNameCasing,
) Error!void {
    var rendered_len: usize = 0;
    for (headers) |header| {
        try http1.validateHeader(header);
        rendered_len = std.math.add(
            usize,
            rendered_len,
            header.name.len,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            2,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            header.value.len,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            2,
        ) catch return error.InvalidResponse;
    }
    try list.ensureUnusedCapacity(allocator, rendered_len);
    for (headers) |header| {
        appendHeaderNameAssumeCapacity(list, header.name, casing);
        list.appendSliceAssumeCapacity(": ");
        list.appendSliceAssumeCapacity(header.value);
        list.appendSliceAssumeCapacity("\r\n");
    }
}

fn writeMergedHeaderLines(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    casing: HeaderNameCasing,
) Error!void {
    var written = try std.ArrayList(bool).initCapacity(
        allocator,
        headers.len,
    );
    defer written.deinit(allocator);
    try written.appendNTimes(allocator, false, headers.len);

    for (headers, 0..) |header, index| {
        if (written.items[index]) continue;
        try http1.validateHeader(header);
        try list.ensureUnusedCapacity(allocator, header.name.len);
        appendHeaderNameAssumeCapacity(list, header.name, casing);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        written.items[index] = true;

        var next = index + 1;
        while (next < headers.len) : (next += 1) {
            if (written.items[next]) continue;
            const duplicate = headers[next];
            if (!header.eqlName(duplicate.name)) continue;
            try http1.validateHeader(duplicate);
            // Keep the first spelling and merge repeated trailer values into
            // one field line, matching Hyper's behavior.
            try list.appendSlice(allocator, ", ");
            try list.appendSlice(allocator, duplicate.value);
            written.items[next] = true;
        }
        try list.appendSlice(allocator, "\r\n");
    }
}

fn encodeChunked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chunks: []const []const u8,
    trailers: []const http1.Header,
    casing: HeaderNameCasing,
) Error!void {
    try http1.validateTrailers(trailers);
    for (chunks) |chunk| {
        // A zero-length chunk is the terminator. Empty payload slices therefore
        // emit no DATA, leaving one terminator after all chunks and trailers.
        if (chunk.len == 0) continue;
        var tmp: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(
            &tmp,
            "{x}\r\n",
            .{chunk.len},
        ) catch return error.InvalidResponse;
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeMergedHeaderLines(list, allocator, trailers, casing);
    try list.appendSlice(allocator, "\r\n");
}

/// Runtime-facing namespace for the stateful body writer.
///
/// Keeping the head/framing helpers behind this narrow surface prevents the
/// complete-message encoder's scratch details from becoming public API.
pub const streaming = struct {
    pub const RequestOptions = StreamingRequestOptions;
    pub const ResponseOptions = StreamingResponseOptions;
    pub const Framing = StreamingFraming;
    pub const Head = StreamingHead;

    pub fn prepareRequest(
        allocator: std.mem.Allocator,
        options: StreamingRequestOptions,
        scratch: *Scratch,
    ) Error!Head {
        return prepareStreamingRequest(allocator, options, scratch);
    }

    pub fn prepareResponse(
        allocator: std.mem.Allocator,
        options: StreamingResponseOptions,
        scratch: *Scratch,
    ) Error!Head {
        return prepareStreamingResponse(allocator, options, scratch);
    }

    /// Runtime-only streaming response preparation with an optional generated
    /// Date value. The Date slice is consumed while encoding the returned head.
    pub fn prepareServerResponse(
        allocator: std.mem.Allocator,
        options: StreamingResponseOptions,
        default_date: ?[]const u8,
        scratch: *Scratch,
    ) Error!Head {
        // The returned head owns the rendered field bytes in Scratch rather
        // than borrowing `default_date`.
        return prepareStreamingResponseWithDefaultDate(
            allocator,
            options,
            default_date,
            scratch,
        );
    }

    /// Encode the unique terminating chunk and merged trailer field lines.
    ///
    /// This runs before any transport write, so malformed trailers and
    /// allocation failures cannot expose a partial terminator on the wire.
    pub fn prepareEnd(
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
        scratch: *Scratch,
    ) Error![]const u8 {
        return prepareEndWithCasing(
            allocator,
            trailers,
            scratch,
            .preserve,
        );
    }

    pub fn prepareEndWithCasing(
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
        scratch: *Scratch,
        casing: HeaderNameCasing,
    ) Error![]const u8 {
        scratch.encoded.clearRetainingCapacity();
        try http1.validateTrailers(trailers);
        try scratch.encoded.appendSlice(allocator, "0\r\n");
        try writeMergedHeaderLines(
            &scratch.encoded,
            allocator,
            trailers,
            casing,
        );
        try scratch.encoded.appendSlice(allocator, "\r\n");
        return scratch.encoded.items;
    }
};
