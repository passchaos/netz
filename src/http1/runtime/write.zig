const std = @import("std");
const http1 = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");

pub const Error = http1.Error || error{InvalidResponse};

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
};

pub const ResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
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
};

/// Reusable encoder storage owned by a persistent runtime connection.
///
/// Single non-chunked messages keep the application body outside `encoded`,
/// allowing the transport to use vectored I/O. A response batch is different:
/// it must be fully materialized before the first socket write so validation of
/// a later response cannot expose a valid prefix on the wire.
pub const Scratch = struct {
    encoded: std.ArrayList(u8) = .empty,
    batch_encoded: std.ArrayList(u8) = .empty,
    headers: std.ArrayList(http1.Header) = .empty,
    request_headers: std.ArrayList(http1.Header) = .empty,
    trailer_headers: std.ArrayList(http1.Header) = .empty,
    trailer_name_storage: std.ArrayList(u8) = .empty,
    trailer_value: std.ArrayList(u8) = .empty,
    streaming_chunk_descriptors: std.ArrayList(u8) = .empty,
    streaming_parts: std.ArrayList([]const u8) = .empty,
    content_length: [32]u8 = undefined,

    fn reset(self: *Scratch) void {
        self.encoded.clearRetainingCapacity();
        self.headers.clearRetainingCapacity();
        self.request_headers.clearRetainingCapacity();
        self.trailer_headers.clearRetainingCapacity();
        self.trailer_name_storage.clearRetainingCapacity();
        self.trailer_value.clearRetainingCapacity();
        self.streaming_chunk_descriptors.clearRetainingCapacity();
        self.streaming_parts.clearRetainingCapacity();
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.encoded.deinit(allocator);
        self.batch_encoded.deinit(allocator);
        self.headers.deinit(allocator);
        self.request_headers.deinit(allocator);
        self.trailer_headers.deinit(allocator);
        self.trailer_name_storage.deinit(allocator);
        self.trailer_value.deinit(allocator);
        self.streaming_chunk_descriptors.deinit(allocator);
        self.streaming_parts.deinit(allocator);
        self.* = undefined;
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

    try prepareTrailerNames(
        &scratch.trailer_headers,
        &scratch.trailer_name_storage,
        allocator,
        scratch.request_headers.items,
        options.trailer_names,
    );
    const explicit_chunked = try chunkedWriteFraming(
        options.version,
        scratch.request_headers.items,
        scratch.trailer_headers.items,
    );
    const trailers_requested = hasHeader(
        scratch.request_headers.items,
        "trailer",
    ) or options.trailer_names.len != 0;
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

    try appendDefaultedHeaders(
        &scratch.headers,
        allocator,
        scratch.request_headers.items,
        fixed_length,
        scratch.trailer_headers.items,
        use_chunked,
        shouldDefaultRequestContentLength(
            options.method,
            fixed_length,
            scratch.trailer_headers.items,
        ),
        &scratch.content_length,
        &scratch.trailer_value,
    );
    try encodeRequestHead(allocator, options, scratch);
    return .{
        .head = scratch.encoded.items,
        .framing = if (use_chunked)
            .chunked
        else
            .{ .fixed = fixed_length },
        .reusable_after_finish = messageKeepAlive(
            options.version,
            scratch.request_headers.items,
        ),
        .expected_length = expected_length,
    };
}

/// Validate and encode only a response head for an incremental body writer.
fn prepareStreamingResponse(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    scratch: *Scratch,
) Error!StreamingHead {
    scratch.reset();
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try prepareTrailerNames(
        &scratch.trailer_headers,
        &scratch.trailer_name_storage,
        allocator,
        options.headers,
        options.trailer_names,
    );
    try http1.validateResponseBodyForStatus(
        options.status,
        options.headers,
        &.{},
        scratch.trailer_headers.items,
    );

    const suppress_body = responseWriteSuppressesBody(
        options.status,
        options.request_method,
    );
    const explicit_chunked = try chunkedWriteFraming(
        options.version,
        options.headers,
        scratch.trailer_headers.items,
    );
    const trailers_requested = hasHeader(options.headers, "trailer") or
        options.trailer_names.len != 0;
    if (trailers_requested and !explicit_chunked) {
        return error.InvalidTrailer;
    }
    const head_response = options.request_method == .HEAD;
    if (suppress_body and explicit_chunked and !head_response) {
        return error.InvalidTransferEncoding;
    }
    if (head_response and trailers_requested) return error.InvalidTrailer;
    const declared_length = try http1.contentLength(options.headers);
    const use_chunked = !suppress_body and
        (explicit_chunked or
            (declared_length == null and options.body_length == null));
    // A HEAD response may describe the transfer coding a corresponding GET
    // would use, but no chunk terminator follows the head. Preserve an
    // explicitly supplied coding while still returning suppressed framing.
    const header_uses_chunked = use_chunked or
        (head_response and explicit_chunked);
    if (use_chunked and options.version == .http_1_0) {
        return error.InvalidVersion;
    }
    if (options.request_method == .CONNECT and
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
    if (suppress_body and options.request_method == .HEAD) {
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
        scratch.trailer_headers.items,
        header_uses_chunked,
        responseShouldDefaultContentLength(
            options.status,
            options.request_method,
        ),
        &scratch.content_length,
        &scratch.trailer_value,
    );
    try encodeStreamingResponseHead(allocator, options, scratch);

    const successful_connect = options.request_method == .CONNECT and
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
            messageKeepAlive(options.version, options.headers),
        .expected_length = if (suppress_body)
            0
        else if (use_chunked)
            options.body_length
        else
            fixed_length,
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
        scratch.trailer_headers.items.len,
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
    const response = try prepareStreamingResponse(
        allocator,
        .{
            .headers = &.{.{
                .name = "Trailer",
                .value = "Digest",
            }},
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

/// Validate and encode a request, borrowing an unframed body when possible.
pub fn prepareRequest(
    allocator: std.mem.Allocator,
    options: RequestOptions,
    scratch: *Scratch,
) Error!MessageParts {
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
    if (options.method == .CONNECT and
        (options.body.len != 0 or options.trailers.len != 0))
    {
        return error.InvalidContentLength;
    }
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
        &scratch.trailer_value,
    );

    try encodeRequestHead(allocator, options, scratch);
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            &scratch.encoded,
            allocator,
            &chunks,
            options.trailers,
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
    scratch.reset();
    const framing = try prepareResponseFraming(allocator, options, scratch);
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
        );
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    return .{ .header = scratch.encoded.items, .body = options.body };
}

/// Encode a complete response pipeline before the caller performs any I/O.
pub fn prepareResponses(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    scratch: *Scratch,
) Error![]const u8 {
    scratch.batch_encoded.clearRetainingCapacity();
    for (responses) |response| {
        scratch.encoded.clearRetainingCapacity();
        scratch.headers.clearRetainingCapacity();
        scratch.request_headers.clearRetainingCapacity();
        scratch.trailer_value.clearRetainingCapacity();

        const framing = try prepareResponseFraming(
            allocator,
            response,
            scratch,
        );
        try encodeResponseHead(allocator, response, scratch);
        if (!framing.suppress_body) {
            if (framing.use_chunked) {
                const chunks = [_][]const u8{response.body};
                try encodeChunked(
                    &scratch.encoded,
                    allocator,
                    &chunks,
                    response.trailers,
                );
            } else {
                try scratch.encoded.appendSlice(
                    allocator,
                    response.body,
                );
            }
        }
        try scratch.batch_encoded.appendSlice(
            allocator,
            scratch.encoded.items,
        );
    }
    return scratch.batch_encoded.items;
}

const ResponseFraming = struct {
    use_chunked: bool,
    suppress_body: bool,
};

fn prepareResponseFraming(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    scratch: *Scratch,
) Error!ResponseFraming {
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateResponseBodyForStatus(
        options.status,
        options.headers,
        options.body,
        options.trailers,
    );
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
        &scratch.trailer_value,
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
    if (options.reason.len != 0) {
        try encoded.append(allocator, ' ');
        try encoded.appendSlice(allocator, options.reason);
    }
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(encoded, allocator, scratch.headers.items);
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
    try writeHeaderLines(encoded, allocator, scratch.headers.items);
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
    if (options.reason.len != 0) {
        try encoded.append(allocator, ' ');
        try encoded.appendSlice(allocator, options.reason);
    }
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(encoded, allocator, scratch.headers.items);
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
    len_buf: *[32]u8,
    trailer_value: *std.ArrayList(u8),
) Error!void {
    var has_content_length = false;
    var has_transfer_encoding = false;
    var has_trailer = false;
    try list.ensureUnusedCapacity(allocator, headers.len + 2);
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
            try renderTrailerHeaderValue(
                trailer_value,
                allocator,
                trailers,
            );
            list.appendAssumeCapacity(.{
                .name = "Trailer",
                .value = trailer_value.items,
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
        .GET, .HEAD, .CONNECT => false,
        else => true,
    };
}

fn messageKeepAlive(
    version: http1.Version,
    headers: []const http1.Header,
) bool {
    for (headers) |header| {
        if (!header.eqlName("connection")) continue;
        if (wire.containsToken(header.value, "close")) return false;
        if (wire.containsToken(header.value, "keep-alive")) return true;
    }
    return version == .http_1_1;
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
    if (trailers.len == 0) return false;
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

fn writeHeaderLines(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
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
        list.appendSliceAssumeCapacity(header.name);
        list.appendSliceAssumeCapacity(": ");
        list.appendSliceAssumeCapacity(header.value);
        list.appendSliceAssumeCapacity("\r\n");
    }
}

fn writeMergedHeaderLines(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
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
        try list.appendSlice(allocator, header.name);
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
    try writeMergedHeaderLines(list, allocator, trailers);
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

    /// Encode the unique terminating chunk and merged trailer field lines.
    ///
    /// This runs before any transport write, so malformed trailers and
    /// allocation failures cannot expose a partial terminator on the wire.
    pub fn prepareEnd(
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
        scratch: *Scratch,
    ) Error![]const u8 {
        scratch.encoded.clearRetainingCapacity();
        try http1.validateTrailers(trailers);
        try scratch.encoded.appendSlice(allocator, "0\r\n");
        try writeMergedHeaderLines(&scratch.encoded, allocator, trailers);
        try scratch.encoded.appendSlice(allocator, "\r\n");
        return scratch.encoded.items;
    }
};
