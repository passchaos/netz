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
    trailer_value: std.ArrayList(u8) = .empty,
    content_length: [32]u8 = undefined,

    fn reset(self: *Scratch) void {
        self.encoded.clearRetainingCapacity();
        self.headers.clearRetainingCapacity();
        self.request_headers.clearRetainingCapacity();
        self.trailer_value.clearRetainingCapacity();
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.encoded.deinit(allocator);
        self.batch_encoded.deinit(allocator);
        self.headers.deinit(allocator);
        self.request_headers.deinit(allocator);
        self.trailer_value.deinit(allocator);
        self.* = undefined;
    }
};

pub const MessageParts = struct {
    header: []const u8,
    body: []const u8,
};

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

    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.method.string());
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.target);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(encoded, allocator, scratch.headers.items);
    try encoded.appendSlice(allocator, "\r\n");
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            encoded,
            allocator,
            &chunks,
            options.trailers,
        );
        return .{ .header = encoded.items, .body = &.{} };
    }
    return .{ .header = encoded.items, .body = options.body };
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
