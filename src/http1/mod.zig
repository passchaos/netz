const std = @import("std");
const wire = @import("../internal/wire.zig");

pub const runtime = @import("runtime.zig");
pub const Header = wire.Header;

pub const Error = wire.Error || error{
    BufferTooShort,
    TooManyHeaders,
    MalformedStartLine,
    MalformedHeader,
    InvalidMethod,
    InvalidVersion,
    InvalidStatus,
    InvalidChunk,
    InvalidHost,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidTransferEncoding,
    InvalidTrailer,
    ChunkSizeOverflow,
    ChunkExtensionTooLarge,
    ContentLengthOverflow,
    RenderBufferTooSmall,
} || std.mem.Allocator.Error;

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,

    pub fn parse(bytes: []const u8) Error!Method {
        inline for (std.meta.fields(Method)) |field| {
            if (std.mem.eql(u8, bytes, field.name)) return @enumFromInt(field.value);
        }
        return error.InvalidMethod;
    }

    pub fn string(self: Method) []const u8 {
        return @tagName(self);
    }

    pub fn safe(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .OPTIONS, .TRACE => true,
            else => false,
        };
    }

    pub fn idempotent(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .PUT, .DELETE, .OPTIONS, .TRACE => true,
            else => false,
        };
    }
};

pub const Version = enum {
    http_1_0,
    http_1_1,

    pub fn parse(bytes: []const u8) Error!Version {
        if (std.mem.eql(u8, bytes, "HTTP/1.0")) return .http_1_0;
        if (std.mem.eql(u8, bytes, "HTTP/1.1")) return .http_1_1;
        return error.InvalidVersion;
    }

    pub fn string(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
        };
    }
};

pub const ParseOptions = struct {
    max_headers: usize = 100,
    allow_obs_fold: bool = false,
};

pub const ResponseContext = struct {
    request_method: ?Method = null,
};

/// Borrowed HTTP/1 request head parsed without allocation.
pub const RequestHead = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: []Header,
    body_framing: BodyFraming,
    content_length: ?usize,
    head_len: usize,

    pub fn header(self: RequestHead, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn keepAlive(self: RequestHead) bool {
        if (self.header("connection")) |connection| {
            if (wire.containsToken(connection, "close")) return false;
            if (wire.containsToken(connection, "keep-alive")) return true;
        }
        return self.version == .http_1_1;
    }

    /// Total bytes for a pipelined message when its body boundary is known from
    /// the head. Chunked bodies require parsing chunks and return null.
    pub fn messageLength(self: RequestHead) Error!?usize {
        return switch (self.body_framing) {
            .none => self.head_len,
            .content_length => std.math.add(usize, self.head_len, self.content_length.?) catch error.ContentLengthOverflow,
            .chunked, .close_delimited => null,
        };
    }
};

/// Borrowed HTTP/1 response head parsed without allocation.
pub const ResponseHead = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    body_framing: BodyFraming,
    content_length: ?usize,
    head_len: usize,

    pub fn header(self: ResponseHead, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn messageLength(self: ResponseHead) Error!?usize {
        return switch (self.body_framing) {
            .none => self.head_len,
            .content_length => std.math.add(usize, self.head_len, self.content_length.?) catch error.ContentLengthOverflow,
            .chunked, .close_delimited => null,
        };
    }
};

pub const max_chunk_extension_bytes: usize = 16 * 1024;

pub const BodyFraming = enum {
    /// No message body framing was present in the parsed bytes.
    none,
    /// The body is delimited by Content-Length and points into the caller buffer.
    content_length,
    /// The parser decoded RFC 9112 chunked transfer coding into owned storage.
    chunked,
    /// Runtime-only response body framing: no length/coding was declared and
    /// EOF delimited the body bytes.
    close_delimited,
};

pub const Request = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: []Header,
    body: []const u8,
    body_framing: BodyFraming = .none,
    trailers: []Header = &.{},
    body_storage: ?[]u8 = null,
    header_value_storage: [][]u8 = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.header_value_storage);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.headers);
        allocator.free(self.trailers);
        self.* = undefined;
    }

    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn keepAlive(self: Request) bool {
        if (self.header("connection")) |connection| {
            if (wire.containsToken(connection, "close")) return false;
            if (wire.containsToken(connection, "keep-alive")) return true;
        }
        return self.version == .http_1_1;
    }

    pub fn upgradeProtocol(self: Request) ?[]const u8 {
        const connection = self.header("connection") orelse return null;
        if (!wire.containsToken(connection, "upgrade")) return null;
        const upgrade = self.header("upgrade") orelse return null;
        return wire.trimOws(upgrade);
    }
};

pub const Response = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    body: []const u8,
    body_framing: BodyFraming = .none,
    trailers: []Header = &.{},
    body_storage: ?[]u8 = null,
    header_value_storage: [][]u8 = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.header_value_storage);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.headers);
        allocator.free(self.trailers);
        self.* = undefined;
    }

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn keepAlive(self: Response) bool {
        if (self.header("connection")) |connection| {
            if (wire.containsToken(connection, "close")) return false;
            if (wire.containsToken(connection, "keep-alive")) return true;
        }
        return self.version == .http_1_1;
    }
};

/// Parse a strict request head into caller-provided header storage.
///
/// Returned strings borrow `bytes`; `header_storage` is only used for the
/// lightweight name/value descriptors. Obsolete folding is intentionally
/// rejected because unfolding requires owned value storage.
pub fn parseRequestHead(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
) Error!RequestHead {
    const parsed = try parseHeadLines(bytes, header_storage, options);
    var parts = std.mem.splitScalar(u8, parsed.start_line, ' ');
    const method_s = parts.next() orelse return error.MalformedStartLine;
    const target = parts.next() orelse return error.MalformedStartLine;
    const version_s = parts.next() orelse return error.MalformedStartLine;
    if (parts.next() != null or target.len == 0) return error.MalformedStartLine;
    const method = try Method.parse(method_s);
    try validateRequestTargetForMethod(method, target);
    const version = try Version.parse(version_s);
    try validateTransferEncodingForVersion(version, parsed.headers);
    try validateRequestHostParts(version, target, parsed.headers);
    const framing = try bodyFraming(parsed.headers);
    return .{
        .method = method,
        .target = target,
        .version = version,
        .headers = parsed.headers,
        .body_framing = framing,
        .content_length = if (framing == .content_length) try contentLength(parsed.headers) else null,
        .head_len = parsed.head_len,
    };
}

pub fn parseResponseHead(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
    context: ResponseContext,
) Error!ResponseHead {
    const parsed = try parseHeadLines(bytes, header_storage, options);
    var parts = std.mem.splitScalar(u8, parsed.start_line, ' ');
    const version_s = parts.next() orelse return error.MalformedStartLine;
    const status_s = parts.next() orelse return error.MalformedStartLine;
    const reason = parts.rest();
    const version = try Version.parse(version_s);
    const status = try parseStatusCode(status_s);
    try validateReasonPhrase(reason);
    try validateTransferEncodingForVersion(version, parsed.headers);
    const declared_content_length = try contentLength(parsed.headers);

    const forbidden = responseForbidsBody(status, context.request_method);
    const framing: BodyFraming = if (forbidden) .none else switch (bodyFraming(parsed.headers) catch |err| switch (err) {
        error.InvalidTransferEncoding => if (responseTransferEncodingIsCloseDelimited(parsed.headers))
            .close_delimited
        else
            return error.InvalidTransferEncoding,
        else => |e| return e,
    }) {
        // Response messages without an explicit body delimiter are bounded by
        // connection close.  Reporting this as `none` would let pipeline-aware
        // callers treat the head as a complete response and misclassify the
        // body bytes as the next message.
        .none => .close_delimited,
        else => |value| value,
    };
    return .{
        .version = version,
        .status = status,
        .reason = reason,
        .headers = parsed.headers,
        .body_framing = framing,
        .content_length = declared_content_length,
        .head_len = parsed.head_len,
    };
}

const BorrowedHead = struct {
    start_line: []const u8,
    headers: []Header,
    head_len: usize,
};

fn parseHeadLines(bytes: []const u8, header_storage: []Header, options: ParseOptions) Error!BorrowedHead {
    // Walk CRLF-delimited lines once and stop at the empty line. The previous
    // implementation first scanned the complete head for CRLFCRLF and then
    // rescanned every line; pipelined runtimes already provide a complete
    // buffer, so the double pass was pure overhead in the parse hot path.
    const first_line_end = std.mem.indexOf(u8, bytes, "\r\n") orelse
        return error.BufferTooShort;
    const start_line = bytes[0..first_line_end];

    var count: usize = 0;
    var pos = first_line_end + 2;
    while (true) {
        const line_end_rel = std.mem.indexOf(
            u8,
            bytes[pos..],
            "\r\n",
        ) orelse return error.BufferTooShort;
        if (line_end_rel == 0) {
            return .{
                .start_line = start_line,
                .headers = header_storage[0..count],
                .head_len = pos + 2,
            };
        }
        const line = bytes[pos .. pos + line_end_rel];
        if (line[0] == ' ' or line[0] == '\t') {
            // Even when allocating parse allows obs-fold, this borrowed API
            // cannot expose a contiguous unfolded value without copying.
            _ = options.allow_obs_fold;
            return error.MalformedHeader;
        }
        if (count >= options.max_headers or count >= header_storage.len) return error.TooManyHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        if (colon == 0) return error.MalformedHeader;
        const name = line[0..colon];
        const value = wire.trimOws(line[colon + 1 ..]);
        try validateHeaderName(name);
        try validateHeaderValue(value);
        header_storage[count] = .{ .name = name, .value = value };
        count += 1;
        pos += line_end_rel + 2;
        if (pos > bytes.len) return error.BufferTooShort;
    }
}

pub fn parseRequest(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!Request {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.MalformedStartLine;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_s = parts.next() orelse return error.MalformedStartLine;
    const target = parts.next() orelse return error.MalformedStartLine;
    const version_s = parts.next() orelse return error.MalformedStartLine;
    if (parts.next() != null or target.len == 0) return error.MalformedStartLine;
    const method = try Method.parse(method_s);
    try validateRequestTargetForMethod(method, target);
    const version = try Version.parse(version_s);

    var parsed_headers = try parseHeaderLines(allocator, &lines, options);
    errdefer parsed_headers.deinit(allocator);
    try validateTransferEncodingForVersion(version, parsed_headers.headers);
    const consumed_head = head_end + 4;
    const parsed_body = try parseBody(allocator, bytes, consumed_head, parsed_headers.headers, options);
    errdefer parsed_body.deinit(allocator);
    if (parsed_body.framing == .chunked or parsed_body.framing == .close_delimited) {
        try parsed_headers.stripContentLength(allocator);
    }

    return .{
        .method = method,
        .target = target,
        .version = version,
        .headers = parsed_headers.headers,
        .body = parsed_body.body,
        .body_framing = parsed_body.framing,
        .trailers = parsed_body.trailers,
        .body_storage = parsed_body.body_storage,
        .header_value_storage = parsed_headers.value_storage,
        .trailer_value_storage = parsed_body.trailer_value_storage,
        .consumed = parsed_body.consumed,
    };
}

pub fn parseResponse(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!Response {
    return parseResponseWithContext(allocator, bytes, options, .{});
}

pub fn parseResponseForRequest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
    request_method: Method,
) Error!Response {
    return parseResponseWithContext(allocator, bytes, options, .{ .request_method = request_method });
}

pub fn parseResponseWithContext(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
    context: ResponseContext,
) Error!Response {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.MalformedStartLine;

    var parts = std.mem.splitScalar(u8, status_line, ' ');
    const version_s = parts.next() orelse return error.MalformedStartLine;
    const status_s = parts.next() orelse return error.MalformedStartLine;
    const reason = if (parts.rest().len > 0) parts.rest() else "";
    const status = try parseStatusCode(status_s);
    const version = try Version.parse(version_s);
    try validateReasonPhrase(reason);

    var parsed_headers = try parseHeaderLines(allocator, &lines, options);
    errdefer parsed_headers.deinit(allocator);
    try validateTransferEncodingForVersion(version, parsed_headers.headers);
    const consumed_head = head_end + 4;
    const parsed_body = if (responseForbidsBody(status, context.request_method))
        ParsedBody{
            .framing = .none,
            .body = bytes[consumed_head..consumed_head],
            .consumed = consumed_head,
        }
    else
        try parseResponseBody(allocator, bytes, consumed_head, parsed_headers.headers, options);
    errdefer parsed_body.deinit(allocator);
    if (parsed_body.framing == .chunked or parsed_body.framing == .close_delimited) {
        try parsed_headers.stripContentLength(allocator);
    }

    return .{
        .version = version,
        .status = status,
        .reason = reason,
        .headers = parsed_headers.headers,
        .body = parsed_body.body,
        .body_framing = parsed_body.framing,
        .trailers = parsed_body.trailers,
        .body_storage = parsed_body.body_storage,
        .header_value_storage = parsed_headers.value_storage,
        .trailer_value_storage = parsed_body.trailer_value_storage,
        .consumed = parsed_body.consumed,
    };
}

const ParsedHeaders = struct {
    headers: []Header,
    value_storage: [][]u8 = &.{},

    fn deinit(self: *ParsedHeaders, allocator: std.mem.Allocator) void {
        freeHeaderValueStorage(allocator, self.value_storage);
        allocator.free(self.headers);
        self.* = undefined;
    }

    fn stripContentLength(self: *ParsedHeaders, allocator: std.mem.Allocator) Error!void {
        var kept: usize = 0;
        var removed = false;
        for (self.headers) |header| {
            if (header.eqlName("content-length")) {
                removed = true;
                continue;
            }
            self.headers[kept] = header;
            kept += 1;
        }
        if (!removed) return;
        const stripped = try allocator.realloc(self.headers, kept);
        self.headers = stripped;
    }
};

fn parseHeaderLines(
    allocator: std.mem.Allocator,
    lines: *std.mem.SplitIterator(u8, .sequence),
    options: ParseOptions,
) Error!ParsedHeaders {
    if (!options.allow_obs_fold) return parseHeaderLinesNoFold(allocator, lines.*, options);

    var headers: std.ArrayList(Header) = .empty;
    var value_storage: std.ArrayList([]u8) = .empty;
    errdefer {
        for (value_storage.items) |value| allocator.free(value);
        value_storage.deinit(allocator);
        headers.deinit(allocator);
    }

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            if (!options.allow_obs_fold or headers.items.len == 0) return error.MalformedHeader;
            const continuation = wire.trimOws(line);
            try validateHeaderValue(continuation);
            try appendFoldedHeaderValue(allocator, &headers, &value_storage, continuation);
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        if (colon == 0) return error.MalformedHeader;
        if (headers.items.len >= options.max_headers) return error.TooManyHeaders;
        try validateHeaderName(line[0..colon]);
        const value = wire.trimOws(line[colon + 1 ..]);
        try validateHeaderValue(value);
        try headers.append(allocator, .{
            .name = line[0..colon],
            .value = value,
        });
    }

    if (headers.items.len == 0 and value_storage.items.len == 0) {
        return .{
            .headers = @constCast(&[_]Header{}),
            .value_storage = @constCast(&[_][]u8{}),
        };
    }
    const owned_headers = try headers.toOwnedSlice(allocator);
    errdefer allocator.free(owned_headers);
    const owned_value_storage = try value_storage.toOwnedSlice(allocator);
    return .{ .headers = owned_headers, .value_storage = owned_value_storage };
}

fn parseHeaderLinesNoFold(
    allocator: std.mem.Allocator,
    lines: std.mem.SplitIterator(u8, .sequence),
    options: ParseOptions,
) Error!ParsedHeaders {
    var scan = lines;
    var count: usize = 0;
    while (scan.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') return error.MalformedHeader;
        if (count >= options.max_headers) return error.TooManyHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        if (colon == 0) return error.MalformedHeader;
        try validateHeaderName(line[0..colon]);
        const value = wire.trimOws(line[colon + 1 ..]);
        try validateHeaderValue(value);
        count += 1;
    }

    if (count == 0) {
        return .{
            .headers = @constCast(&[_]Header{}),
            .value_storage = @constCast(&[_][]u8{}),
        };
    }

    const headers = try allocator.alloc(Header, count);
    errdefer allocator.free(headers);
    var fill = lines;
    var index: usize = 0;
    while (fill.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':').?;
        headers[index] = .{
            .name = line[0..colon],
            .value = wire.trimOws(line[colon + 1 ..]),
        };
        index += 1;
    }
    return .{
        .headers = headers,
        .value_storage = @constCast(&[_][]u8{}),
    };
}

fn appendFoldedHeaderValue(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(Header),
    value_storage: *std.ArrayList([]u8),
    continuation: []const u8,
) Error!void {
    const last = &headers.items[headers.items.len - 1];
    var unfolded: std.ArrayList(u8) = .empty;
    errdefer unfolded.deinit(allocator);
    try unfolded.appendSlice(allocator, last.value);
    if (continuation.len != 0) {
        // RFC 9112 deprecates obs-fold but permits recipients to replace each
        // fold with whitespace.  Hyper trims the folded line before joining;
        // doing the same turns "Fold: just\r\n some\r\n\t folding" into the
        // application-facing value "just some folding".
        try unfolded.append(allocator, ' ');
        try unfolded.appendSlice(allocator, continuation);
    }
    const owned = try unfolded.toOwnedSlice(allocator);
    errdefer allocator.free(owned);
    try value_storage.append(allocator, owned);
    last.value = owned;
}

const ParsedBody = struct {
    framing: BodyFraming,
    body: []const u8,
    body_storage: ?[]u8 = null,
    trailers: []Header = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    fn deinit(self: ParsedBody, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.trailers);
    }
};

fn parseBody(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    body_start: usize,
    headers: []const Header,
    options: ParseOptions,
) Error!ParsedBody {
    return switch (try bodyFraming(headers)) {
        .none => .{
            .framing = .none,
            .body = bytes[body_start..body_start],
            .consumed = body_start,
        },
        .content_length => blk: {
            const len = (try contentLength(headers)).?;
            const end = std.math.add(usize, body_start, len) catch return error.ContentLengthOverflow;
            if (bytes.len < end) return error.BufferTooShort;
            break :blk .{
                .framing = .content_length,
                .body = bytes[body_start..end],
                .consumed = end,
            };
        },
        .chunked => blk: {
            var decoded = try decodeChunked(allocator, bytes[body_start..], options);
            errdefer decoded.deinit(allocator);
            break :blk .{
                .framing = .chunked,
                .body = decoded.body,
                .body_storage = decoded.body,
                .trailers = decoded.trailers,
                .trailer_value_storage = decoded.trailer_value_storage,
                .consumed = body_start + decoded.consumed,
            };
        },
        .close_delimited => unreachable,
    };
}

fn parseResponseBody(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    body_start: usize,
    headers: []const Header,
    options: ParseOptions,
) Error!ParsedBody {
    return parseBody(allocator, bytes, body_start, headers, options) catch |err| switch (err) {
        error.InvalidTransferEncoding => blk: {
            if (!responseTransferEncodingIsCloseDelimited(headers)) return error.InvalidTransferEncoding;
            break :blk .{
                .framing = .close_delimited,
                .body = bytes[body_start..],
                .consumed = bytes.len,
            };
        },
        else => |e| return e,
    };
}

pub fn bodyFraming(headers: []const Header) Error!BodyFraming {
    if (try transferEncodingFraming(headers)) |framing| return framing;
    if ((try contentLength(headers)) != null) return .content_length;
    return .none;
}

pub fn contentLength(headers: []const Header) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!header.eqlName("content-length")) continue;
        found = try parseContentLengthFieldValue(header.value, found);
    }
    return found;
}

fn parseContentLengthFieldValue(value: []const u8, previous: ?usize) Error!?usize {
    var found = previous;
    // HTTP field coalescing can turn repeated Content-Length fields into a
    // comma-separated list.  The message is only unambiguous when every decimal
    // value is byte-for-byte equivalent after OWS trimming.
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw_part| {
        const part = wire.trimOws(raw_part);
        if (part.len == 0) return error.InvalidContentLength;
        for (part) |byte| {
            // Be stricter than std.fmt.parseInt: HTTP Content-Length is the
            // `1*DIGIT` grammar, so a leading '+' must be rejected instead of
            // being accepted by some numeric parsers and rejected by others.
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
        }
        const parsed = std.fmt.parseInt(usize, part, 10) catch |err| switch (err) {
            error.InvalidCharacter => return error.InvalidContentLength,
            error.Overflow => return error.ContentLengthOverflow,
        };
        if (found) |existing| {
            if (existing != parsed) return error.ConflictingContentLength;
        } else {
            found = parsed;
        }
    }
    return found;
}

fn transferEncodingFraming(headers: []const Header) Error!?BodyFraming {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var final_is_chunked = false;

    for (headers) |header| {
        if (!header.eqlName("transfer-encoding")) continue;
        saw_transfer_encoding = true;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |raw_token| {
            const token = wire.trimOws(raw_token);
            if (token.len == 0) return error.InvalidTransferEncoding;
            const is_chunked = std.ascii.eqlIgnoreCase(token, "chunked");
            if (is_chunked) {
                // RFC 9112 allows other transfer codings before chunked, but
                // chunked itself may only be applied once and must be final.  We
                // decode the final chunk framing while leaving any preceding
                // transfer-coded bytes for the caller that understands that
                // coding (matching Hyper's message-length decision).
                if (saw_chunked) return error.InvalidTransferEncoding;
                saw_chunked = true;
            }
            final_is_chunked = is_chunked;
        }
    }

    if (!saw_transfer_encoding) return null;
    if (!saw_chunked or !final_is_chunked) return error.InvalidTransferEncoding;
    return .chunked;
}

fn responseTransferEncodingIsCloseDelimited(headers: []const Header) bool {
    var saw_transfer_encoding = false;
    var final_coding: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName("transfer-encoding")) continue;
        saw_transfer_encoding = true;
        const final = finalTransferCoding(header.value) orelse return false;
        final_coding = final;
    }
    return saw_transfer_encoding and !std.ascii.eqlIgnoreCase(final_coding orelse return false, "chunked");
}

fn finalTransferCoding(value: []const u8) ?[]const u8 {
    var tokens = std.mem.splitScalar(u8, value, ',');
    var final: ?[]const u8 = null;
    while (tokens.next()) |raw| {
        const token = wire.trimOws(raw);
        if (token.len == 0) return null;
        final = token;
    }
    return final;
}

pub fn statusCodeForbidsBody(status: u16) bool {
    return (status >= 100 and status < 200) or status == 204 or status == 304;
}

fn validateTransferEncodingForVersion(version: Version, headers: []const Header) Error!void {
    if (version != .http_1_0) return;
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) return error.InvalidTransferEncoding;
    }
}

pub fn validateResponseBodyForStatus(status: u16, headers: []const Header, body: []const u8, trailers: []const Header) Error!void {
    try validateStatusCode(status);
    if (!statusCodeForbidsBody(status)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    const declared_content_length = try contentLength(headers);
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) return error.InvalidTransferEncoding;
    }
    // 304 may carry Content-Length to describe the selected representation;
    // 1xx and 204 terminate at the header section and must not carry one.
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

fn responseForbidsBody(status: u16, request_method: ?Method) bool {
    if (statusCodeForbidsBody(status)) return true;
    return switch (request_method orelse return false) {
        // RFC 9110: HEAD responses have the same headers as GET but never carry
        // content.  Hyper applies the request method when deciding response body
        // length; doing the same prevents a HEAD Content-Length from consuming
        // the next pipelined response as body bytes.
        .HEAD => true,
        // A successful CONNECT switches the connection to a tunnel after the
        // header section.  From HTTP's perspective there is no response body.
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

pub fn writeRequest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    method: Method,
    target: []const u8,
    version: Version,
    headers: []const Header,
    body: []const u8,
) !void {
    try validateRequestTargetForMethod(method, target);
    try list.ensureUnusedCapacity(allocator, try requestWireLen(method, target, version, headers, body));
    try list.appendSlice(allocator, method.string());
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, target);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, version.string());
    try list.appendSlice(allocator, "\r\n");
    try writeHeaders(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

pub fn writeRequestChecked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    method: Method,
    target: []const u8,
    version: Version,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateRequestTargetForMethod(method, target);
    try list.ensureUnusedCapacity(allocator, try requestWireLen(method, target, version, headers, body));
    try list.appendSlice(allocator, method.string());
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, target);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, version.string());
    try list.appendSlice(allocator, "\r\n");
    try writeHeadersChecked(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

fn requestWireLen(method: Method, target: []const u8, version: Version, headers: []const Header, body: []const u8) Error!usize {
    var len = method.string().len;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, target.len) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, version.string().len) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, try headerBlockWireLen(headers)) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    return std.math.add(usize, len, body.len) catch return error.RenderBufferTooSmall;
}

pub fn writeResponse(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) !void {
    try validateReasonPhrase(reason);
    try validateStatusCode(status);
    try validateResponseBodyForStatus(status, headers, body, &.{});
    try list.ensureUnusedCapacity(allocator, try responseWireLen(version, status, reason, headers, body));
    try list.appendSlice(allocator, version.string());
    try list.append(allocator, ' ');
    try appendDecimal(list, allocator, status);
    if (reason.len > 0) {
        try list.append(allocator, ' ');
        try list.appendSlice(allocator, reason);
    }
    try list.appendSlice(allocator, "\r\n");
    try writeHeaders(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

pub fn writeResponseChecked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateReasonPhrase(reason);
    try validateStatusCode(status);
    try validateResponseBodyForStatus(status, headers, body, &.{});
    try list.ensureUnusedCapacity(allocator, try responseWireLen(version, status, reason, headers, body));
    try list.appendSlice(allocator, version.string());
    try list.append(allocator, ' ');
    try appendDecimalChecked(list, allocator, status);
    if (reason.len > 0) {
        try list.append(allocator, ' ');
        try list.appendSlice(allocator, reason);
    }
    try list.appendSlice(allocator, "\r\n");
    try writeHeadersChecked(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

fn responseWireLen(version: Version, status: u16, reason: []const u8, headers: []const Header, body: []const u8) Error!usize {
    var len = version.string().len;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, decimalDigitLen(status)) catch return error.RenderBufferTooSmall;
    if (reason.len > 0) {
        len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, reason.len) catch return error.RenderBufferTooSmall;
    }
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, try headerBlockWireLen(headers)) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    return std.math.add(usize, len, body.len) catch return error.RenderBufferTooSmall;
}

fn decimalDigitLen(value: u16) usize {
    if (value >= 1000) return 4;
    if (value >= 100) return 3;
    if (value >= 10) return 2;
    return 1;
}

fn writeHeaders(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    try writeHeadersDirect(list, allocator, headers);
}

fn writeHeadersChecked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) Error!void {
    try writeHeadersDirect(list, allocator, headers);
}

fn writeHeadersDirect(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) Error!void {
    const len = try headerBlockWireLen(headers);

    const start = list.items.len;
    try list.ensureUnusedCapacity(allocator, len);
    list.items.len = start + len;
    var pos = start;
    for (headers) |header| {
        @memcpy(list.items[pos..][0..header.name.len], header.name);
        pos += header.name.len;
        @memcpy(list.items[pos..][0..2], ": ");
        pos += 2;
        @memcpy(list.items[pos..][0..header.value.len], header.value);
        pos += header.value.len;
        @memcpy(list.items[pos..][0..2], "\r\n");
        pos += 2;
    }
}

fn headerBlockWireLen(headers: []const Header) Error!usize {
    var len: usize = 0;
    for (headers) |header| {
        try validateHeader(header);
        len = std.math.add(usize, len, header.name.len) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, header.value.len) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    }
    return len;
}

fn appendDecimal(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&tmp, "{}", .{value});
    try list.appendSlice(allocator, rendered);
}

fn appendDecimalChecked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(&tmp, "{}", .{value}) catch return error.RenderBufferTooSmall;
    try list.appendSlice(allocator, rendered);
}

pub fn validateHeader(header: Header) Error!void {
    try validateHeaderName(header.name);
    try validateHeaderValue(header.value);
}

pub fn validateRequestTarget(target: []const u8) Error!void {
    if (target.len == 0) return error.MalformedStartLine;
    for (target) |byte| {
        // The request target is a single start-line token.  Rejecting SP/HTAB
        // and all control bytes prevents request-smuggling/start-line injection
        // while still allowing UTF-8/opaque octets that many origin-form paths
        // carry in practice.  URI fragments are never sent in HTTP requests;
        // clients such as hyper strip them before serialization, so reject raw
        // '#' here to avoid origin/proxy disagreement.
        if (byte <= 0x20 or byte == 0x7f or byte == '#') return error.MalformedStartLine;
    }
}

pub fn validateRequestTargetForMethod(method: Method, target: []const u8) Error!void {
    switch (method) {
        .CONNECT => try validateConnectTarget(target),
        .OPTIONS => {
            try validateRequestTarget(target);
            if (std.mem.eql(u8, target, "*")) return;
            try validateOriginOrAbsoluteFormTarget(target);
        },
        else => {
            try validateRequestTarget(target);
            if (std.mem.eql(u8, target, "*")) return error.MalformedStartLine;
            try validateOriginOrAbsoluteFormTarget(target);
        },
    }
}

fn validateOriginOrAbsoluteFormTarget(target: []const u8) Error!void {
    if (target[0] == '/') return;
    if (absoluteFormAuthority(target) != null) return;
    return error.MalformedStartLine;
}

pub fn validateConnectTarget(target: []const u8) Error!void {
    try validateRequestTarget(target);
    if (target[0] == '/' or target[0] == '*' or std.mem.indexOf(u8, target, "://") != null) return error.MalformedStartLine;
    try validateAuthorityForbiddenDelimiters(target, error.MalformedStartLine);

    const port: []const u8 = if (target[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, target, ']') orelse return error.MalformedStartLine;
        if (end <= 1 or end + 2 > target.len or target[end + 1] != ':') return error.MalformedStartLine;
        break :blk target[end + 2 ..];
    } else blk: {
        if (std.mem.indexOfScalar(u8, target, '[') != null or std.mem.indexOfScalar(u8, target, ']') != null) return error.MalformedStartLine;
        const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.MalformedStartLine;
        if (colon == 0 or colon + 1 >= target.len) return error.MalformedStartLine;
        // Unbracketed IPv6 is ambiguous in authority-form; require RFC 3986
        // bracket syntax so the final colon is unambiguously the port separator.
        if (std.mem.indexOfScalar(u8, target[0..colon], ':') != null) return error.MalformedStartLine;
        break :blk target[colon + 1 ..];
    };

    try validateAuthorityPort(port, error.MalformedStartLine);
}

pub fn validateRequestHost(request: Request) Error!void {
    try validateRequestHostParts(request.version, request.target, request.headers);
}

fn validateRequestHostParts(version: Version, target: []const u8, headers: []const Header) Error!void {
    const host = try validateHostHeaderBlockValue(version, headers);
    if (absoluteFormAuthority(target)) |authority| {
        try validateHostValue(authority);
        if (host) |host_value| {
            if (!std.ascii.eqlIgnoreCase(wire.trimOws(host_value), authority)) return error.InvalidHost;
        }
    }
}

pub fn validateHostHeaderBlock(version: Version, headers: []const Header) Error!void {
    _ = try validateHostHeaderBlockValue(version, headers);
}

fn validateHostHeaderBlockValue(version: Version, headers: []const Header) Error!?[]const u8 {
    var found_host: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName("host")) continue;
        if (found_host != null) return error.InvalidHost;
        found_host = header.value;
        try validateHostValue(header.value);
    }
    if (version == .http_1_1 and found_host == null) return error.InvalidHost;
    return found_host;
}

pub fn absoluteFormAuthority(target: []const u8) ?[]const u8 {
    const scheme_end = std.mem.indexOf(u8, target, "://") orelse return null;
    if (!validUriScheme(target[0..scheme_end])) return null;
    const authority_start = scheme_end + 3;
    if (authority_start >= target.len) return null;
    const rest = target[authority_start..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    if (authority_end == 0) return null;
    const authority = rest[0..authority_end];
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;
    return authority;
}

fn validUriScheme(scheme: []const u8) bool {
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return false;
    for (scheme[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return false;
    }
    return true;
}

pub fn validateHostValue(raw_host: []const u8) Error!void {
    const host = wire.trimOws(raw_host);
    if (host.len == 0) return error.InvalidHost;
    if (std.mem.indexOf(u8, host, "://") != null) return error.InvalidHost;
    try validateAuthorityForbiddenDelimiters(host, error.InvalidHost);

    const port: ?[]const u8 = if (host[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, host, ']') orelse return error.InvalidHost;
        if (end <= 1) return error.InvalidHost;
        if (end + 1 == host.len) break :blk null;
        if (host[end + 1] != ':' or end + 2 >= host.len) return error.InvalidHost;
        break :blk host[end + 2 ..];
    } else blk: {
        if (std.mem.indexOfScalar(u8, host, '[') != null or std.mem.indexOfScalar(u8, host, ']') != null) return error.InvalidHost;
        const colon = std.mem.lastIndexOfScalar(u8, host, ':') orelse break :blk null;
        if (colon == 0 or colon + 1 >= host.len) return error.InvalidHost;
        // IPv6 literals in URI/Host authority form must be bracketed.  Treat an
        // additional colon before the final separator as an ambiguous authority.
        if (std.mem.indexOfScalar(u8, host[0..colon], ':') != null) return error.InvalidHost;
        break :blk host[colon + 1 ..];
    };

    if (port) |value| try validateAuthorityPort(value, error.InvalidHost);
}

fn validateAuthorityForbiddenDelimiters(authority: []const u8, comptime err: Error) Error!void {
    for (authority) |byte| {
        // Authority-form is a host[:port] component, not a complete URI or a
        // comma-list.  Hyper and Go's HTTP stacks keep this surface strict
        // because userinfo/path/query/fragment/list delimiters are common
        // sources of proxy/origin disagreement and CONNECT request smuggling.
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == '/' or byte == '\\' or byte == '?' or byte == '#' or byte == '@') return err;
    }
}

fn validateAuthorityPort(port: []const u8, comptime err: Error) Error!void {
    if (port.len == 0) return err;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return err;
    }
    const parsed_port = std.fmt.parseInt(u32, port, 10) catch return err;
    if (parsed_port > std.math.maxInt(u16)) return err;
}

pub fn validateReasonPhrase(reason: []const u8) Error!void {
    for (reason) |byte| {
        // RFC reason-phrases are human-readable text after the status code.
        // They may contain SP/HTAB and obs-text, but never CR/LF or other
        // controls that could append forged fields to the response head.
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.MalformedStartLine;
    }
}

pub fn validateStatusCode(status: u16) Error!void {
    if (status < 100 or status > 999) return error.InvalidStatus;
}

fn parseStatusCode(status_s: []const u8) Error!u16 {
    if (status_s.len != 3) return error.InvalidStatus;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
    try validateStatusCode(status);
    return status;
}

pub fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.MalformedHeader;
    for (name) |byte| {
        if (!validHeaderNameByte(byte)) return error.MalformedHeader;
    }
}

pub fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.MalformedHeader;
    }
}

fn validHeaderNameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

pub fn encodeChunked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunks: []const []const u8, trailers: []const Header) !void {
    try validateTrailers(trailers);
    if (chunks.len == 0 and trailers.len == 0) {
        try list.appendSlice(allocator, "0\r\n\r\n");
        return;
    }
    var encoded_len: usize = 0;
    for (chunks) |chunk| {
        encoded_len = std.math.add(usize, encoded_len, hexDigitLen(chunk.len)) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, chunk.len) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
    }
    encoded_len = std.math.add(usize, encoded_len, "0\r\n".len) catch return error.RenderBufferTooSmall;
    encoded_len = std.math.add(usize, encoded_len, try headerBlockWireLen(trailers)) catch return error.RenderBufferTooSmall;
    encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
    try list.ensureUnusedCapacity(allocator, encoded_len);
    for (chunks) |chunk| {
        var tmp: [32]u8 = undefined;
        const rendered = try std.fmt.bufPrint(&tmp, "{x}\r\n", .{chunk.len});
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeHeaders(list, allocator, trailers);
    try list.appendSlice(allocator, "\r\n");
}

fn hexDigitLen(value: usize) usize {
    var digits: usize = 1;
    var remaining = value;
    while (remaining >= 16) : (remaining >>= 4) digits += 1;
    return digits;
}

pub const DecodedChunked = struct {
    body: []u8,
    trailers: []Header,
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    pub fn deinit(self: *DecodedChunked, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.trailers);
        self.* = undefined;
    }
};

const ChunkedBodyScan = struct {
    body_len: usize,
    trailer_start: usize,
};

fn scanChunkedBody(bytes: []const u8) Error!ChunkedBodyScan {
    var pos: usize = 0;
    var extension_bytes: usize = 0;
    var body_len: usize = 0;

    while (true) {
        const line_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = bytes[pos .. pos + line_end_rel];
        pos += line_end_rel + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        if (semi != line.len) {
            extension_bytes = std.math.add(usize, extension_bytes, line.len - semi) catch return error.ChunkExtensionTooLarge;
            if (extension_bytes > max_chunk_extension_bytes) return error.ChunkExtensionTooLarge;
            try validateChunkExtension(line[semi + 1 ..]);
        }
        const size_part = try chunkSizePart(line[0..semi]);
        const size = try parseChunkSize(size_part);
        const data_end = std.math.add(usize, pos, size) catch return error.ChunkSizeOverflow;
        const required_end = std.math.add(usize, data_end, 2) catch return error.ChunkSizeOverflow;
        if (bytes.len < required_end) return error.BufferTooShort;
        if (size == 0) return .{ .body_len = body_len, .trailer_start = pos };
        body_len = std.math.add(usize, body_len, size) catch return error.ChunkSizeOverflow;
        pos = data_end;
        if (!std.mem.eql(u8, bytes[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }
}

fn copyChunkedBody(bytes: []const u8, out: []u8) Error!void {
    var pos: usize = 0;
    var out_pos: usize = 0;
    while (true) {
        const line_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = bytes[pos .. pos + line_end_rel];
        pos += line_end_rel + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size_part = try chunkSizePart(line[0..semi]);
        const size = try parseChunkSize(size_part);
        if (size == 0) return;
        const data_end = pos + size;
        @memcpy(out[out_pos..][0..size], bytes[pos..data_end]);
        out_pos += size;
        pos = data_end + 2;
    }
}

pub fn decodeChunked(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!DecodedChunked {
    if (std.mem.startsWith(u8, bytes, "0\r\n\r\n")) {
        return .{
            .body = @constCast(&[_]u8{}),
            .trailers = @constCast(&[_]Header{}),
            .trailer_value_storage = @constCast(&[_][]u8{}),
            .consumed = "0\r\n\r\n".len,
        };
    }
    const scan = try scanChunkedBody(bytes);
    const body = if (scan.body_len == 0) @constCast(&[_]u8{}) else try allocator.alloc(u8, scan.body_len);
    errdefer if (scan.body_len != 0) allocator.free(body);
    try copyChunkedBody(bytes, body);

    const trailer_end_rel = std.mem.indexOf(u8, bytes[scan.trailer_start..], "\r\n") orelse return error.BufferTooShort;
    var trailer_block_end = scan.trailer_start + trailer_end_rel;
    // A zero-length trailer block is represented by the CRLF immediately after
    // the terminating zero-size chunk. Otherwise parse until the empty line.
    if (trailer_end_rel != 0) {
        const full_end_rel = std.mem.indexOf(u8, bytes[scan.trailer_start..], "\r\n\r\n") orelse return error.BufferTooShort;
        trailer_block_end = scan.trailer_start + full_end_rel;
    }
    const consumed = if (trailer_end_rel == 0) scan.trailer_start + 2 else trailer_block_end + 4;
    if (trailer_end_rel == 0) {
        return .{
            .body = body,
            .trailers = @constCast(&[_]Header{}),
            .trailer_value_storage = @constCast(&[_][]u8{}),
            .consumed = consumed,
        };
    }

    var lines = std.mem.splitSequence(u8, bytes[scan.trailer_start..trailer_block_end], "\r\n");
    var parsed_trailers = try parseHeaderLines(allocator, &lines, options);
    errdefer parsed_trailers.deinit(allocator);
    try validateTrailers(parsed_trailers.headers);
    return .{
        .body = body,
        .trailers = parsed_trailers.headers,
        .trailer_value_storage = parsed_trailers.value_storage,
        .consumed = consumed,
    };
}

fn freeHeaderValueStorage(allocator: std.mem.Allocator, storage: [][]u8) void {
    for (storage) |value| allocator.free(value);
    allocator.free(storage);
}

pub fn validateTrailers(trailers: []const Header) Error!void {
    for (trailers) |trailer| {
        if (!validTrailerFieldName(trailer.name)) return error.InvalidTrailer;
    }
}

fn validateChunkExtension(extension: []const u8) Error!void {
    for (extension) |byte| {
        // Hyper rejects bare LF inside ignored chunk extensions because some
        // permissive intermediaries accidentally treat it as a line boundary.
        // Reject CR too unless it is the actual CRLF delimiter consumed by the
        // caller; otherwise peers can disagree about where the chunk header ends.
        if (byte == 0x0a or byte == 0x0d) return error.InvalidChunk;
    }
}

fn chunkSizePart(raw_size: []const u8) Error![]const u8 {
    if (raw_size.len == 0) return error.InvalidChunk;

    var end: usize = 0;
    while (end < raw_size.len and std.ascii.isHex(raw_size[end])) : (end += 1) {}
    if (end == 0) return error.InvalidChunk;

    for (raw_size[end..]) |byte| {
        switch (byte) {
            ' ', 0x09 => {},
            else => return error.InvalidChunk,
        }
    }
    // Hyper's decoder permits LWS only after at least one chunk-size digit and
    // never allows more digits afterward.  Splitting this before parseInt keeps
    // the public size parser on the exact RFC `1*HEXDIG` grammar while still
    // accepting the same post-size tolerance as mature HTTP/1 parsers.
    return raw_size[0..end];
}

pub fn parseChunkSize(raw_size: []const u8) Error!usize {
    if (raw_size.len == 0) return error.InvalidChunk;
    for (raw_size) |byte| {
        // RFC 9112 chunk-size is 1*HEXDIG.  std.fmt.parseInt would accept
        // leading '+', but wire parsers must not because peers and
        // intermediaries disagreeing here is a request-smuggling primitive.
        if (!std.ascii.isHex(byte)) return error.InvalidChunk;
    }
    return std.fmt.parseInt(usize, raw_size, 16) catch |err| switch (err) {
        error.InvalidCharacter => error.InvalidChunk,
        error.Overflow => error.ChunkSizeOverflow,
    };
}

fn validTrailerFieldName(name: []const u8) bool {
    return !(std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-range") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "te"));
}

test "HTTP/1 request parse and serialize" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nContent-Length: 5\r\n\r\nhello";
    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectEqual(Method.GET, req.method);
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
    try std.testing.expectEqual(Method.POST, first.method);
    try std.testing.expectEqualStrings("/one", first.target);
    try std.testing.expectEqualStrings("example.com", first.header("host").?);
    try std.testing.expect(first.keepAlive());
    try std.testing.expectEqual(BodyFraming.content_length, first.body_framing);
    const first_len = (try first.messageLength()).?;
    try std.testing.expectEqualStrings("hello", pipeline[first.head_len..first_len]);

    var second_headers: [4]Header = undefined;
    const second = try parseRequestHead(pipeline[first_len..], &second_headers, .{});
    try std.testing.expectEqual(Method.GET, second.method);
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

test "HTTP/1 validates Host authority rules" {
    const allocator = std.testing.allocator;
    const valid = "GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    var req = try parseRequest(allocator, valid, .{});
    defer req.deinit(allocator);
    try validateRequestHost(req);

    const missing = "GET / HTTP/1.1\r\nUser-Agent: demo\r\n\r\n";
    var missing_req = try parseRequest(allocator, missing, .{});
    defer missing_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHost, validateRequestHost(missing_req));

    const duplicate = "GET / HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\n\r\n";
    var duplicate_req = try parseRequest(allocator, duplicate, .{});
    defer duplicate_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHost, validateRequestHost(duplicate_req));

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

test "HTTP/1 validates absolute-form authority against Host" {
    const allocator = std.testing.allocator;

    const matching = "GET http://example.com:8080/proxy?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    var req = try parseRequest(allocator, matching, .{});
    defer req.deinit(allocator);
    try validateRequestHost(req);
    try std.testing.expectEqualStrings("example.com:8080", absoluteFormAuthority(req.target).?);

    const mismatch = "GET http://example.com/proxy HTTP/1.1\r\nHost: other.example\r\n\r\n";
    var bad = try parseRequest(allocator, mismatch, .{});
    defer bad.deinit(allocator);
    try std.testing.expectError(error.InvalidHost, validateRequestHost(bad));

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

    try writeResponseChecked(&encoded, allocator, .http_1_1, 304, "Not Modified", &.{.{
        .name = "Content-Length",
        .value = "123",
    }}, "");
    try std.testing.expect(std.mem.indexOf(u8, encoded.items, "Content-Length: 123\r\n") != null);
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

    encoded.clearRetainingCapacity();
    try encoded.ensureTotalCapacity(allocator, encoded_with_trailer.len);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try encodeChunked(&encoded, no_alloc.allocator(), &chunks, &trailers);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(encoded_with_trailer, encoded.items);

    encoded.clearRetainingCapacity();
    try encoded.ensureTotalCapacity(allocator, "0\r\n\r\n".len);
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try encodeChunked(&encoded, no_alloc.allocator(), &.{}, &.{});
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings("0\r\n\r\n", encoded.items);

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

test "HTTP/1 chunked trailers reject forbidden fields" {
    const allocator = std.testing.allocator;
    const invalid = [_]Header{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Trailer", .value = "Digest" },
        .{ .name = "Host", .value = "example.com" },
    };
    for (invalid) |trailer| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.InvalidTrailer, encodeChunked(&encoded, allocator, &[_][]const u8{"hello"}, &.{trailer}));
    }

    const raw = "5\r\nhello\r\n0\r\nContent-Length: 5\r\n\r\n";
    try std.testing.expectError(error.InvalidTrailer, decodeChunked(allocator, raw, .{}));
}

test "HTTP/1 chunked extensions are bounded" {
    const allocator = std.testing.allocator;
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try raw.appendSlice(allocator, "1;");
    try raw.appendNTimes(allocator, 'a', max_chunk_extension_bytes + 1);
    try raw.appendSlice(allocator, "\r\nx\r\n0\r\n\r\n");
    try std.testing.expectError(error.ChunkExtensionTooLarge, decodeChunked(allocator, raw.items, .{}));

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

test "HTTP/1 parser decodes chunked transfer bodies" {
    const allocator = std.testing.allocator;
    const raw = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nDigest: sha-256=demo\r\n\r\nnext";
    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);

    try std.testing.expectEqual(BodyFraming.chunked, req.body_framing);
    try std.testing.expect(req.header("content-length") == null);
    try std.testing.expectEqualStrings("hello world", req.body);
    try std.testing.expectEqualStrings("sha-256=demo", req.trailers[0].value);
    try std.testing.expectEqual(raw.len - "next".len, req.consumed);
}

test "HTTP/1 parser rejects ambiguous body lengths" {
    const allocator = std.testing.allocator;
    const conflicting = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    try std.testing.expectError(error.ConflictingContentLength, parseRequest(allocator, conflicting, .{}));

    const plus_prefixed = "POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello";
    try std.testing.expectError(error.InvalidContentLength, parseRequest(allocator, plus_prefixed, .{}));

    const coalesced = "POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\nhello";
    var req = try parseRequest(allocator, coalesced, .{});
    defer req.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.content_length, req.body_framing);
    try std.testing.expectEqualStrings("hello", req.body);

    const stacked_te = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    var stacked = try parseRequest(allocator, stacked_te, .{});
    defer stacked.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, stacked.body_framing);
    try std.testing.expectEqualStrings("hello", stacked.body);

    const split_stacked_te = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    var split_stacked = try parseRequest(allocator, split_stacked_te, .{});
    defer split_stacked.deinit(allocator);
    try std.testing.expectEqual(BodyFraming.chunked, split_stacked.body_framing);
    try std.testing.expectEqualStrings("hello", split_stacked.body);

    const non_final_chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseRequest(allocator, non_final_chunked, .{}));

    const split_non_final_chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseRequest(allocator, split_non_final_chunked, .{}));

    const http10_te = "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseRequest(allocator, http10_te, .{}));
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

    const http10_te_response = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(error.InvalidTransferEncoding, parseResponse(allocator, http10_te_response, .{}));
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
test {
    _ = runtime;
}
