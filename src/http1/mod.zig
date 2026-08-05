const std = @import("std");
const wire = @import("../internal/wire.zig");

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
    ChunkSizeOverflow,
    ContentLengthOverflow,
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

pub const Request = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: []Header,
    body: []const u8,
    consumed: usize,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
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
};

pub const Response = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    body: []const u8,
    consumed: usize,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        self.* = undefined;
    }

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }
};

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

    const headers = try parseHeaderLines(allocator, &lines, options);
    errdefer allocator.free(headers);
    const consumed_head = head_end + 4;
    const body = try bodySlice(bytes, consumed_head, headers);

    return .{
        .method = try Method.parse(method_s),
        .target = target,
        .version = try Version.parse(version_s),
        .headers = headers,
        .body = body,
        .consumed = consumed_head + body.len,
    };
}

pub fn parseResponse(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!Response {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.MalformedStartLine;

    var parts = std.mem.splitScalar(u8, status_line, ' ');
    const version_s = parts.next() orelse return error.MalformedStartLine;
    const status_s = parts.next() orelse return error.MalformedStartLine;
    const reason = if (parts.rest().len > 0) parts.rest() else "";
    if (status_s.len != 3) return error.InvalidStatus;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
    if (status < 100 or status > 999) return error.InvalidStatus;

    const headers = try parseHeaderLines(allocator, &lines, options);
    errdefer allocator.free(headers);
    const consumed_head = head_end + 4;
    const body = try bodySlice(bytes, consumed_head, headers);

    return .{
        .version = try Version.parse(version_s),
        .status = status,
        .reason = reason,
        .headers = headers,
        .body = body,
        .consumed = consumed_head + body.len,
    };
}

fn parseHeaderLines(
    allocator: std.mem.Allocator,
    lines: *std.mem.SplitIterator(u8, .sequence),
    options: ParseOptions,
) Error![]Header {
    var headers: std.ArrayList(Header) = .empty;
    errdefer headers.deinit(allocator);

    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if ((line[0] == ' ' or line[0] == '\t') and !options.allow_obs_fold) return error.MalformedHeader;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        if (colon == 0) return error.MalformedHeader;
        if (headers.items.len >= options.max_headers) return error.TooManyHeaders;
        try headers.append(allocator, .{
            .name = line[0..colon],
            .value = wire.trimOws(line[colon + 1 ..]),
        });
    }

    return headers.toOwnedSlice(allocator);
}

fn bodySlice(bytes: []const u8, body_start: usize, headers: []const Header) Error![]const u8 {
    if (wire.findHeader(headers, "content-length")) |value| {
        const len = std.fmt.parseInt(usize, value, 10) catch return error.ContentLengthOverflow;
        if (bytes.len < body_start + len) return error.BufferTooShort;
        return bytes[body_start .. body_start + len];
    }
    return bytes[body_start..body_start];
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

pub fn writeResponse(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) !void {
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

fn writeHeaders(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    for (headers) |header| {
        try list.appendSlice(allocator, header.name);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        try list.appendSlice(allocator, "\r\n");
    }
}

fn appendDecimal(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&tmp, "{}", .{value});
    try list.appendSlice(allocator, rendered);
}

pub fn encodeChunked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunks: []const []const u8, trailers: []const Header) !void {
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

pub const DecodedChunked = struct {
    body: []u8,
    trailers: []Header,
    consumed: usize,

    pub fn deinit(self: *DecodedChunked, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        allocator.free(self.trailers);
        self.* = undefined;
    }
};

pub fn decodeChunked(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!DecodedChunked {
    var pos: usize = 0;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    while (true) {
        const line_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = bytes[pos .. pos + line_end_rel];
        pos += line_end_rel + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size = std.fmt.parseInt(usize, wire.trimOws(line[0..semi]), 16) catch return error.InvalidChunk;
        if (bytes.len < pos + size + 2) return error.BufferTooShort;
        if (size == 0) break;
        try out.appendSlice(allocator, bytes[pos .. pos + size]);
        pos += size;
        if (!std.mem.eql(u8, bytes[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }

    const trailer_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse return error.BufferTooShort;
    var trailer_block_end = pos + trailer_end_rel;
    // A zero-length trailer block is represented by the CRLF immediately after
    // the terminating zero-size chunk. Otherwise parse until the empty line.
    if (trailer_end_rel != 0) {
        const full_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n\r\n") orelse return error.BufferTooShort;
        trailer_block_end = pos + full_end_rel;
    }
    var lines = std.mem.splitSequence(u8, bytes[pos..trailer_block_end], "\r\n");
    const trailers = try parseHeaderLines(allocator, &lines, options);
    errdefer allocator.free(trailers);
    const consumed = if (trailer_end_rel == 0) pos + 2 else trailer_block_end + 4;

    return .{
        .body = try out.toOwnedSlice(allocator),
        .trailers = trailers,
        .consumed = consumed,
    };
}

test "HTTP/1 request parse and serialize" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\nContent-Length: 5\r\n\r\nhello";
    var req = try parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/chat", req.target);
    try std.testing.expectEqualStrings("hello", req.body);
    try std.testing.expect(wire.containsToken(req.header("connection").?, "upgrade"));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writeRequest(&out, allocator, req.method, req.target, req.version, req.headers, req.body);
    try std.testing.expectEqualStrings(raw, out.items);
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
}
