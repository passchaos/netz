const std = @import("std");
const http1 = @import("mod.zig");
const wire = @import("../internal/wire.zig");

const net = std.Io.net;

pub const Error = http1.Error || error{
    HeadersTooLarge,
    BodyTooLarge,
    ConnectionClosed,
    InvalidResponse,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    max_body_bytes: usize = 16 * 1024 * 1024,
};

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) Error!Connection {
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = try self.listener.accept(self.io),
            .limits = self.limits,
        };
    }

    pub fn serveOne(self: *Server, context: anytype, comptime handler: anytype) Error!void {
        var connection = try self.accept();
        defer connection.close();
        var request = try connection.readRequest(.{});
        defer request.deinit(self.allocator);
        const response = try handler(context, request.request);
        try connection.writeResponse(response);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results, 0..) |*result, index| {
            var connection = try self.accept();
            errdefer connection.close();

            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            // `std.Io.Group.async` copies the task context into the selected
            // std.Io backend.  The connection stream ownership transfers to the
            // task; each task closes its own stream after writing a response.
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
            _ = index;
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .errors = results };
    }
};

pub const AsyncServeError = Error || std.Io.Cancelable;

pub const ConcurrentServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            var request = connection.readRequest(.{}) catch |err| {
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            const response = task.handler(task.context, request.request) catch |err| {
                task.result.* = err;
                return;
            };
            connection.writeResponse(response) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const Client = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .io = io,
            .allocator = allocator,
            .stream = try address.connect(io, .{ .mode = .stream }),
            .limits = limits,
        };
    }

    pub fn close(self: *Client) void {
        self.inbuf.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        try writeRequestToStream(self.allocator, self.io, self.stream, request_options);
        return readResponseFromStreamBufferedForRequest(self.allocator, self.io, self.stream, self.limits, .{}, &self.inbuf, request_options.method);
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,

    pub fn close(self: *Connection) void {
        self.inbuf.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn readRequest(self: *Connection, options: http1.ParseOptions) Error!OwnedRequest {
        return readRequestFromStreamBuffered(self.allocator, self.io, self.stream, self.limits, options, &self.inbuf);
    }

    pub fn writeResponse(self: *Connection, response: ResponseOptions) Error!void {
        try writeResponseToStream(self.allocator, self.io, self.stream, response);
    }
};

pub const OwnedRequest = struct {
    bytes: []u8,
    request: http1.Request,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedResponse = struct {
    bytes: []u8,
    response: http1.Response,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const RequestOptions = struct {
    method: http1.Method = .GET,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
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
};

pub fn readRequestFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytes(allocator, io, stream, limits);
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

pub fn readRequestFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytesBuffered(allocator, io, stream, limits, inbuf);
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    return .{ .bytes = bytes, .request = request };
}

pub fn readResponseFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytes(allocator, io, stream, limits);
        errdefer allocator.free(bytes);
        var response = try http1.parseResponse(allocator, bytes, options);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesForResponse(allocator, io, stream, limits, request_method);
        errdefer allocator.free(bytes);
        var response = try http1.parseResponseForRequest(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesBuffered(allocator, io, stream, limits, inbuf);
        errdefer allocator.free(bytes);
        var response = try http1.parseResponse(allocator, bytes, options);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamBufferedForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesBufferedForResponse(allocator, io, stream, limits, inbuf, request_method);
        errdefer allocator.free(bytes);
        var response = try http1.parseResponseForRequest(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn writeRequestToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: RequestOptions) Error!void {
    const use_chunked = try chunkedWriteFraming(options.version, options.headers, options.trailers);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    var trailer_value: std.ArrayList(u8) = .empty;
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(&headers, allocator, options.headers, options.body.len, options.trailers, use_chunked, &len_buf, &trailer_value);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, options.method.string());
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.target);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(&encoded, allocator, headers.items);
    try encoded.appendSlice(allocator, "\r\n");
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunkedForRuntime(&encoded, allocator, &chunks, options.trailers);
    } else {
        try encoded.appendSlice(allocator, options.body);
    }
    try writeAll(io, stream, encoded.items);
}

pub fn writeResponseToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: ResponseOptions) Error!void {
    const use_chunked = try chunkedWriteFraming(options.version, options.headers, options.trailers);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    var trailer_value: std.ArrayList(u8) = .empty;
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(&headers, allocator, options.headers, options.body.len, options.trailers, use_chunked, &len_buf, &trailer_value);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimalForRuntime(&encoded, allocator, options.status);
    if (options.reason.len != 0) {
        try encoded.append(allocator, ' ');
        try encoded.appendSlice(allocator, options.reason);
    }
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(&encoded, allocator, headers.items);
    try encoded.appendSlice(allocator, "\r\n");
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunkedForRuntime(&encoded, allocator, &chunks, options.trailers);
    } else {
        try encoded.appendSlice(allocator, options.body);
    }
    try writeAll(io, stream, encoded.items);
}

fn appendDefaultedHeaders(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    len_buf: *[32]u8,
    trailer_value: *std.ArrayList(u8),
) Error!void {
    var has_content_length = false;
    var has_connection = false;
    var has_transfer_encoding = false;
    var has_trailer = false;
    for (headers) |header| {
        if (header.eqlName("content-length")) has_content_length = true;
        if (header.eqlName("connection")) has_connection = true;
        if (header.eqlName("transfer-encoding")) has_transfer_encoding = true;
        if (header.eqlName("trailer")) has_trailer = true;
        if (use_chunked and header.eqlName("content-length")) continue;
        try list.append(allocator, header);
    }
    if (use_chunked) {
        if (!has_transfer_encoding) try list.append(allocator, .{ .name = "Transfer-Encoding", .value = "chunked" });
        if (trailers.len != 0 and !has_trailer) {
            try renderTrailerHeaderValue(trailer_value, allocator, trailers);
            try list.append(allocator, .{ .name = "Trailer", .value = trailer_value.items });
        }
    } else if (!has_content_length) {
        const rendered = std.fmt.bufPrint(len_buf, "{}", .{body_len}) catch unreachable;
        try list.append(allocator, .{ .name = "Content-Length", .value = rendered });
    }
    if (!has_connection) try list.append(allocator, .{ .name = "Connection", .value = "close" });
}

fn chunkedWriteFraming(version: http1.Version, headers: []const http1.Header, trailers: []const http1.Header) Error!bool {
    var has_transfer_encoding = false;
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) {
            has_transfer_encoding = true;
            break;
        }
    }

    if (has_transfer_encoding) {
        // Once callers opt into transfer coding, the runtime must emit bytes
        // that match the declared framing.  This HTTP/1 layer only knows how to
        // encode chunked bodies, so reject unsupported stacked codings instead
        // of silently sending a raw body under misleading headers.
        if ((try http1.bodyFraming(headers)) != .chunked) return error.InvalidTransferEncoding;
        if (version == .http_1_0) return error.InvalidVersion;
        return true;
    }

    if (trailers.len == 0) return false;
    if (version == .http_1_0) return error.InvalidVersion;
    return true;
}

fn renderTrailerHeaderValue(value: *std.ArrayList(u8), allocator: std.mem.Allocator, trailers: []const http1.Header) Error!void {
    value.clearRetainingCapacity();
    for (trailers, 0..) |trailer, index| {
        if (index != 0) try value.appendSlice(allocator, ", ");
        try value.appendSlice(allocator, trailer.name);
    }
}

fn appendDecimalForRuntime(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(&tmp, "{}", .{value}) catch return error.InvalidResponse;
    try list.appendSlice(allocator, rendered);
}

fn writeHeaderLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const http1.Header) Error!void {
    for (headers) |header| {
        try list.appendSlice(allocator, header.name);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        try list.appendSlice(allocator, "\r\n");
    }
}

fn encodeChunkedForRuntime(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chunks: []const []const u8,
    trailers: []const http1.Header,
) Error!void {
    for (chunks) |chunk| {
        // A zero-length chunk is the chunked terminator on the wire.  Treat
        // empty payload slices as "no DATA" and emit exactly one terminating
        // chunk after all non-empty payload slices so empty bodies can still
        // carry trailers.
        if (chunk.len == 0) continue;
        var tmp: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&tmp, "{x}\r\n", .{chunk.len}) catch return error.InvalidResponse;
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeHeaderLines(list, allocator, trailers);
    try list.appendSlice(allocator, "\r\n");
}

fn readMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, null, false);
}

fn readMessageBytesForResponse(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits, request_method: http1.Method) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, request_method, false);
}

fn readRequestMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, null, true);
}

fn readMessageBytesWithContext(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    request_method: ?http1.Method,
    auto_continue: bool,
) Error![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = null;
    while (head_end == null) {
        if (bytes.items.len >= limits.max_head_bytes) return error.HeadersTooLarge;
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
        head_end = std.mem.indexOf(u8, bytes.items, "\r\n\r\n");
    }
    try maybeWriteContinue(io, stream, bytes.items[0..head_end.?], bytes.items.len - (head_end.? + 4), auto_continue);

    const target_len = while (true) {
        const len = messageTargetLength(bytes.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try readSome(io, stream, &scratch);
                if (n == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..n]);
                if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                continue;
            },
            else => |e| return e,
        };
        break len;
    };
    while (bytes.items.len < target_len) {
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
        if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
    }
    if (bytes.items.len > target_len) bytes.shrinkRetainingCapacity(target_len);
    return bytes.toOwnedSlice(allocator);
}

fn readMessageBytesBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, null, false);
}

fn readMessageBytesBufferedForResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, request_method, false);
}

fn readRequestMessageBytesBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, null, true);
}

fn readMessageBytesBufferedWithContext(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
    request_method: ?http1.Method,
    auto_continue: bool,
) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = std.mem.indexOf(u8, inbuf.items, "\r\n\r\n");
    while (head_end == null) {
        if (inbuf.items.len >= limits.max_head_bytes) return error.HeadersTooLarge;
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
        head_end = std.mem.indexOf(u8, inbuf.items, "\r\n\r\n");
    }
    try maybeWriteContinue(io, stream, inbuf.items[0..head_end.?], inbuf.items.len - (head_end.? + 4), auto_continue);

    const target_len = while (true) {
        const len = messageTargetLength(inbuf.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try readSome(io, stream, &scratch);
                if (n == 0) return error.ConnectionClosed;
                try inbuf.appendSlice(allocator, scratch[0..n]);
                if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                continue;
            },
            else => |e| return e,
        };
        break len;
    };

    while (inbuf.items.len < target_len) {
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
        if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
    }

    const bytes = try allocator.dupe(u8, inbuf.items[0..target_len]);
    discardPrefix(inbuf, target_len);
    return bytes;
}

fn maybeWriteContinue(io: std.Io, stream: net.Stream, head: []const u8, already_buffered_body_bytes: usize, auto_continue: bool) Error!void {
    if (!auto_continue or already_buffered_body_bytes != 0) return;
    if (!requestShouldSendContinue(head)) return;
    try writeAll(io, stream, "HTTP/1.1 100 Continue\r\n\r\n");
}

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    const remaining = list.items[len..];
    @memmove(list.items[0..remaining.len], remaining);
    list.shrinkRetainingCapacity(remaining.len);
}

fn messageTargetLength(bytes: []const u8, head_end: usize, max_body_bytes: usize, request_method: ?http1.Method) Error!usize {
    const body_start = head_end + 4;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return body_start;
    if (findHeaderValue(head, "transfer-encoding")) |transfer_encoding| {
        if (wire.containsToken(transfer_encoding, "chunked")) {
            return body_start + try chunkedWireLength(bytes[body_start..], max_body_bytes);
        }
    }
    if (findHeaderValue(head, "content-length")) |content_length| {
        const len = std.fmt.parseInt(usize, wire.trimOws(content_length), 10) catch return error.InvalidContentLength;
        if (len > max_body_bytes) return error.BodyTooLarge;
        return body_start + len;
    }
    return body_start;
}

fn responseHeadForbidsBody(head: []const u8, request_method: ?http1.Method) bool {
    if (request_method == null) return false;

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return false;
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return false;
    const status_s = parts.next() orelse return false;
    if (status_s.len != 3) return false;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    return switch (request_method.?) {
        .HEAD => true,
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

fn informationalResponseToSkip(status: u16) bool {
    // RFC 9110 allows one or more interim 1xx responses before the final
    // response.  101 is deliberately not skipped because it transfers the
    // connection to the upgraded protocol.
    return status >= 100 and status < 200 and status != 101;
}

fn requestShouldSendContinue(head: []const u8) bool {
    if (!requestHeadIsHttp11(head)) return false;
    const expect = findHeaderValue(head, "expect") orelse return false;
    if (!std.ascii.eqlIgnoreCase(wire.trimOws(expect), "100-continue")) return false;
    return requestHeadHasBody(head);
}

fn requestHeadIsHttp11(head: []const u8) bool {
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
    return std.mem.endsWith(u8, head[0..first_line_end], " HTTP/1.1");
}

fn requestHeadHasBody(head: []const u8) bool {
    if (findHeaderValue(head, "transfer-encoding")) |transfer_encoding| {
        if (wire.containsToken(transfer_encoding, "chunked")) return true;
    }
    if (findHeaderValue(head, "content-length")) |content_length| {
        const len = std.fmt.parseInt(usize, wire.trimOws(content_length), 10) catch return false;
        return len > 0;
    }
    return false;
}

fn chunkedWireLength(body: []const u8, max_body_bytes: usize) Error!usize {
    var pos: usize = 0;
    var decoded_total: usize = 0;
    while (true) {
        const line_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = body[pos .. pos + line_end];
        pos += line_end + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size = std.fmt.parseInt(usize, wire.trimOws(line[0..semi]), 16) catch return error.InvalidChunk;
        decoded_total = std.math.add(usize, decoded_total, size) catch return error.BodyTooLarge;
        if (decoded_total > max_body_bytes) return error.BodyTooLarge;
        if (size == 0) {
            const trailer_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
            if (trailer_end == 0) return pos + 2;
            const full_end = std.mem.indexOf(u8, body[pos..], "\r\n\r\n") orelse return error.BufferTooShort;
            return pos + full_end + 4;
        }
        if (body.len < pos + size + 2) return error.BufferTooShort;
        pos += size;
        if (!std.mem.eql(u8, body[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }
}

fn findHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return wire.trimOws(line[colon + 1 ..]);
    }
    return null;
}

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn readExactForTest(io: std.Io, stream: net.Stream, buffer: []u8) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try readSome(io, stream, buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

test "HTTP/1 runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqualStrings("/echo", request.request.target);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 201,
                .reason = "Created",
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/echo",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 201), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expectEqualStrings("text/plain", response.response.header("content-type").?);
}

test "HTTP/1 server sends 100 Continue before reading expected body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqualStrings("/expect", request.request.target);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 200,
                .reason = "OK",
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    // Send only the head first.  A Hyper-compatible HTTP/1 server must emit
    // 100 Continue after seeing a valid HTTP/1.1 request with a body so the
    // client can safely stream a large payload without deadlocking.
    try writeAll(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-Continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    try writeAll(io, client.stream, "ping");
    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client skips interim responses before final response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/interim", request.request.target);

            try writeAll(server_ptr.io, connection.stream, "HTTP/1.1 100 Continue\r\n\r\n" ++
                "HTTP/1.1 102 Processing\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/interim",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: http1.Request) Error!ResponseOptions {
            if (request.method != .POST) return error.InvalidMethod;
            if (std.mem.eql(u8, request.target, "/one")) {
                return .{ .status = 200, .body = "handled-one" };
            }
            if (std.mem.eql(u8, request.target, "/two")) {
                return .{ .status = 200, .body = "handled-two" };
            }
            return .{ .status = 404, .reason = "Not Found", .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        target: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
            defer client.close();
            var response = try client.request(.{
                .method = .POST,
                .target = task.target,
                .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(task.expected, response.response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/one", .expected = "handled-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/two", .expected = "handled-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/1 runtime reuses persistent connection and preserves pipelined bytes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/one", first.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                .body = "first",
            });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/two", second.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "close" }},
                .body = "second",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/one",
        .headers = &keep_alive,
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/two",
        .headers = &keep_alive,
    });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings("first", first_response.response.body);
    try std.testing.expect(first_response.response.keepAlive());

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("second", second_response.response.body);
    try std.testing.expect(!second_response.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client keeps pipelined response after HEAD response headers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.HEAD, first.request.method);

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.GET, second.request.method);

            // A HEAD response can advertise the Content-Length a GET would have
            // returned, but no body bytes follow.  Send the next response
            // immediately to prove the client does not consume it as a HEAD
            // body.
            const raw =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
            try writeAll(server_ptr.io, connection.stream, raw);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .HEAD,
        .target = "/head",
        .headers = &keep_alive,
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/next",
        .headers = &keep_alive,
    });

    var head_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .HEAD);
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.none, head_response.response.body_framing);
    try std.testing.expectEqualStrings("", head_response.response.body);

    var get_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .GET);
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.response.status);
    try std.testing.expectEqualStrings("pong", get_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime writes request trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);

            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("upload", request.request.body);
            try std.testing.expectEqualStrings("chunked", request.request.header("transfer-encoding").?);
            try std.testing.expectEqualStrings("Digest, X-Upload-Complete", request.request.header("trailer").?);
            try std.testing.expectEqual(@as(usize, 2), request.request.trailers.len);
            try std.testing.expectEqualStrings("Digest", request.request.trailers[0].name);
            try std.testing.expectEqualStrings("sha-256=demo", request.request.trailers[0].value);
            try std.testing.expectEqualStrings("X-Upload-Complete", request.request.trailers[1].name);
            try std.testing.expectEqualStrings("yes", request.request.trailers[1].value);

            try connection.writeResponse(.{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/upload",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        .body = "upload",
        .trailers = &.{
            .{ .name = "Digest", .value = "sha-256=demo" },
            .{ .name = "X-Upload-Complete", .value = "yes" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
}

test "HTTP/1 runtime writes response trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/download", request.request.target);
            try std.testing.expectEqualStrings("trailers", request.request.header("te").?);

            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "download",
                .trailers = &.{.{ .name = "Digest", .value = "sha-256=response" }},
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/download",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "TE", .value = "trailers" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("download", response.response.body);
    try std.testing.expectEqualStrings("chunked", response.response.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("Digest", response.response.header("trailer").?);
    try std.testing.expectEqual(@as(usize, 1), response.response.trailers.len);
    try std.testing.expectEqualStrings("Digest", response.response.trailers[0].name);
    try std.testing.expectEqualStrings("sha-256=response", response.response.trailers[0].value);
}

test "HTTP/1 runtime honors explicit transfer-encoding chunked writes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("streamed", request.request.body);
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("content-length"));
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("trailer"));

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/explicit-chunked",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Content-Length", .value = "999" },
        },
        .body = "streamed",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(?[]const u8, null), response.response.header("content-length"));
    try std.testing.expectEqual(@as(usize, 0), response.response.trailers.len);
}
