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
};

pub const Client = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .io = io,
            .allocator = allocator,
            .stream = try address.connect(io, .{ .mode = .stream }),
            .limits = limits,
        };
    }

    pub fn close(self: *Client) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        try writeRequestToStream(self.allocator, self.io, self.stream, request_options);
        return readResponseFromStream(self.allocator, self.io, self.stream, self.limits, .{});
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},

    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn readRequest(self: *Connection, options: http1.ParseOptions) Error!OwnedRequest {
        return readRequestFromStream(self.allocator, self.io, self.stream, self.limits, options);
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
};

pub const ResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
};

pub fn readRequestFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedRequest {
    const bytes = try readMessageBytes(allocator, io, stream, limits);
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
    const bytes = try readMessageBytes(allocator, io, stream, limits);
    errdefer allocator.free(bytes);
    var response = try http1.parseResponse(allocator, bytes, options);
    errdefer response.deinit(allocator);
    return .{ .bytes = bytes, .response = response };
}

pub fn writeRequestToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: RequestOptions) Error!void {
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    try appendDefaultedHeaders(&headers, allocator, options.headers, options.body.len, &len_buf);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeRequest(&encoded, allocator, options.method, options.target, options.version, headers.items, options.body);
    try writeAll(io, stream, encoded.items);
}

pub fn writeResponseToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: ResponseOptions) Error!void {
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    try appendDefaultedHeaders(&headers, allocator, options.headers, options.body.len, &len_buf);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeResponse(&encoded, allocator, options.version, options.status, options.reason, headers.items, options.body);
    try writeAll(io, stream, encoded.items);
}

fn appendDefaultedHeaders(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    body_len: usize,
    len_buf: *[32]u8,
) Error!void {
    var has_content_length = false;
    var has_connection = false;
    for (headers) |header| {
        if (header.eqlName("content-length")) has_content_length = true;
        if (header.eqlName("connection")) has_connection = true;
        try list.append(allocator, header);
    }
    if (!has_content_length) {
        const rendered = std.fmt.bufPrint(len_buf, "{}", .{body_len}) catch unreachable;
        try list.append(allocator, .{ .name = "Content-Length", .value = rendered });
    }
    if (!has_connection) try list.append(allocator, .{ .name = "Connection", .value = "close" });
}

fn readMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
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

    const target_len = while (true) {
        const len = messageTargetLength(bytes.items, head_end.?, limits.max_body_bytes) catch |err| switch (err) {
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

fn messageTargetLength(bytes: []const u8, head_end: usize, max_body_bytes: usize) Error!usize {
    const body_start = head_end + 4;
    const head = bytes[0..head_end];
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
