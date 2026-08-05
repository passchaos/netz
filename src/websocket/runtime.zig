const std = @import("std");
const websocket = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = http1.runtime;
const wire = @import("../internal/wire.zig");

const net = std.Io.net;

pub const Error = websocket.Error || http1_runtime.Error || error{
    HeadersTooLarge,
    ConnectionClosed,
    InvalidResponse,
    InvalidSubprotocol,
    MessageTooLarge,
} || std.Io.RandomSecureError || net.Stream.Reader.Error || net.Stream.Writer.Error;

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    max_frame_bytes: usize = 16 * 1024 * 1024,
};

pub const Role = enum {
    client,
    server,
};

pub const Server = struct {
    http: http1_runtime.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .http = try .listen(allocator, io, bind_address, .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = 0,
            }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.http.address();
    }

    pub fn accept(self: *Server, options: AcceptOptions) Error!Connection {
        var http_conn = try self.http.accept();
        errdefer http_conn.close();

        var head = try readHttpHead(self.http.allocator, http_conn.io, http_conn.stream, self.limits.max_head_bytes);
        defer head.deinit(self.http.allocator);

        var request = try http1.parseRequest(self.http.allocator, head.head, .{});
        defer request.deinit(self.http.allocator);
        try websocket.validateClientHandshake(request);

        const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
        const selected_protocol = try selectSubprotocol(self.http.allocator, request.header("sec-websocket-protocol"), options.protocols);
        errdefer if (selected_protocol) |protocol| self.http.allocator.free(protocol);
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(self.http.allocator);
        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(self.http.allocator);
        if (selected_protocol) |protocol| try headers.append(self.http.allocator, .{ .name = "Sec-WebSocket-Protocol", .value = protocol });
        try headers.appendSlice(self.http.allocator, options.extra_headers);
        try websocket.writeServerHandshake(&response, self.http.allocator, key, headers.items);
        try writeAll(http_conn.io, http_conn.stream, response.items);

        var connection = Connection{
            .io = http_conn.io,
            .allocator = self.http.allocator,
            .stream = http_conn.stream,
            .role = .server,
            .limits = self.limits,
            .selected_protocol = selected_protocol,
            .inbuf = try std.ArrayList(u8).initCapacity(self.http.allocator, head.extra.len),
        };
        errdefer connection.inbuf.deinit(connection.allocator);
        try connection.bufferInitial(head.extra);
        return connection;
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.http.allocator.alloc(?anyerror, max_connections);
        errdefer self.http.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var connection = try self.accept(options);
            errdefer connection.close();
            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            group.async(self.http.io, ServeTask(HandlerContext).run, .{task});
        }

        try group.await(self.http.io);
        return .{ .allocator = self.http.allocator, .errors = results };
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
        handler: *const fn (*HandlerContext, *Connection) Error!void,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();
            task.handler(task.context, &connection) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    extra_headers: []const http1.Header = &.{},
};

pub const Client = struct {
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!Connection {
        const stream = net.IpAddress.connect(&address, io, .{ .mode = .stream }) catch |err| return err;
        errdefer stream.close(io);

        var nonce: [16]u8 = undefined;
        try std.Io.randomSecure(io, &nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);

        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(allocator);
        try headers.appendSlice(allocator, &.{
            .{ .name = "Host", .value = options.host },
            .{ .name = "Upgrade", .value = "websocket" },
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Sec-WebSocket-Key", .value = &key },
            .{ .name = "Sec-WebSocket-Version", .value = "13" },
        });
        var protocol_value: std.ArrayList(u8) = .empty;
        defer protocol_value.deinit(allocator);
        if (options.protocols.len != 0) {
            for (options.protocols, 0..) |protocol, index| {
                if (!validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
                if (index != 0) try protocol_value.appendSlice(allocator, ", ");
                try protocol_value.appendSlice(allocator, protocol);
            }
            try headers.append(allocator, .{ .name = "Sec-WebSocket-Protocol", .value = protocol_value.items });
        }
        try http1_runtime.writeRequestToStream(allocator, io, stream, .{
            .method = .GET,
            .target = options.target,
            .headers = headers.items,
        });

        var head = try readHttpHead(allocator, io, stream, options.limits.max_head_bytes);
        defer head.deinit(allocator);
        var response = try http1.parseResponse(allocator, head.head, .{});
        defer response.deinit(allocator);
        if (response.status != 101) return error.InvalidResponse;
        const selected_protocol = try validateServerHandshake(allocator, response, &key, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);

        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
            .limits = options.limits,
            .selected_protocol = selected_protocol,
            .inbuf = try std.ArrayList(u8).initCapacity(allocator, head.extra.len),
        };
        errdefer connection.inbuf.deinit(connection.allocator);
        try connection.bufferInitial(head.extra);
        return connection;
    }
};

pub const ConnectOptions = struct {
    host: []const u8,
    target: []const u8 = "/",
    protocols: []const []const u8 = &.{},
    limits: Limits = .{},
};

pub const OwnedMessage = struct {
    opcode: websocket.Opcode,
    payload: []u8,

    pub fn deinit(self: *OwnedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    send_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    selected_protocol: ?[]u8 = null,

    fn bufferInitial(self: *Connection, bytes: []const u8) Error!void {
        try self.inbuf.appendSlice(self.allocator, bytes);
    }

    pub fn close(self: *Connection) void {
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        self.inbuf.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn sendText(self: *Connection, text: []const u8) Error!void {
        try self.sendFrame(.text, text);
    }

    pub fn sendBinary(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.binary, payload);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.append(self.allocator, @truncate(@intFromEnum(code) >> 8));
        try payload.append(self.allocator, @truncate(@intFromEnum(code)));
        try payload.appendSlice(self.allocator, reason);
        try self.sendFrame(.close, payload.items);
    }

    pub fn sendFrame(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (self.close_sent and opcode != .close) return error.ConnectionClosed;
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        try self.writeFrameLocked(opcode, payload, true);
        if (opcode == .close) self.close_sent = true;
    }

    pub fn sendFragmented(self: *Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (self.close_sent) return error.ConnectionClosed;
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (fragments.len == 0) return error.InvalidFrame;

        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        for (fragments, 0..) |fragment, index| {
            const frame_opcode: websocket.Opcode = if (index == 0) opcode else .continuation;
            const fin = index + 1 == fragments.len;
            try self.writeFrameLocked(frame_opcode, fragment, fin);
        }
    }

    pub fn receiveFrame(self: *Connection) Error!websocket.Frame {
        try self.ensureBuffered(2);
        const second = self.inbuf.items[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBuffered(header_len);

        const header = try websocket.FrameHeader.parse(self.inbuf.items);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try self.ensureBuffered(total_len);

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{ .expect_mask = .unmasked },
            .server => .{ .expect_mask = .masked },
        };
        const frame = try websocket.parseFrameOptions(self.allocator, self.inbuf.items[0..total_len], parse_options);
        self.discardBuffered(frame.consumed);
        return frame;
    }

    pub fn receiveMessage(self: *Connection) Error!OwnedMessage {
        var assembler = websocket.MessageAssembler.init(self.allocator);
        defer assembler.deinit();

        while (true) {
            var frame = try self.receiveFrame();
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendPong(frame.payload);
                    continue;
                },
                .pong => continue,
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) {
                        try self.sendFrame(.close, frame.payload);
                    }
                    return error.ConnectionClosed;
                },
                else => {
                    const maybe_message = try assembler.feed(frame);
                    if (maybe_message) |message| {
                        if (message.opcode == .text and !std.unicode.utf8ValidateSlice(message.payload)) {
                            self.allocator.free(message.payload);
                            return error.InvalidUtf8;
                        }
                        return .{ .opcode = message.opcode, .payload = message.payload };
                    }
                },
            }
        }
    }

    fn writeFrameLocked(self: *Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;
        try websocket.writeFrame(&encoded, self.allocator, opcode, payload, .{ .fin = fin, .mask_key = mask_key });
        try writeAll(self.io, self.stream, encoded.items);
    }

    fn ensureBuffered(self: *Connection, len: usize) Error!void {
        var scratch: [4096]u8 = undefined;
        while (self.inbuf.items.len < len) {
            const n = try readSome(self.io, self.stream, &scratch);
            if (n == 0) return error.ConnectionClosed;
            try self.inbuf.appendSlice(self.allocator, scratch[0..n]);
        }
    }

    fn discardBuffered(self: *Connection, len: usize) void {
        if (len == self.inbuf.items.len) {
            self.inbuf.clearRetainingCapacity();
            return;
        }
        const remaining = self.inbuf.items[len..];
        @memmove(self.inbuf.items[0..remaining.len], remaining);
        self.inbuf.shrinkRetainingCapacity(remaining.len);
    }
};

const HttpHead = struct {
    head: []u8,
    extra: []u8,

    fn deinit(self: *HttpHead, allocator: std.mem.Allocator) void {
        allocator.free(self.head);
        allocator.free(self.extra);
        self.* = undefined;
    }
};

fn readHttpHead(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, max_head_bytes: usize) Error!HttpHead {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var scratch: [4096]u8 = undefined;
    while (true) {
        if (std.mem.indexOf(u8, bytes.items, "\r\n\r\n")) |head_end| {
            const split = head_end + 4;
            const head = try allocator.dupe(u8, bytes.items[0..split]);
            errdefer allocator.free(head);
            return .{
                .head = head,
                .extra = try allocator.dupe(u8, bytes.items[split..]),
            };
        }
        if (bytes.items.len >= max_head_bytes) return error.HeadersTooLarge;
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
}

fn validateServerHandshake(
    allocator: std.mem.Allocator,
    response: http1.Response,
    client_key: []const u8,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    const upgrade = response.header("upgrade") orelse return error.MissingHeader;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidHandshake;
    const connection = response.header("connection") orelse return error.MissingHeader;
    if (!wire.containsToken(connection, "upgrade")) return error.InvalidHandshake;
    const accept = response.header("sec-websocket-accept") orelse return error.MissingHeader;
    const expected = websocket.acceptKey(client_key);
    if (!std.mem.eql(u8, accept, &expected)) return error.InvalidHandshake;
    if (response.header("sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) return try allocator.dupe(u8, protocol);
        }
        return error.InvalidSubprotocol;
    }
    return null;
}

fn selectSubprotocol(allocator: std.mem.Allocator, requested_header: ?[]const u8, supported: []const []const u8) Error!?[]u8 {
    for (supported) |protocol| {
        if (!validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
    }
    const raw_requested = requested_header orelse return null;
    var requested = std.mem.splitScalar(u8, raw_requested, ',');
    while (requested.next()) |raw| {
        const candidate = wire.trimOws(raw);
        if (!validSubprotocolToken(candidate)) return error.InvalidSubprotocol;
        for (supported) |protocol| {
            if (std.mem.eql(u8, candidate, protocol)) return try allocator.dupe(u8, protocol);
        }
    }
    return null;
}

fn validSubprotocolToken(protocol: []const u8) bool {
    if (protocol.len == 0) return false;
    for (protocol) |byte| {
        if (!isTchar(byte)) return false;
    }
    return true;
}

fn isTchar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
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

test "WebSocket runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expect(frame.header.masked);
            try std.testing.expectEqualStrings("hello", frame.payload);

            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/chat",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
    try std.testing.expect(!response.header.masked);
    try std.testing.expectEqualStrings("world", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{ .protocols = &.{ "chat.v2", "superchat" } });
            defer connection.close();
            try std.testing.expectEqualStrings("superchat", connection.selected_protocol.?);

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", frame.payload);
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/subprotocol",
        .protocols = &.{ "video", "superchat" },
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectEqualStrings("superchat", client.selected_protocol.?);

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client rejects unoffered subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(server_ptr.http.allocator, head.head, .{});
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try websocket.writeServerHandshake(&response, server_ptr.http.allocator, key, &.{.{ .name = "Sec-WebSocket-Protocol", .value = "not-offered" }});
            try writeAll(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidSubprotocol, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/bad-subprotocol",
        .protocols = &.{"superchat"},
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage assembles fragments and handles control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("hello fragmented", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_received);
            try std.testing.expect(connection.close_sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("?");
    const fragments = [_][]const u8{ "hello ", "fragmented" };
    try client.sendFragmented(.text, &fragments);

    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("?", pong.payload);

    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), connection: *Connection) Error!void {
            var frame = try connection.receiveFrame();
            defer frame.deinit(connection.allocator);
            if (frame.header.opcode != .text) return error.ProtocolFailure;
            if (std.mem.eql(u8, frame.payload, "one")) {
                try connection.sendText("echo-one");
            } else if (std.mem.eql(u8, frame.payload, "two")) {
                try connection.sendText("echo-two");
            } else {
                try connection.sendClose(.unsupported_data, "unexpected");
            }

            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            if (close.header.opcode != .close) return error.ProtocolFailure;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{}) catch |err| {
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
        payload: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .host = "127.0.0.1",
                .target = "/async",
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer client.close();

            try client.sendText(task.payload);
            var response = try client.receiveFrame();
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
            try std.testing.expectEqualStrings(task.expected, response.payload);
            try client.sendClose(.normal_closure, "bye");
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "one", .expected = "echo-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "two", .expected = "echo-two" },
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

test "WebSocket connection serializes concurrent sends" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn sendOne(connection: *Connection, payload: []const u8, err: *?anyerror) void {
            connection.sendText(payload) catch |e| {
                err.* = e;
            };
        }

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var err_a: ?anyerror = null;
            var err_b: ?anyerror = null;
            const thread_a = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-a", &err_a });
            const thread_b = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-b", &err_b });
            thread_a.join();
            thread_b.join();
            if (err_a) |err| return err;
            if (err_b) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/send-lock",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var first = try client.receiveFrame();
    defer first.deinit(allocator);
    var second = try client.receiveFrame();
    defer second.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first.header.opcode);
    try std.testing.expectEqual(websocket.Opcode.text, second.header.opcode);
    const saw_a = std.mem.eql(u8, first.payload, "from-a") or std.mem.eql(u8, second.payload, "from-a");
    const saw_b = std.mem.eql(u8, first.payload, "from-b") or std.mem.eql(u8, second.payload, "from-b");
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}
