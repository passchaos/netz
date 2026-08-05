const std = @import("std");
const http2 = @import("mod.zig");

const net = std.Io.net;

pub const Error = http2.Error || error{
    ConnectionClosed,
    UnexpectedFrame,
    MissingPseudoHeader,
    InvalidStatus,
    MessageTooLarge,
    FlowControlBlocked,
    FlowControlViolation,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;

const ReadExactError = net.Stream.Reader.Error || error{ConnectionClosed};

const flag_end_stream: u8 = 0x1;
const flag_ack: u8 = 0x1;
const flag_end_headers: u8 = 0x4;
const default_flow_window: i64 = 65_535;

pub const Limits = struct {
    max_frame_payload: usize = 16 * 1024 * 1024,
    max_body_bytes: usize = 16 * 1024 * 1024,
    max_header_fields: usize = 256,
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
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);

        var preface_buf: [http2.connection_preface.len]u8 = undefined;
        try readExact(self.io, stream, &preface_buf);
        try http2.validateClientPreface(&preface_buf);

        var client_settings = try readFrame(self.allocator, self.io, stream, self.limits);
        defer client_settings.deinit(self.allocator);
        if (client_settings.frame.header.frame_type != .settings or (client_settings.frame.header.flags & flag_ack) != 0) {
            return error.UnexpectedFrame;
        }

        try writeFrame(self.allocator, self.io, stream, .settings, 0, 0, &.{});
        try writeFrame(self.allocator, self.io, stream, .settings, flag_ack, 0, &.{});

        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .role = .server,
            .limits = self.limits,
        };
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var connection = try self.accept();
            errdefer connection.close();
            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
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
        handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            const response = task.handler(task.context, request) catch |err| {
                task.result.* = err;
                return;
            };
            connection.writeResponse(request.stream_id, response) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const Client = struct {
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Connection {
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        try writeAll(io, stream, http2.connection_preface);
        try writeFrame(allocator, io, stream, .settings, 0, 0, &.{});

        var saw_server_settings = false;
        var saw_settings_ack = false;
        while (!saw_server_settings or !saw_settings_ack) {
            var frame = try readFrame(allocator, io, stream, limits);
            defer frame.deinit(allocator);
            if (frame.frame.header.frame_type != .settings) return error.UnexpectedFrame;
            if ((frame.frame.header.flags & flag_ack) != 0) {
                saw_settings_ack = true;
            } else {
                saw_server_settings = true;
                try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
            }
        }

        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
            .limits = limits,
        };
    }
};

pub const Role = enum {
    client,
    server,
};

pub const FlowWindow = struct {
    value: i64 = default_flow_window,

    pub fn reserve(self: *FlowWindow, amount: usize) Error!void {
        const delta = std.math.cast(i64, amount) orelse return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlBlocked;
        self.value -= delta;
    }

    pub fn receive(self: *FlowWindow, amount: usize) Error!void {
        const delta = std.math.cast(i64, amount) orelse return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlViolation;
        self.value -= delta;
    }

    pub fn update(self: *FlowWindow, increment: u31) void {
        self.value = std.math.add(i64, self.value, increment) catch std.math.maxInt(i64);
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    role: Role,
    limits: Limits = .{},
    next_client_stream_id: u31 = 1,
    send_connection_window: FlowWindow = .{},
    recv_connection_window: FlowWindow = .{},

    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn request(self: *Connection, options: RequestOptions) Error!OwnedResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        const stream_id = self.next_client_stream_id;
        self.next_client_stream_id += 2;

        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":method", .value = options.method });
        try fields.append(self.allocator, .{ .name = ":path", .value = options.path });
        try fields.append(self.allocator, .{ .name = ":scheme", .value = options.scheme });
        if (options.authority) |authority| try fields.append(self.allocator, .{ .name = ":authority", .value = authority });
        for (options.headers) |header| try fields.append(self.allocator, header);

        try self.writeHeaders(stream_id, fields.items, options.body.len == 0);
        if (options.body.len != 0) try self.writeData(stream_id, options.body, true);
        return self.readResponse(stream_id);
    }

    pub fn readRequest(self: *Connection) Error!OwnedRequest {
        if (self.role != .server) return error.UnexpectedFrame;
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            switch (frame.frame.header.frame_type) {
                .settings => {
                    if ((frame.frame.header.flags & flag_ack) == 0) {
                        try writeFrame(self.allocator, self.io, self.stream, .settings, flag_ack, 0, &.{});
                    }
                    continue;
                },
                .headers => {
                    const stream_id = frame.frame.header.stream_id;
                    const headers = try cloneDecodedHeaders(self.allocator, frame.frame.payload, self.limits);
                    errdefer freeHeaders(self.allocator, headers);
                    var body: std.ArrayList(u8) = .empty;
                    errdefer body.deinit(self.allocator);

                    if ((frame.frame.header.flags & flag_end_stream) == 0) {
                        while (true) {
                            var data_frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
                            defer data_frame.deinit(self.allocator);
                            if (data_frame.frame.header.stream_id != stream_id) continue;
                            if (data_frame.frame.header.frame_type != .data) return error.UnexpectedFrame;
                            const data = try http2.DataPayload.parse(data_frame.frame);
                            if (body.items.len + data.data.len > self.limits.max_body_bytes) return error.MessageTooLarge;
                            try self.recv_connection_window.receive(data.data.len);
                            try body.appendSlice(self.allocator, data.data);
                            if ((data_frame.frame.header.flags & flag_end_stream) != 0) break;
                        }
                    }

                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = findHeader(headers, ":method") orelse return error.MissingPseudoHeader,
                        .path = findHeader(headers, ":path") orelse return error.MissingPseudoHeader,
                        .scheme = findHeader(headers, ":scheme") orelse "https",
                        .authority = findHeader(headers, ":authority"),
                        .body = try body.toOwnedSlice(self.allocator),
                    };
                },
                else => continue,
            }
        }
    }

    pub fn writeResponse(self: *Connection, stream_id: u31, options: ResponseOptions) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        var status_buf: [3]u8 = undefined;
        if (options.status < 100 or options.status > 999) return error.InvalidStatus;
        const status = std.fmt.bufPrint(&status_buf, "{}", .{options.status}) catch return error.InvalidStatus;

        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":status", .value = status });
        for (options.headers) |header| try fields.append(self.allocator, header);
        try self.writeHeaders(stream_id, fields.items, options.body.len == 0);
        if (options.body.len != 0) try self.writeData(stream_id, options.body, true);
    }

    pub fn ping(self: *Connection, data: [8]u8) Error![8]u8 {
        try writeFrame(self.allocator, self.io, self.stream, .ping, 0, 0, &data);
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .ping) continue;
            if ((frame.frame.header.flags & flag_ack) == 0) {
                const ping_payload = try http2.PingPayload.parse(frame.frame);
                try writeFrame(self.allocator, self.io, self.stream, .ping, flag_ack, 0, &ping_payload.data);
                continue;
            }
            return (try http2.PingPayload.parse(frame.frame)).data;
        }
    }

    pub fn readPing(self: *Connection) Error![8]u8 {
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .ping) continue;
            const ping_payload = try http2.PingPayload.parse(frame.frame);
            if ((frame.frame.header.flags & flag_ack) == 0) {
                try writeFrame(self.allocator, self.io, self.stream, .ping, flag_ack, 0, &ping_payload.data);
            }
            return ping_payload.data;
        }
    }

    pub fn sendGoAway(self: *Connection, last_stream_id: u31, error_code: http2.ErrorCode, debug_data: []const u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.GoAwayPayload.write(&encoded, self.allocator, last_stream_id, error_code, debug_data);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readGoAway(self: *Connection) Error!OwnedGoAway {
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .goaway) {
                frame.deinit(self.allocator);
                continue;
            }
            return .{ .frame = frame, .goaway = try http2.GoAwayPayload.parse(frame.frame) };
        }
    }

    pub fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u31) Error!void {
        if (stream_id == 0) self.recv_connection_window.update(increment);
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.WindowUpdatePayload.write(&encoded, self.allocator, stream_id, increment);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readWindowUpdate(self: *Connection) Error!OwnedWindowUpdate {
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .window_update) {
                frame.deinit(self.allocator);
                continue;
            }
            const update = try http2.WindowUpdatePayload.parse(frame.frame);
            if (update.stream_id == 0) self.send_connection_window.update(update.increment);
            return .{ .frame = frame, .window_update = update };
        }
    }

    fn readResponse(self: *Connection, stream_id: u31) Error!OwnedResponse {
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |h| freeHeaders(self.allocator, h);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);

        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type == .settings) {
                if ((frame.frame.header.flags & flag_ack) == 0) {
                    try writeFrame(self.allocator, self.io, self.stream, .settings, flag_ack, 0, &.{});
                }
                continue;
            }
            if (frame.frame.header.frame_type == .window_update) {
                const update = try http2.WindowUpdatePayload.parse(frame.frame);
                if (update.stream_id == 0) self.send_connection_window.update(update.increment);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) continue;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    if (headers != null) return error.UnexpectedFrame;
                    headers = try cloneDecodedHeaders(self.allocator, frame.frame.payload, self.limits);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) break;
                },
                .data => {
                    const data = try http2.DataPayload.parse(frame.frame);
                    if (body.items.len + data.data.len > self.limits.max_body_bytes) return error.MessageTooLarge;
                    try self.recv_connection_window.receive(data.data.len);
                    try body.appendSlice(self.allocator, data.data);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) break;
                },
                else => continue,
            }
        }

        const final_headers = headers orelse return error.MissingPseudoHeader;
        const status_s = findHeader(final_headers, ":status") orelse return error.MissingPseudoHeader;
        const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
        return .{
            .headers = final_headers,
            .status = status,
            .body = try body.toOwnedSlice(self.allocator),
        };
    }

    fn writeHeaders(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, end_stream: bool) Error!void {
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try http2.Hpack.encodeLiteralBlock(&block, self.allocator, headers);
        try writeFrame(
            self.allocator,
            self.io,
            self.stream,
            .headers,
            flag_end_headers | if (end_stream) flag_end_stream else 0,
            stream_id,
            block.items,
        );
    }

    fn writeData(self: *Connection, stream_id: u31, data: []const u8, end_stream: bool) Error!void {
        try self.send_connection_window.reserve(data.len);
        try writeFrame(
            self.allocator,
            self.io,
            self.stream,
            .data,
            if (end_stream) flag_end_stream else 0,
            stream_id,
            data,
        );
    }
};

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
};

pub const ResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
};

pub const OwnedRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    body: []u8,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const OwnedResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body: []u8,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const OwnedGoAway = struct {
    frame: OwnedFrame,
    goaway: http2.GoAwayPayload,

    pub fn deinit(self: *OwnedGoAway, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedWindowUpdate = struct {
    frame: OwnedFrame,
    window_update: http2.WindowUpdatePayload,

    pub fn deinit(self: *OwnedWindowUpdate, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedFrame = struct {
    bytes: []u8,
    frame: http2.Frame,

    pub fn deinit(self: *OwnedFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn readFrame(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!OwnedFrame {
    var header_buf: [@intCast(http2.FrameHeader.encoded_len)]u8 = undefined;
    try readExact(io, stream, &header_buf);
    const header = try http2.FrameHeader.parse(&header_buf);
    const payload_len: usize = header.length;
    if (payload_len > limits.max_frame_payload) return error.MessageTooLarge;

    const bytes = try allocator.alloc(u8, header_buf.len + payload_len);
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..header_buf.len], &header_buf);
    try readExact(io, stream, bytes[header_buf.len..]);
    return .{ .bytes = bytes, .frame = try http2.Frame.parse(bytes) };
}

fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{ .length = 0, .frame_type = frame_type, .flags = flags, .stream_id = stream_id },
        .payload = payload,
    }).write(&encoded, allocator);
    try writeAll(io, stream, encoded.items);
}

fn cloneDecodedHeaders(allocator: std.mem.Allocator, block: []const u8, limits: Limits) Error![]http2.Hpack.HeaderField {
    const decoded = try http2.Hpack.decodeLiteralBlock(allocator, block);
    defer allocator.free(decoded);
    if (decoded.len > limits.max_header_fields) return error.MessageTooLarge;
    const cloned = try allocator.alloc(http2.Hpack.HeaderField, decoded.len);
    var initialized: usize = 0;
    errdefer {
        for (cloned[0..initialized]) |field| {
            allocator.free(field.name);
            allocator.free(field.value);
        }
        allocator.free(cloned);
    }
    for (decoded, cloned) |field, *out| {
        const name = try allocator.dupe(u8, field.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, field.value);
        out.* = .{
            .name = name,
            .value = value,
            .never_index = field.never_index,
        };
        initialized += 1;
    }
    return cloned;
}

fn freeHeaders(allocator: std.mem.Allocator, headers: []http2.Hpack.HeaderField) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

fn findHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn readExact(io: std.Io, stream: net.Stream, buffer: []u8) ReadExactError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var bufs = [_][]u8{buffer[offset..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
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

test "HTTP/2 h2c runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
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

            var client_window = try connection.readWindowUpdate();
            defer client_window.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 0), client_window.window_update.stream_id);
            try std.testing.expectEqual(@as(u31, 4096), client_window.window_update.increment);

            const ping_data = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_data);

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/echo", request.path);
            try std.testing.expectEqualStrings("ping", request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
            try connection.sendWindowUpdate(0, 2048);
            try connection.sendGoAway(request.stream_id, .no_error, "done");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try client.sendWindowUpdate(0, 4096);
    const ping_ack = try client.ping(.{ 8, 6, 7, 5, 3, 0, 9, 9 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_ack);

    var response = try client.request(.{
        .method = "POST",
        .path = "/echo",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
    try std.testing.expectEqualStrings("text/plain", findHeader(response.headers, "content-type").?);
    var window = try client.readWindowUpdate();
    defer window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2048), window.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 2048 - "ping".len), client.send_connection_window.value);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
}

test "HTTP/2 async std.Io server handles concurrent h2c clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: OwnedRequest) Error!ResponseOptions {
            if (!std.mem.eql(u8, request.method, "POST")) return error.UnexpectedFrame;
            if (std.mem.eql(u8, request.path, "/one")) {
                return .{ .status = 200, .body = "h2-one" };
            }
            if (std.mem.eql(u8, request.path, "/two")) {
                return .{ .status = 200, .body = "h2-two" };
            }
            return .{ .status = 404, .body = "missing" };
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
        path: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            });
            defer client.close();

            var response = try client.request(.{
                .method = "POST",
                .path = task.path,
                .authority = "localhost",
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings(task.expected, response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/one", .expected = "h2-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/two", .expected = "h2-two" },
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

test "HTTP/2 flow window blocks and updates" {
    var window = FlowWindow{ .value = 4 };
    try window.reserve(4);
    try std.testing.expectEqual(@as(i64, 0), window.value);
    try std.testing.expectError(error.FlowControlBlocked, window.reserve(1));
    window.update(8);
    try window.reserve(3);
    try std.testing.expectEqual(@as(i64, 5), window.value);

    var recv = FlowWindow{ .value = 2 };
    try std.testing.expectError(error.FlowControlViolation, recv.receive(3));
    try recv.receive(2);
    try std.testing.expectEqual(@as(i64, 0), recv.value);
}
