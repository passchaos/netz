const std = @import("std");
const http2 = @import("mod.zig");

const net = std.Io.net;

pub const Error = http2.Error || error{
    ConnectionClosed,
    UnexpectedFrame,
    MissingPseudoHeader,
    InvalidStatus,
    InvalidContentLength,
    InvalidHeader,
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
        const peer_settings = try http2.parseSettings(self.allocator, client_settings.frame.payload);
        defer self.allocator.free(peer_settings);

        try writeFrame(self.allocator, self.io, stream, .settings, 0, 0, &.{});
        try writeFrame(self.allocator, self.io, stream, .settings, flag_ack, 0, &.{});

        var connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .role = .server,
            .limits = self.limits,
        };
        try connection.applySettings(peer_settings);
        return connection;
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
        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
            .limits = limits,
        };
        errdefer connection.close();
        while (!saw_server_settings or !saw_settings_ack) {
            var frame = try readFrame(allocator, io, stream, limits);
            defer frame.deinit(allocator);
            if (frame.frame.header.frame_type != .settings) return error.UnexpectedFrame;
            if ((frame.frame.header.flags & flag_ack) != 0) {
                saw_settings_ack = true;
            } else {
                saw_server_settings = true;
                const settings = try http2.parseSettings(allocator, frame.frame.payload);
                defer allocator.free(settings);
                try connection.applySettings(settings);
                try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
            }
        }
        return connection;
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

    pub fn adjust(self: *FlowWindow, delta: i64) void {
        self.value = std.math.add(i64, self.value, delta) catch if (delta > 0) std.math.maxInt(i64) else std.math.minInt(i64);
    }
};

const StreamWindowEntry = struct {
    stream_id: u31,
    window: FlowWindow = .{},
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
    send_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    recv_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    peer_initial_stream_window: i64 = default_flow_window,

    pub fn close(self: *Connection) void {
        self.send_stream_windows.deinit(self.allocator);
        self.recv_stream_windows.deinit(self.allocator);
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
        try validateHeaderBlock(fields.items, .request);
        try validateHeaderBlock(options.trailers, .request_trailers);

        try self.writeHeaders(stream_id, fields.items, options.body.len == 0 and options.trailers.len == 0);
        if (options.body.len != 0) try self.writeData(stream_id, options.body, options.trailers.len == 0);
        if (options.trailers.len != 0) try self.writeHeaders(stream_id, options.trailers, true);
        return self.readResponse(stream_id, options.method);
    }

    pub fn readRequest(self: *Connection) Error!OwnedRequest {
        if (self.role != .server) return error.UnexpectedFrame;
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            switch (frame.frame.header.frame_type) {
                .settings => {
                    if ((frame.frame.header.flags & flag_ack) == 0) {
                        const settings = try http2.parseSettings(self.allocator, frame.frame.payload);
                        defer self.allocator.free(settings);
                        try self.applySettings(settings);
                        try writeFrame(self.allocator, self.io, self.stream, .settings, flag_ack, 0, &.{});
                    }
                    continue;
                },
                .headers => {
                    const stream_id = frame.frame.header.stream_id;
                    const headers = try self.readHeaderBlock(frame.frame);
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .request);
                    var trailers: []http2.Hpack.HeaderField = &.{};
                    errdefer freeHeaders(self.allocator, trailers);
                    var body: std.ArrayList(u8) = .empty;
                    errdefer body.deinit(self.allocator);

                    const method = findHeader(headers, ":method") orelse return error.MissingPseudoHeader;
                    const expected_request_len = try contentLength(headers);
                    if (std.ascii.eqlIgnoreCase(method, "CONNECT") and (expected_request_len orelse 0) != 0) return error.InvalidContentLength;

                    if (!std.ascii.eqlIgnoreCase(method, "CONNECT") and (frame.frame.header.flags & flag_end_stream) == 0) {
                        while (true) {
                            var data_frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
                            defer data_frame.deinit(self.allocator);
                            if (data_frame.frame.header.stream_id != stream_id) continue;
                            switch (data_frame.frame.header.frame_type) {
                                .data => {
                                    const data = try http2.DataPayload.parse(data_frame.frame);
                                    if (body.items.len + data.data.len > self.limits.max_body_bytes) return error.MessageTooLarge;
                                    try self.recv_connection_window.receive(data.data.len);
                                    try (try self.recvStreamWindow(stream_id)).receive(data.data.len);
                                    try body.appendSlice(self.allocator, data.data);
                                    if ((data_frame.frame.header.flags & flag_end_stream) != 0) break;
                                },
                                .headers => {
                                    if ((data_frame.frame.header.flags & flag_end_stream) == 0) return error.UnexpectedFrame;
                                    trailers = try self.readHeaderBlock(data_frame.frame);
                                    try validateHeaderBlock(trailers, .request_trailers);
                                    break;
                                },
                                else => return error.UnexpectedFrame,
                            }
                        }
                    }

                    try validateContentLength(headers, body.items.len);
                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = findHeader(headers, ":path") orelse return error.MissingPseudoHeader,
                        .scheme = findHeader(headers, ":scheme") orelse "https",
                        .authority = findHeader(headers, ":authority"),
                        .body = try body.toOwnedSlice(self.allocator),
                        .trailers = trailers,
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
        try validateHeaderBlock(fields.items, .response);
        try validateHeaderBlock(options.trailers, .response_trailers);
        try self.writeHeaders(stream_id, fields.items, options.body.len == 0 and options.trailers.len == 0);
        if (options.body.len != 0) try self.writeData(stream_id, options.body, options.trailers.len == 0);
        if (options.trailers.len != 0) try self.writeHeaders(stream_id, options.trailers, true);
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

    pub fn sendResetStream(self: *Connection, stream_id: u31, error_code: http2.ErrorCode) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.ResetStreamPayload.write(&encoded, self.allocator, stream_id, error_code);
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn readResetStream(self: *Connection) Error!OwnedResetStream {
        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .rst_stream) {
                frame.deinit(self.allocator);
                continue;
            }
            return .{ .frame = frame, .reset = try http2.ResetStreamPayload.parse(frame.frame) };
        }
    }

    pub fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u31) Error!void {
        if (stream_id == 0) {
            self.recv_connection_window.update(increment);
        } else {
            (try self.recvStreamWindow(stream_id)).update(increment);
        }
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
            if (update.stream_id == 0) {
                self.send_connection_window.update(update.increment);
            } else {
                (try self.sendStreamWindow(update.stream_id)).update(update.increment);
            }
            return .{ .frame = frame, .window_update = update };
        }
    }

    fn readResponse(self: *Connection, stream_id: u31, request_method: []const u8) Error!OwnedResponse {
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |h| freeHeaders(self.allocator, h);
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);

        while (true) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type == .settings) {
                if ((frame.frame.header.flags & flag_ack) == 0) {
                    const settings = try http2.parseSettings(self.allocator, frame.frame.payload);
                    defer self.allocator.free(settings);
                    try self.applySettings(settings);
                    try writeFrame(self.allocator, self.io, self.stream, .settings, flag_ack, 0, &.{});
                }
                continue;
            }
            if (frame.frame.header.frame_type == .window_update) {
                const update = try http2.WindowUpdatePayload.parse(frame.frame);
                if (update.stream_id == 0) {
                    self.send_connection_window.update(update.increment);
                } else {
                    (try self.sendStreamWindow(update.stream_id)).update(update.increment);
                }
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) continue;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    if (headers) |h| {
                        if ((frame.frame.header.flags & flag_end_stream) == 0) return error.UnexpectedFrame;
                        try validateContentLength(h, body.items.len);
                        trailers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(trailers, .response_trailers);
                        break;
                    } else {
                        headers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(headers.?, .response);
                        const status_s = findHeader(headers.?, ":status") orelse return error.MissingPseudoHeader;
                        const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
                        if (responseForbidsBody(status, request_method)) {
                            const response_content_length = (try contentLength(headers.?)) orelse 0;
                            if (std.ascii.eqlIgnoreCase(request_method, "CONNECT") and response_content_length != 0) return error.InvalidContentLength;
                            break;
                        }
                        if ((frame.frame.header.flags & flag_end_stream) != 0) {
                            try validateContentLength(headers.?, 0);
                            break;
                        }
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const data = try http2.DataPayload.parse(frame.frame);
                    if (body.items.len + data.data.len > self.limits.max_body_bytes) return error.MessageTooLarge;
                    try self.recv_connection_window.receive(data.data.len);
                    try (try self.recvStreamWindow(stream_id)).receive(data.data.len);
                    try body.appendSlice(self.allocator, data.data);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        if (headers) |h| try validateContentLength(h, body.items.len);
                        break;
                    }
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
            .trailers = trailers,
        };
    }

    fn writeHeaders(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, end_stream: bool) Error!void {
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try http2.Hpack.encodeLiteralBlock(&block, self.allocator, headers);
        try self.writeHeaderBlock(stream_id, block.items, end_stream);
    }

    fn writeHeaderBlock(self: *Connection, stream_id: u31, block: []const u8, end_stream: bool) Error!void {
        const chunk_size = @max(@as(usize, 1), self.limits.max_frame_payload);
        const first_len = @min(block.len, chunk_size);
        var offset = first_len;
        try writeFrame(
            self.allocator,
            self.io,
            self.stream,
            .headers,
            (if (offset == block.len) flag_end_headers else 0) | if (end_stream) flag_end_stream else 0,
            stream_id,
            block[0..first_len],
        );
        while (offset < block.len) {
            const end = @min(block.len, offset + chunk_size);
            try writeFrame(
                self.allocator,
                self.io,
                self.stream,
                .continuation,
                if (end == block.len) flag_end_headers else 0,
                stream_id,
                block[offset..end],
            );
            offset = end;
        }
    }

    fn readHeaderBlock(self: *Connection, first: http2.Frame) Error![]http2.Hpack.HeaderField {
        if (first.header.frame_type != .headers) return error.UnexpectedFrame;
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try block.appendSlice(self.allocator, first.payload);
        if (block.items.len > self.limits.max_frame_payload * @as(usize, self.limits.max_header_fields + 1)) return error.MessageTooLarge;

        var flags = first.header.flags;
        while ((flags & flag_end_headers) == 0) {
            var frame = try readFrame(self.allocator, self.io, self.stream, self.limits);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .continuation or frame.frame.header.stream_id != first.header.stream_id) {
                return error.UnexpectedFrame;
            }
            try block.appendSlice(self.allocator, frame.frame.payload);
            if (block.items.len > self.limits.max_frame_payload * @as(usize, self.limits.max_header_fields + 1)) return error.MessageTooLarge;
            flags = frame.frame.header.flags;
        }
        return cloneDecodedHeaders(self.allocator, block.items, self.limits);
    }

    fn writeData(self: *Connection, stream_id: u31, data: []const u8, end_stream: bool) Error!void {
        try self.send_connection_window.reserve(data.len);
        errdefer self.send_connection_window.update(@intCast(data.len));
        const stream_window = try self.sendStreamWindow(stream_id);
        try stream_window.reserve(data.len);
        errdefer stream_window.update(@intCast(data.len));
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

    fn applySettings(self: *Connection, settings: []const http2.Setting) Error!void {
        for (settings) |setting| {
            if (setting.id == .initial_window_size) {
                const new_window = std.math.cast(i64, setting.value) orelse return error.InvalidSetting;
                const delta = new_window - self.peer_initial_stream_window;
                self.peer_initial_stream_window = new_window;
                for (self.send_stream_windows.items) |*entry| entry.window.adjust(delta);
            }
        }
    }

    fn sendStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        for (self.send_stream_windows.items) |*entry| {
            if (entry.stream_id == stream_id) return &entry.window;
        }
        try self.send_stream_windows.append(self.allocator, .{ .stream_id = stream_id, .window = .{ .value = self.peer_initial_stream_window } });
        return &self.send_stream_windows.items[self.send_stream_windows.items.len - 1].window;
    }

    fn recvStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        for (self.recv_stream_windows.items) |*entry| {
            if (entry.stream_id == stream_id) return &entry.window;
        }
        try self.recv_stream_windows.append(self.allocator, .{ .stream_id = stream_id });
        return &self.recv_stream_windows.items[self.recv_stream_windows.items.len - 1].window;
    }
};

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
};

pub const ResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
};

pub const OwnedRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    body: []u8,
    trailers: []http2.Hpack.HeaderField = &.{},

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const OwnedResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body: []u8,
    trailers: []http2.Hpack.HeaderField = &.{},

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
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

pub const OwnedResetStream = struct {
    frame: OwnedFrame,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *OwnedResetStream, allocator: std.mem.Allocator) void {
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

fn contentLength(headers: []const http2.Hpack.HeaderField) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        var parts = std.mem.splitScalar(u8, header.value, ',');
        while (parts.next()) |raw_part| {
            const part = std.mem.trim(u8, raw_part, " \t");
            if (part.len == 0) return error.InvalidContentLength;
            const parsed = std.fmt.parseInt(usize, part, 10) catch return error.InvalidContentLength;
            if (found) |existing| {
                if (existing != parsed) return error.InvalidContentLength;
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

fn validateContentLength(headers: []const http2.Hpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != actual) return error.InvalidContentLength;
    }
}

const HeaderBlockKind = enum {
    request,
    response,
    request_trailers,
    response_trailers,
};

fn validateHeaderBlock(headers: []const http2.Hpack.HeaderField, kind: HeaderBlockKind) Error!void {
    var connection_header_values: std.ArrayList([]const u8) = .empty;
    defer connection_header_values.deinit(std.heap.page_allocator);
    var saw_regular = false;
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    var seen_status = false;

    for (headers) |header| {
        try validateHeaderName(header.name);
        const pseudo = std.mem.startsWith(u8, header.name, ":");
        if (pseudo) {
            if (saw_regular) return error.InvalidHeader;
            switch (kind) {
                .request => try markRequestPseudo(header.name, &seen_method, &seen_scheme, &seen_path, &seen_authority),
                .response => try markResponsePseudo(header.name, &seen_status),
                .request_trailers, .response_trailers => return error.InvalidHeader,
            }
            continue;
        }
        saw_regular = true;

        if (connectionSpecificHeaderName(header.name)) return error.InvalidHeader;
        if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
            // RFC 9113 inherits the HTTP/1.1 Connection token rule: anything
            // nominated by Connection is connection-specific and forbidden in
            // HTTP/2.  We reject the block instead of silently stripping so
            // runtime callers see malformed peers immediately.
            try connection_header_values.append(std.heap.page_allocator, header.value);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "te")) {
            switch (kind) {
                .request => if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return error.InvalidHeader,
                else => return error.InvalidHeader,
            }
        }
    }

    switch (kind) {
        .request => if (!seen_method or !seen_scheme or !seen_path) return error.MissingPseudoHeader,
        .response => if (!seen_status) return error.MissingPseudoHeader,
        .request_trailers, .response_trailers => {},
    }

    for (connection_header_values.items) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |raw| {
            const token = std.mem.trim(u8, raw, " \t");
            if (token.len == 0) return error.InvalidHeader;
            for (headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, token)) return error.InvalidHeader;
            }
        }
    }
}

fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeader;
    for (name) |byte| {
        if (byte >= 'A' and byte <= 'Z') return error.InvalidHeader;
        if (!validHeaderNameByte(byte)) return error.InvalidHeader;
    }
}

fn validHeaderNameByte(byte: u8) bool {
    return std.ascii.isLower(byte) or std.ascii.isDigit(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':' => true,
        else => false,
    };
}

fn markRequestPseudo(
    name: []const u8,
    seen_method: *bool,
    seen_scheme: *bool,
    seen_path: *bool,
    seen_authority: *bool,
) Error!void {
    if (std.mem.eql(u8, name, ":method")) return markOnce(seen_method);
    if (std.mem.eql(u8, name, ":scheme")) return markOnce(seen_scheme);
    if (std.mem.eql(u8, name, ":path")) return markOnce(seen_path);
    if (std.mem.eql(u8, name, ":authority")) return markOnce(seen_authority);
    return error.InvalidHeader;
}

fn markResponsePseudo(name: []const u8, seen_status: *bool) Error!void {
    if (std.mem.eql(u8, name, ":status")) return markOnce(seen_status);
    return error.InvalidHeader;
}

fn markOnce(seen: *bool) Error!void {
    if (seen.*) return error.InvalidHeader;
    seen.* = true;
}

fn connectionSpecificHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

fn responseForbidsBody(status: u16, request_method: []const u8) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (std.ascii.eqlIgnoreCase(request_method, "HEAD")) return true;
    if (std.ascii.eqlIgnoreCase(request_method, "CONNECT") and status >= 200 and status < 300) return true;
    return false;
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
            try connection.sendWindowUpdate(request.stream_id, 1024);
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
    var stream_window = try client.readWindowUpdate();
    defer stream_window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), stream_window.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 1024), stream_window.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 1024 - "ping".len), (try client.sendStreamWindow(1)).value);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
}

test "HTTP/2 runtime sends and receives RST_STREAM" {
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

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/reset-me", request.path);
            try connection.sendResetStream(request.stream_id, .cancel);

            var reset = try connection.readResetStream();
            defer reset.deinit(server_ptr.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.no_error, reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-me" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try client.writeHeaders(1, &fields, true);

    var inbound_reset = try client.readResetStream();
    defer inbound_reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), inbound_reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, inbound_reset.reset.error_code);

    try client.sendResetStream(1, .no_error);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime reads and writes CONTINUATION header blocks" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 24, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const long_header_value = "abcdefghijklmnopqrstuvwxyz0123456789";
    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, shared.expected) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server, expected: []const u8) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/continuation", request.path);
            try std.testing.expectEqualStrings(expected, findHeader(request.headers, "x-long").?);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "x-long-response", .value = expected },
                },
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server, .expected = long_header_value };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 24,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/continuation",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqualStrings(long_header_value, findHeader(response.headers, "x-long-response").?);
}

test "HTTP/2 runtime rejects malformed CONTINUATION sequence" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.UnexpectedFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-continuation" },
        .{ .name = ":scheme", .value = "https" },
    });
    const split = block.items.len / 2;
    try writeFrame(allocator, io, client.stream, .headers, 0, 1, block.items[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, block.items[split..]);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime exchanges request and response trailers" {
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

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/trailers", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings("request-checksum", request.trailers[0].name);
            try std.testing.expectEqualStrings("ok", request.trailers[0].value);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "world",
                .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/trailers",
        .authority = "localhost",
        .body = "hello",
        .trailers = &.{.{ .name = "request-checksum", .value = "ok" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("world", response.body);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", response.trailers[0].name);
    try std.testing.expectEqualStrings("0", response.trailers[0].value);
}

test "HTTP/2 runtime validates connection-specific headers" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidHeader) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidHeader;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-header" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "connection", .value = "x-hop" },
        .{ .name = "x-hop", .value = "secret" },
    };
    try client.writeHeaders(1, &fields, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-te",
        .authority = "localhost",
        .headers = &.{.{ .name = "te", .value = "gzip" }},
    }));
    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-transfer-encoding",
        .authority = "localhost",
        .headers = &.{.{ .name = "transfer-encoding", .value = "chunked" }},
    }));
    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-trailer-te",
        .authority = "localhost",
        .trailers = &.{.{ .name = "te", .value = "trailers" }},
    }));
}

test "HTTP/2 runtime validates pseudo headers and lowercase names" {
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
        expected_errors: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            while (shared.expected_errors < 3) {
                var request = connection.readRequest() catch |err| {
                    if (err == error.InvalidHeader or err == error.MissingPseudoHeader) {
                        shared.expected_errors += 1;
                        continue;
                    }
                    shared.err = err;
                    return;
                };
                request.deinit(shared.server.allocator);
                shared.err = error.InvalidHeader;
                return;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const uppercase = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/uppercase" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Host", .value = "localhost" },
    };
    try client.writeHeaders(1, &uppercase, true);

    const late_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/late-pseudo" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(3, &late_pseudo, true);

    const duplicate_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/duplicate-pseudo" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(5, &duplicate_pseudo, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), shared.expected_errors);

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-response-header",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "bad" }},
    }));
    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-request-pseudo",
        .authority = "localhost",
        .headers = &.{.{ .name = ":status", .value = "200" }},
    }));
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

test "HTTP/2 runtime validates request content-length" {
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
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidContentLength;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &fields, false);
    try client.writeData(1, "ping", true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime validates response content-length and method body rules" {
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
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var mismatch = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer mismatch.deinit(shared.server.allocator);
            connection.writeResponse(mismatch.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-length", .value = "5" }},
                .body = "pong",
            }) catch |err| {
                shared.err = err;
                return;
            };

            var head = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer head.deinit(shared.server.allocator);
            connection.writeResponse(head.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-length", .value = "5" }},
            }) catch |err| {
                shared.err = err;
                return;
            };

            var connect = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer connect.deinit(shared.server.allocator);
            connection.writeResponse(connect.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-length", .value = "9" }},
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/mismatch",
        .authority = "localhost",
    }));

    var head_response = try client.request(.{
        .method = "HEAD",
        .path = "/head",
        .authority = "localhost",
    });
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.status);
    try std.testing.expectEqualStrings("", head_response.body);

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "CONNECT",
        .path = "example.com:443",
        .authority = "example.com:443",
    }));

    thread.join();
    if (shared.err) |err| return err;
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

test "HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE updates stream send windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
    }

    const first = try connection.sendStreamWindow(1);
    try first.reserve(1024);
    try std.testing.expectEqual(@as(i64, default_flow_window - 1024), first.value);

    const settings = [_]http2.Setting{.{ .id = .initial_window_size, .value = 70_000 }};
    try connection.applySettings(&settings);
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 70_000 - 1024), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(@as(i64, 70_000), (try connection.sendStreamWindow(3)).value);
}
