const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");

const Mode = enum { aggregate, streaming };
const Failure = enum { overrun, short_fin, short_trailers, callback, peer_reset };
const Flow = enum { ordinary, refill, adaptive };

test "HTTP/2 failed single responses return earlier DATA credit without starving later streams" {
    for ([_]Mode{ .aggregate, .streaming }) |mode| {
        for ([_]Failure{ .overrun, .short_fin, .short_trailers, .peer_reset }) |failure| try exercise(mode, failure, .ordinary);
    }
    try exercise(.streaming, .callback, .ordinary);
}

test "HTTP/2 failed single responses exclude refills and adaptive grants from refunds" {
    for ([_]Mode{ .aggregate, .streaming }) |mode| {
        try exercise(mode, .overrun, .refill);
        try exercise(mode, .overrun, .adaptive);
    }
}

fn exercise(mode: Mode, failure: Failure, flow: Flow) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        client: *runtime.Connection,
        failure: Failure,
        flow: Flow,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer request.deinit(self.server.allocator);
            if (self.flow == .adaptive) {
                // Match the locally prepared maximum on the wire before DATA
                // makes room for the queued two-byte adaptive expansion.
                var increment: [4]u8 = undefined;
                std.mem.writeInt(u32, &increment, @intCast(window.max_value - window.default_value), .big);
                var update: std.ArrayList(u8) = .empty;
                defer update.deinit(self.server.allocator);
                try wire.appendFrame(&update, self.server.allocator, .window_update, 0, request.stream_id, &increment);
                var client_writer = self.client.stream.writer(self.client.io, &.{});
                try client_writer.interface.writeAll(update.items);
                var received = try connection.readWindowUpdateWithTimeout(.fromSeconds(2));
                defer received.deinit(self.server.allocator);
                try std.testing.expectEqual(request.stream_id, received.window_update.stream_id);
            }
            const prefix_len: usize = if (self.flow == .refill) 40_000 else 2;
            // Raw message-error fixtures must still charge their sender's
            // windows before the adaptive SETTINGS delta or refill arrives.
            const charged = prefix_len + @as(usize, if (self.flow == .refill) 0 else 3) + @as(usize, if (self.failure == .peer_reset or self.failure == .short_trailers) 0 else 2);
            try connection.send_connection_window.reserve(charged);
            try (try runtime.testing.sendStreamWindow(&connection, request.stream_id)).reserve(charged);
            var length_storage: [20]u8 = undefined;
            const length = try std.fmt.bufPrint(&length_storage, "{d}", .{prefix_len + @as(usize, if (self.failure == .overrun) 1 else 4)});
            const headers = try connection.hpack_encoder.encodeBlockRetained(self.server.allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = length },
            });
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(self.server.allocator);
            try wire.appendFrame(&bytes, self.server.allocator, .headers, 0x04, request.stream_id, headers);
            if (self.flow == .refill) {
                const chunk = "a" ** 8_000;
                for (0..5) |_| try wire.appendFrame(&bytes, self.server.allocator, .data, 0, request.stream_id, chunk);
            } else {
                // Five charged bytes: two content, a Pad Length byte and padding.
                try wire.appendFrame(&bytes, self.server.allocator, .data, 0x08, request.stream_id, "\x02ab\x00\x00");
            }
            if (self.failure == .peer_reset) {
                try wire.appendFrame(&bytes, self.server.allocator, .rst_stream, 0, request.stream_id, &.{ 0, 0, 0, @intFromEnum(http2.ErrorCode.cancel) });
            } else if (self.failure == .short_trailers) {
                const trailers = try connection.hpack_encoder.encodeBlockRetained(self.server.allocator, &.{.{ .name = "x-done", .value = "yes" }});
                try wire.appendFrame(&bytes, self.server.allocator, .headers, 0x05, request.stream_id, trailers);
            } else {
                try wire.appendFrame(&bytes, self.server.allocator, .data, if (self.failure == .short_fin) 1 else 0, request.stream_id, "cd");
            }
            var writer = connection.stream.writer(connection.io, &.{});
            try writer.interface.writeAll(bytes.items);
            if (self.failure != .peer_reset) {
                var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
                defer reset.deinit(self.server.allocator);
                try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
                try std.testing.expectEqual(if (self.failure == .callback) http2.ErrorCode.cancel else http2.ErrorCode.protocol_error, reset.reset.error_code);
            }
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            // The peer has processed all preceding WINDOW_UPDATE frames by
            // this request. Verify the refund reached the wire, including the
            // adaptive two-byte grant, rather than only changing local state.
            try std.testing.expectEqual(window.default_value + @as(i64, if (self.flow == .adaptive) 2 else 0), connection.send_connection_window.value);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy" });
        }
    };
    var client: runtime.Connection = undefined;
    var peer = Peer{ .server = &server, .client = &client, .failure = failure, .flow = flow };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    if (flow == .adaptive) {
        (try runtime.testing.recvStreamWindow(&client, 1)).value = window.max_value;
        try runtime.testing.queueAdaptiveWindowTarget(&client, 65_537);
    }
    const before = client.recv_connection_window.value;
    const expected = switch (failure) {
        .callback => error.CallbackRejected,
        .peer_reset => error.StreamReset,
        else => error.InvalidContentLength,
    };
    var observed: Observer = .{ .failure = failure };
    if (mode == .aggregate) {
        try std.testing.expectError(expected, client.requestWithTimeout(.{ .path = "/malformed", .authority = "localhost" }, .fromSeconds(2)));
    } else {
        try std.testing.expectError(expected, client.requestStreamingWithTimeout(.{ .path = "/malformed", .authority = "localhost" }, .fromSeconds(2), &observed, Observer.consume));
        try std.testing.expectEqualStrings(if (flow == .refill) "a" ** 40_000 else "ab", observed.prefix[0..observed.len]);
    }
    try std.testing.expectEqual(before + @as(i64, if (flow == .adaptive) 2 else 0), client.recv_connection_window.value);
    try std.testing.expect(!client.aggregate_timeout_unusable);
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

const Observer = struct {
    failure: Failure,
    prefix: [40_000]u8 = undefined,
    len: usize = 0,

    fn consume(self: *@This(), bytes: []const u8) !void {
        if (self.failure == .callback and self.len != 0) return error.CallbackRejected;
        try std.testing.expect(bytes.len <= self.prefix.len - self.len);
        @memcpy(self.prefix[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};
