const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");

const Mode = enum { aggregate, padded, streaming, batch };
const Failure = enum { overrun, short_fin, trailers, callback, peer_reset };
const Flow = enum { ordinary, refill, adaptive };

test {
    _ = @import("credit_reset_tests.zig");
}

test "HTTP/2 failed request readers return prior DATA connection credit" {
    for ([_]Mode{ .aggregate, .padded, .streaming, .batch }) |mode| {
        for ([_]Failure{ .overrun, .short_fin, .trailers }) |failure| try exercise(mode, failure, .ordinary);
    }
    try exercise(.streaming, .callback, .ordinary);
    try exercise(.batch, .callback, .ordinary);
    try exercise(.aggregate, .peer_reset, .ordinary);
    try exercise(.streaming, .peer_reset, .ordinary);
}

test "HTTP/2 failed request readers exclude refills and adaptive grants from refunds" {
    for ([_]Mode{ .aggregate, .streaming, .batch }) |mode| {
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
        mode: Mode,
        failure: Failure,
        flow: Flow,
        delivered: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn consume(self: *@This(), bytes: []const u8) !void {
            if (self.failure == .callback and self.delivered != 0) return error.CallbackRejected;
            self.delivered += bytes.len;
        }

        fn consumeBatch(self: *@This(), id: u31, bytes: []const u8) !void {
            if (id == 1) try self.consume(bytes);
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            if (self.flow == .adaptive) {
                (try runtime.testing.recvStreamWindow(&connection, 1)).value = window.max_value;
                try runtime.testing.queueAdaptiveWindowTarget(&connection, 65_537);
                var increment: [4]u8 = undefined;
                std.mem.writeInt(u32, &increment, @intCast(window.max_value - window.default_value), .big);
                var bytes: std.ArrayList(u8) = .empty;
                defer bytes.deinit(self.server.allocator);
                try wire.appendFrame(&bytes, self.server.allocator, .window_update, 0, 1, &increment);
                var writer = connection.stream.writer(connection.io, &.{});
                try writer.interface.writeAll(bytes.items);
            }
            const before = connection.recv_connection_window.value;
            const expected = switch (self.failure) {
                .callback => error.CallbackRejected,
                .peer_reset => error.StreamReset,
                else => error.InvalidContentLength,
            };
            switch (self.mode) {
                .aggregate, .padded => try std.testing.expectError(expected, connection.readRequestWithTimeout(.fromSeconds(2))),
                .streaming => try std.testing.expectError(expected, connection.readRequestStreamingWithTimeout(.fromSeconds(2), self, @This().consume)),
                .batch => {
                    var requests: [2]runtime.StreamingRequest = undefined;
                    try std.testing.expectError(expected, connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(2), self, @This().consumeBatch));
                },
            }
            try std.testing.expectEqual(before + @as(i64, if (self.flow == .adaptive) 2 else 0), connection.recv_connection_window.value);
            try std.testing.expect(!connection.aggregate_timeout_unusable);
            if (self.mode != .batch and self.failure != .callback and self.failure != .peer_reset) {
                // Direct reads keep the existing caller-selected reset policy.
                var encoded: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
                var writer = connection.stream.writer(connection.io, &.{});
                try writer.interface.writeAll(try http2.ResetStreamPayload.writeInto(&encoded, 1, .protocol_error));
                connection.abandonPeerRequest(1, .protocol_error);
            }
            var healthy = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer healthy.deinit(allocator);
            try connection.writeResponse(healthy.stream_id, .{ .body = "healthy" });
        }
    };
    var peer = Peer{ .server = &server, .mode = mode, .failure = failure, .flow = flow };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    client.next_client_stream_id = if (mode == .batch) 5 else 3;
    try runtime.testing.addActiveLocalStream(&client, 1);
    if (mode == .batch) try runtime.testing.addActiveLocalStream(&client, 3);
    try appendHead(&client, &bytes, 1, if (flow == .refill) "40001" else if (failure == .overrun) "3" else "6");
    if (flow == .adaptive) {
        var writer = client.stream.writer(io, &.{});
        try writer.interface.writeAll(bytes.items);
        bytes.clearRetainingCapacity();
        var update = try client.readWindowUpdateWithTimeout(.fromSeconds(2));
        defer update.deinit(allocator);
        try std.testing.expectEqual(@as(u31, 1), update.window_update.stream_id);
    }
    var charged: usize = if (flow == .refill) 40_000 else if (mode == .aggregate) 2 else 5;
    if (flow == .refill) {
        const chunk = "a" ** 8_000;
        for (0..5) |_| try wire.appendFrame(&bytes, allocator, .data, 0, 1, chunk);
    } else {
        try wire.appendFrame(&bytes, allocator, .data, if (mode == .aggregate) 0 else 0x08, 1, if (mode == .aggregate) "ab" else "\x02ab\x00\x00");
    }
    if (mode == .batch) {
        try appendHead(&client, &bytes, 3, "6");
        try wire.appendFrame(&bytes, allocator, .data, 0x08, 3, "\x00xy");
        try (try runtime.testing.sendStreamWindow(&client, 3)).reserve(3);
    }
    if (failure == .peer_reset) {
        try wire.appendFrame(&bytes, allocator, .rst_stream, 0, 1, &.{ 0, 0, 0, @intFromEnum(http2.ErrorCode.cancel) });
    } else if (failure == .trailers) {
        const trailers = try client.hpack_encoder.encodeBlockRetained(allocator, &.{.{ .name = "x-done", .value = "yes" }});
        try wire.appendFrame(&bytes, allocator, .headers, 0x05, 1, trailers);
    } else {
        try wire.appendFrame(&bytes, allocator, .data, if (failure == .short_fin) 1 else 0, 1, "cd");
        charged += 2;
    }
    try client.send_connection_window.reserve(charged);
    try (try runtime.testing.sendStreamWindow(&client, 1)).reserve(charged);
    if (mode == .batch) try client.send_connection_window.reserve(3);
    var writer = client.stream.writer(io, &.{});
    try writer.interface.writeAll(bytes.items);
    if (failure != .peer_reset) {
        var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
        defer reset.deinit(allocator);
        try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
        try std.testing.expectEqual(if (failure == .callback) http2.ErrorCode.cancel else http2.ErrorCode.protocol_error, reset.reset.error_code);
        if (mode == .batch) {
            var sibling = try client.readResetStreamWithTimeout(.fromSeconds(2));
            defer sibling.deinit(allocator);
            try std.testing.expectEqual(@as(u31, 3), sibling.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, sibling.reset.error_code);
        }
    }
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    try std.testing.expectEqual(window.default_value + @as(i64, if (flow == .adaptive) 2 else 0), client.send_connection_window.value);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn appendHead(client: *runtime.Connection, bytes: *std.ArrayList(u8), id: u31, length: []const u8) !void {
    const block = try client.hpack_encoder.encodeBlockRetained(std.testing.allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/failed" },
        .{ .name = "content-length", .value = length },
    });
    try wire.appendFrame(bytes, std.testing.allocator, .headers, 0x04, id, block);
}
