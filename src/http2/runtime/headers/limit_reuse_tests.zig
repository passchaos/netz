const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const Mode = enum { aggregate, callback, duplex, server, push, aggregate_bytes, server_bytes, push_promise };
const large_request_fields = [_]http2.Hpack.HeaderField{
    .{ .name = ":method", .value = "GET" },              .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" ++ "~" ** 24_000 }, .{ .name = ":authority", .value = "localhost" },
};
const large_response_fields = [_]http2.Hpack.HeaderField{
    .{ .name = ":status", .value = "200" },            .{ .name = "x-large", .value = "~" ** 24_000 },
    .{ .name = "x-dictionary", .value = "preserved" },
};

test "HTTP/2 complete continuation overflow preserves aggregate HPACK reuse" {
    try exercise(.aggregate);
}
test "HTTP/2 complete continuation overflow preserves callback HPACK reuse" {
    try exercise(.callback);
}
test "HTTP/2 complete continuation overflow preserves duplex HPACK reuse" {
    try exercise(.duplex);
}
test "HTTP/2 complete continuation overflow preserves server HPACK reuse" {
    try exercise(.server);
}
test "HTTP/2 complete continuation overflow preserves push HPACK and parent" {
    try exercise(.push);
}
test "HTTP/2 complete compressed block overflow preserves aggregate HPACK reuse" {
    try exercise(.aggregate_bytes);
}
test "HTTP/2 complete compressed block overflow preserves server HPACK reuse" {
    try exercise(.server_bytes);
}
test "HTTP/2 complete continuation overflow refuses promise while preserving HPACK and parent" {
    try exercise(.push_promise);
}

fn exercise(comptime mode: Mode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const server_mode = mode == .server or mode == .server_bytes;
    const byte_mode = mode == .aggregate_bytes or mode == .server_bytes;
    var predictor = http2.Hpack.Encoder{};
    defer predictor.deinit(allocator);
    const predicted = if (byte_mode) try predictor.encodeBlockRetained(allocator, if (server_mode) &large_request_fields else &large_response_fields) else &.{};
    // The sixth, terminal frame crosses a five-frame compressed-byte budget.
    const payload_limit: usize = if (byte_mode) (predicted.len - 1) / 5 else 16 * 1024 * 1024;
    if (byte_mode) try std.testing.expect(payload_limit >= 8 and payload_limit <= 16 * 1024);
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_frame_payload = if (mode == .server_bytes) payload_limit else 16 * 1024 * 1024,
        .max_header_fields = if (mode == .server_bytes) 4 else 256,
        .max_continuation_frames = if (mode == .server_bytes) 100 else if (server_mode) 1 else null,
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        payload_limit: usize,
        calls: usize = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn handler(self: *@This(), request: runtime.OwnedRequest) runtime.Error!runtime.ResponseOptions {
            self.calls += 1;
            if (!std.mem.eql(u8, "localhost", request.authority orelse "")) return error.InvalidHeader;
            return .{ .body = "healthy" };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            if (server_mode) {
                try std.testing.expectError(error.MessageTooLarge, connection.serveOne(@This(), self, @This().handler));
                try std.testing.expectEqual(@as(usize, 0), self.calls);
                _ = try connection.serveOne(@This(), self, @This().handler);
                try std.testing.expectEqual(@as(usize, 1), self.calls);
                return;
            }
            var request = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer request.deinit(self.server.allocator);
            const id = if (mode == .push_promise) blk: {
                const fields = [_]http2.Hpack.HeaderField{
                    .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/push" },
                    .{ .name = "x-large", .value = "s" ** 30_000 },  .{ .name = "x-dictionary", .value = "preserved" },
                };
                var encoder = http2.Hpack.Encoder{};
                defer encoder.deinit(self.server.allocator);
                const estimated = try encoder.encodeBlockRetained(self.server.allocator, &fields);
                // Emit exactly HEADERS/PUSH_PROMISE plus two continuations.
                connection.limits.max_frame_payload = estimated.len / 3 + 8;
                try std.testing.expect(connection.limits.max_frame_payload <= 16 * 1024);
                break :blk try connection.promisePush(request.stream_id, &fields);
            } else if (mode == .push) try connection.promisePush(request.stream_id, &.{
                .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/push" },
            }) else request.stream_id;
            if (mode != .push_promise) {
                const block = try connection.hpack_encoder.encodeBlockRetained(self.server.allocator, if (mode == .aggregate_bytes) &large_response_fields else &.{
                    .{ .name = ":status", .value = "200" }, .{ .name = "x-dictionary", .value = "preserved" },
                });
                try fragmented(&connection, id, block, if (mode == .aggregate_bytes) self.payload_limit else null);
            }
            var reset = try connection.readResetStreamWithTimeout(.fromSeconds(2));
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(id, reset.reset.stream_id);
            try std.testing.expectEqual(if (mode == .push_promise) http2.ErrorCode.refused_stream else if (mode == .push) http2.ErrorCode.cancel else http2.ErrorCode.enhance_your_calm, reset.reset.error_code);
            if (mode == .push or mode == .push_promise) try connection.writeResponse(request.stream_id, .{ .body = "parent", .headers = &.{.{ .name = "x-dictionary", .value = "preserved" }} });
            var next = try connection.readRequestWithTimeout(.fromSeconds(2));
            defer next.deinit(self.server.allocator);
            try connection.writeResponse(next.stream_id, .{ .body = "healthy", .headers = &.{.{ .name = "x-dictionary", .value = "preserved" }} });
        }
    };
    var peer = Peer{ .server = &server, .payload_limit = payload_limit };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = if (mode == .aggregate_bytes) payload_limit else 16 * 1024 * 1024,
        .max_header_fields = if (mode == .aggregate_bytes) 4 else 256,
        .max_continuation_frames = if (mode == .aggregate_bytes) 100 else if (server_mode) null else 1,
        .enable_push = mode == .push or mode == .push_promise,
    });
    defer client.close();
    const options = runtime.RequestOptions{ .path = "/limit", .authority = "localhost" };
    switch (mode) {
        .aggregate, .aggregate_bytes => try std.testing.expectError(error.MessageTooLarge, client.requestWithTimeout(options, .fromSeconds(1))),
        .callback => {
            var delivered: usize = 0;
            try std.testing.expectError(error.MessageTooLarge, client.requestStreamingWithTimeout(options, .fromSeconds(1), &delivered, struct {
                fn consume(count: *usize, bytes: []const u8) !void {
                    count.* += bytes.len;
                }
            }.consume));
            try std.testing.expectEqual(@as(usize, 0), delivered);
        },
        .duplex => {
            var writer = try client.startRequest(.{ .path = options.path, .authority = options.authority });
            defer writer.deinit();
            try writer.finish();
            var duplex = try writer.beginDuplex();
            defer duplex.deinit();
            try std.testing.expectError(error.MessageTooLarge, duplex.readResponseEventWithTimeout(.fromSeconds(1)));
            const table_used = client.hpack_decoder.dynamic_table.used;
            try std.testing.expectError(error.MessageTooLarge, duplex.readResponseEventWithTimeout(.fromSeconds(1)));
            try std.testing.expectEqual(table_used, client.hpack_decoder.dynamic_table.used);
            try duplex.reset(.enhance_your_calm);
        },
        .server, .server_bytes => {
            const fields = [_]http2.Hpack.HeaderField{
                .{ .name = ":method", .value = "GET" },  .{ .name = ":scheme", .value = "http" },
                .{ .name = ":path", .value = "/limit" }, .{ .name = ":authority", .value = "localhost" },
            };
            const block = try client.hpack_encoder.encodeBlockRetained(allocator, if (mode == .server_bytes) &large_request_fields else &fields);
            try fragmented(&client, 1, block, if (mode == .server_bytes) payload_limit else null);
            client.next_client_stream_id = 3;
            var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, reset.reset.error_code);
        },
        .push => {
            var parent = try client.requestWithTimeout(options, .fromSeconds(2));
            defer parent.deinit(allocator);
            try std.testing.expectEqualStrings("parent", parent.body);
            try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(parent.headers, "x-dictionary").?);
            var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
            defer promise.deinit(allocator);
            try std.testing.expectError(error.MessageTooLarge, client.readPushedResponseWithTimeout(promise, .fromSeconds(1)));
        },
        .push_promise => {
            var parent = try client.requestWithTimeout(options, .fromSeconds(2));
            defer parent.deinit(allocator);
            try std.testing.expectEqualStrings("parent", parent.body);
            try std.testing.expect(client.takePromisedRequest() == null);
        },
    }
    var healthy = try client.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(2));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("healthy", healthy.body);
    if (!server_mode) try std.testing.expectEqualStrings("preserved", runtime.testing.findHeader(healthy.headers, "x-dictionary").?);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn fragmented(connection: *runtime.Connection, id: u31, block: []const u8, payload_limit: ?usize) !void {
    try std.testing.expect(block.len > 2);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    if (payload_limit) |limit| {
        var offset: usize = 0;
        while (offset < block.len) {
            const end = @min(block.len, offset + limit);
            try wire.appendFrame(&bytes, std.testing.allocator, if (offset == 0) .headers else .continuation, @as(u8, if (offset == 0) 0x01 else 0) | @as(u8, if (end == block.len) 0x04 else 0), id, block[offset..end]);
            offset = end;
        }
    } else {
        try wire.appendFrame(&bytes, std.testing.allocator, .headers, 0x01, id, block[0..1]);
        try wire.appendFrame(&bytes, std.testing.allocator, .continuation, 0, id, block[1 .. block.len - 1]);
        try wire.appendFrame(&bytes, std.testing.allocator, .continuation, 0x04, id, block[block.len - 1 ..]);
    }
    var writer = connection.stream.writer(connection.io, &.{});
    try writer.interface.writeAll(bytes.items);
}
