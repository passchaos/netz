const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const Mode = enum { bytes, data_bytes, count, reset, cancel, fragment };

pub fn sendFrame(connection: *runtime.Connection, kind: http2.FrameType, flags: u8, id: u31, payload: []const u8) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try wire.appendFrame(&encoded, std.testing.allocator, kind, flags, id, payload);
    var writer = connection.stream.writer(connection.io, &.{});
    try writer.interface.writeAll(encoded.items);
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *runtime.Server,
        mode: Mode,
        header_sent: std.Io.Event = .unset,
        resume_header: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.header_sent.set(self.server.io);
            };
        }

        fn promise(connection: *runtime.Connection, parent: u31, path: []const u8) !u31 {
            return connection.promisePush(parent, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = path },
            });
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer request.deinit(std.testing.allocator);
            const pushed = try promise(&connection, request.stream_id, "/push");
            if (self.mode == .fragment) {
                try connection.writeResponse(request.stream_id, .{});
                const block = try connection.hpack_encoder.encodeBlockRetained(std.testing.allocator, &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "0" },
                    .{ .name = "x-retry", .value = "retained" },
                });
                try std.testing.expect(block.len > 1);
                try sendFrame(&connection, .headers, 0x1, pushed, block[0..1]);
                self.header_sent.set(self.server.io);
                try self.resume_header.wait(self.server.io);
                try sendFrame(&connection, .continuation, 0x4, pushed, block[1..]);
                return;
            }
            if (self.mode == .reset) {
                var storage: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
                const bytes = try http2.ResetStreamPayload.writeInto(&storage, pushed, .cancel);
                var writer = connection.stream.writer(connection.io, &.{});
                try writer.interface.writeAll(bytes);
            } else {
                try connection.writePushedResponse(pushed, .{
                    .headers = &.{.{ .name = "x-dictionary", .value = "quota-dictionary" }},
                    .body = if (self.mode == .data_bytes) "body" ** 256 else "push",
                });
            }
            if (self.mode == .count) {
                const refused = try promise(&connection, request.stream_id, "/refused");
                try connection.writePushedResponse(refused, .{
                    .headers = &.{.{ .name = "x-dictionary", .value = "refused-dictionary" }},
                    .body = "refused",
                });
            }
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "x-dictionary", .value = if (self.mode == .count) "refused-dictionary" else "quota-dictionary" }},
                .body = "parent",
            });
            if (self.mode == .cancel) {
                var after = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer after.deinit(std.testing.allocator);
                try connection.writeResponse(after.stream_id, .{ .body = "healthy" });
            }
        }
    };
    var worker = Worker{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        worker.resume_header.set(io);
        thread.join();
    };
    var client = try runtime.Client.connect(std.testing.allocator, io, server.address(), .{
        .enable_push = true,
        .max_buffered_push_bytes = if (mode == .bytes) 0 else if (mode == .data_bytes) 300 else 4096,
        .max_buffered_pushes = if (mode == .count) 1 else 4,
    });
    defer client.close();
    var parent = try client.requestWithTimeout(.{ .path = "/", .authority = "localhost" }, .fromSeconds(3));
    defer parent.deinit(std.testing.allocator);
    var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
    var promise_owned = true;
    defer if (promise_owned) promise.deinit(std.testing.allocator);
    switch (mode) {
        .bytes, .data_bytes => {
            try std.testing.expectEqualStrings("parent", parent.body);
            try std.testing.expectError(error.PushBufferFull, client.readPushedResponseWithTimeout(promise, .fromSeconds(3)));
        },
        .reset => {
            try std.testing.expectEqualStrings("parent", parent.body);
            try std.testing.expectError(error.StreamReset, client.readPushedResponseWithTimeout(promise, .fromSeconds(3)));
        },
        .count => {
            try std.testing.expectEqualStrings("parent", parent.body);
            try std.testing.expectEqualStrings("refused-dictionary", runtime.testing.findHeader(parent.headers, "x-dictionary").?);
            try std.testing.expect(client.takePromisedRequest() == null);
            var pushed = try client.readPushedResponseWithTimeout(promise, .fromSeconds(3));
            defer pushed.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("push", pushed.body);
        },
        .cancel => {
            try std.testing.expect(client.push_state.state.?.received.retained_bytes != 0);
            const retained = client.push_state.state.?.received.retained_bytes;
            try std.testing.expectError(error.Timeout, client.readPushedResponseWithDeadline(promise, .{ .clock = .awake, .raw = .zero }));
            try std.testing.expectEqual(retained, client.push_state.state.?.received.retained_bytes);
            try client.cancelPush(&promise);
            promise_owned = false;
            try std.testing.expectEqual(@as(usize, 0), client.push_state.state.?.received.retained_bytes);
            var after = try client.requestWithTimeout(.{ .path = "/after", .authority = "localhost" }, .fromSeconds(3));
            defer after.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("healthy", after.body);
        },
        .fragment => {
            try worker.header_sent.wait(io);
            if (worker.err) |err| return err;
            try std.testing.expectError(error.Timeout, client.readPushedResponseWithTimeout(promise, .fromMilliseconds(10)));
            try std.testing.expect(!client.aggregate_timeout_unusable);
            try std.testing.expect(client.pending_push_header != null);
            worker.resume_header.set(io);
            var pushed = try client.readPushedResponseWithTimeout(promise, .fromSeconds(3));
            defer pushed.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("retained", runtime.testing.findHeader(pushed.headers, "x-retry").?);
            try std.testing.expectEqual(@as(usize, 0), pushed.body.len);
            try std.testing.expect(client.pending_push_header == null);
        },
    }
    try std.testing.expectEqual(@as(usize, 0), client.push_state.state.?.received.retained_bytes);
    try std.testing.expectEqual(@as(usize, 0), client.push_state.remoteReservedCount());
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/2 push byte quota cancels only its pushed stream" {
    try exercise(.bytes);
}
test "HTTP/2 push DATA byte quota releases credit and preserves parent" {
    try exercise(.data_bytes);
}
test "HTTP/2 push count quota preserves accepted push and parent" {
    try exercise(.count);
}
test "HTTP/2 push peer reset remains visible after parent completion" {
    try exercise(.reset);
}
test "HTTP/2 push cancellation frees buffered response and keeps connection usable" {
    try exercise(.cancel);
}
test "HTTP/2 push fragmented header timeout retains HPACK prefix for retry" {
    try exercise(.fragment);
}
