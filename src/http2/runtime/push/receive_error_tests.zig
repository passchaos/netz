const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const sendFrame = @import("receive_lifecycle_tests.zig").sendFrame;

const Mode = enum { hpack, interleaving, reserved_data, reserved_window, zero_window, late_data };

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        server: *runtime.Server,
        mode: Mode,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(3));
            defer request.deinit(std.testing.allocator);
            const pushed = try connection.promisePush(request.stream_id, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = "/push" },
            });
            switch (self.mode) {
                .hpack => try sendFrame(&connection, .headers, 0x5, pushed, "\xff"),
                .interleaving => {
                    try sendFrame(&connection, .headers, 0, request.stream_id, "\x88");
                    try sendFrame(&connection, .headers, 0x5, pushed, "\x88");
                },
                .reserved_data => try sendFrame(&connection, .data, 0x1, pushed, "x"),
                .reserved_window => try sendFrame(&connection, .window_update, 0, pushed, &.{ 0, 0, 0, 0 }),
                .zero_window => {
                    const block = try connection.hpack_encoder.encodeBlockRetained(std.testing.allocator, &.{
                        .{ .name = ":status", .value = "200" },
                        .{ .name = "content-length", .value = "1" },
                    });
                    try sendFrame(&connection, .headers, 0x4, pushed, block);
                    try sendFrame(&connection, .window_update, 0, pushed, &.{ 0, 0, 0, 0 });
                },
                .late_data => {
                    try connection.writePushedResponse(pushed, .{ .body = "push" });
                    try sendFrame(&connection, .data, 0x1, pushed, "late");
                },
            }
            if (self.mode == .zero_window or self.mode == .late_data) {
                try connection.writeResponse(request.stream_id, .{ .body = "parent" });
            } else {
                var goaway = try connection.readGoAwayWithTimeout(.fromSeconds(3));
                defer goaway.deinit(std.testing.allocator);
                try std.testing.expectEqual(if (self.mode == .hpack) http2.ErrorCode.compression_error else http2.ErrorCode.protocol_error, goaway.goaway.error_code);
            }
        }
    };
    var worker = Worker{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(std.testing.allocator, io, server.address(), .{ .enable_push = true });
    defer client.close();
    const options = runtime.RequestOptions{ .path = "/", .authority = "localhost" };
    if (mode == .zero_window or mode == .late_data) {
        var parent = try client.requestWithTimeout(options, .fromSeconds(3));
        defer parent.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("parent", parent.body);
        var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
        defer promise.deinit(std.testing.allocator);
        if (mode == .zero_window) {
            try std.testing.expectError(error.InvalidFrame, client.readPushedResponseWithTimeout(promise, .fromSeconds(3)));
        } else {
            var pushed = try client.readPushedResponseWithTimeout(promise, .fromSeconds(3));
            defer pushed.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("push", pushed.body);
        }
    } else {
        const expected = switch (mode) {
            .hpack => error.MessageTooLarge,
            .interleaving => error.UnexpectedFrame,
            else => error.InvalidFrame,
        };
        try std.testing.expectError(expected, client.requestWithTimeout(options, .fromSeconds(3)));
        try std.testing.expect(client.aggregate_timeout_unusable);
    }
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/2 push corrupt HPACK closes with COMPRESSION_ERROR" {
    try exercise(.hpack);
}
test "HTTP/2 push cannot interleave a parent CONTINUATION sequence" {
    try exercise(.interleaving);
}
test "HTTP/2 push DATA on a reserved stream closes the connection" {
    try exercise(.reserved_data);
}
test "HTTP/2 push WINDOW_UPDATE on a reserved stream closes the connection" {
    try exercise(.reserved_window);
}
test "HTTP/2 push zero WINDOW_UPDATE resets only the pushed stream" {
    try exercise(.zero_window);
}
test "HTTP/2 push late DATA preserves an already completed response" {
    try exercise(.late_data);
}
