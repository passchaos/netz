const std = @import("std");
const runtime = @import("../../runtime.zig");

const Mode = enum { reordered, large, ping };
const dictionary = "shared-dictionary-value-" ** 8;
const large_body = "large-push-body-" ** 8192;

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
            const first = try promise(&connection, request.stream_id, "/two");
            if (self.mode == .reordered) {
                const second = try promise(&connection, request.stream_id, "/four");
                try connection.writePushedResponse(second, .{
                    .headers = &.{.{ .name = "x-dictionary", .value = dictionary }},
                    .body = "four",
                });
            }
            if (self.mode == .ping) {
                var parent = try connection.startResponse(request.stream_id, .{
                    .headers = &.{.{ .name = "x-dictionary", .value = dictionary }},
                });
                defer parent.deinit();
                try std.testing.expectEqual([_]u8{0xa1} ** 8, try connection.pingWithTimeout([_]u8{0xa1} ** 8, .fromSeconds(3)));
                try connection.writePushedResponse(first, .{
                    .headers = &.{.{ .name = "x-dictionary", .value = dictionary }},
                    .body = "two",
                });
                try parent.finishData("parent");
                return;
            }
            try connection.writePushedResponse(first, .{
                .headers = &.{.{ .name = "x-dictionary", .value = dictionary }},
                .body = if (self.mode == .large) large_body else "two",
            });
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "x-dictionary", .value = dictionary }},
                .body = "parent",
            });
        }
    };
    var worker = Worker{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(std.testing.allocator, io, server.address(), .{
        .enable_push = true,
        .initial_window_size = 4096,
        .max_body_bytes = large_body.len,
        .max_buffered_push_bytes = large_body.len + 2048,
    });
    defer client.close();
    if (mode == .ping) {
        const pending = try runtime.testing.sendCompleteRequest(&client, .{ .path = "/", .authority = "localhost" });
        try std.testing.expectEqual([_]u8{0xa2} ** 8, try client.pingWithTimeout([_]u8{0xa2} ** 8, .fromSeconds(3)));
        var promise = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
        defer promise.deinit(std.testing.allocator);
        var pushed = try client.readPushedResponseWithTimeout(promise, .fromSeconds(3));
        defer pushed.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("two", pushed.body);
        try std.testing.expectEqualStrings(dictionary, runtime.testing.findHeader(pushed.headers, "x-dictionary").?);
        var parent = try client.readResponseWithTimeout(pending.stream_id, "GET", false, .fromSeconds(3));
        defer parent.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("parent", parent.body);
        try std.testing.expectEqualStrings(dictionary, runtime.testing.findHeader(parent.headers, "x-dictionary").?);
    } else {
        var parent = try client.requestWithTimeout(.{ .path = "/", .authority = "localhost" }, .fromSeconds(3));
        defer parent.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("parent", parent.body);
        try std.testing.expectEqualStrings(dictionary, runtime.testing.findHeader(parent.headers, "x-dictionary").?);
        var first = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
        defer first.deinit(std.testing.allocator);
        if (mode == .reordered) {
            var second = client.takePromisedRequest() orelse return error.TestUnexpectedResult;
            defer second.deinit(std.testing.allocator);
            var pushed = try client.readPushedResponseWithTimeout(second, .fromSeconds(3));
            defer pushed.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("four", pushed.body);
            try std.testing.expectEqualStrings(dictionary, runtime.testing.findHeader(pushed.headers, "x-dictionary").?);
        }
        const credit_before = client.recv_connection_window.value;
        var pushed = try client.readPushedResponseWithTimeout(first, .fromSeconds(3));
        defer pushed.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(if (mode == .large) large_body else "two", pushed.body);
        try std.testing.expectEqualStrings(dictionary, runtime.testing.findHeader(pushed.headers, "x-dictionary").?);
        try std.testing.expectEqual(credit_before, client.recv_connection_window.value);
    }
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/2 push responses retain HPACK fields and can be read out of promise order" {
    try exercise(.reordered);
}

test "HTTP/2 push before parent advances stream and connection flow control once" {
    try exercise(.large);
}

test "HTTP/2 push HPACK follows a normal header deferred by PING" {
    try exercise(.ping);
}
