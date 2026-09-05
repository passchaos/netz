const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../runtime.zig");

const test_limits: runtime.Limits = .{
    .http3 = .{
        .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        },
        .max_concurrent_request_streams = 1,
    },
};

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
}

const RequestAction = enum { drop, reject };

const LifecycleServerTask = struct {
    server: *runtime.Server,
    io: std.Io,
    actions: []const RequestAction,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        for (self.actions) |action| {
            var pending = try self.server.receiveSessionRequestWithDeadline(
                futureDeadline(self.io),
            );
            switch (action) {
                .drop => pending.deinit(),
                .reject => {
                    var rejected = try pending.notFound();
                    rejected.deinit(
                        self.server.h3.quic_server.endpoint.allocator,
                    );
                },
            }
        }
    }
};

fn sendConnect(
    client: *http3.runtime.Client,
    path: []const u8,
) !u62 {
    return client.startRequest(.{
        .method = "CONNECT",
        .path = path,
        .scheme = "https",
        .authority = "localhost",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            http3.capsule.protocol_header,
        },
    }, null);
}

test "WebTransport development pending deinit retires request capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var task = LifecycleServerTask{
        .server = &server,
        .io = io,
        .actions = &.{ .drop, .drop },
    };
    const thread = try std.Thread.spawn(.{}, LifecycleServerTask.run, .{&task});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        test_limits.http3,
    );
    defer client.deinit();
    const first = try sendConnect(&client, "/drop-one");
    try std.testing.expectError(
        error.RequestRejected,
        client.receiveResponseEventWithDeadline(first, futureDeadline(io)),
    );
    const second = try sendConnect(&client, "/drop-two");
    try std.testing.expectError(
        error.RequestRejected,
        client.receiveResponseEventWithDeadline(second, futureDeadline(io)),
    );

    thread.join();
    joined = true;
    if (task.err) |err| return err;
}

test "WebTransport development rejection finishes streaming response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    var task = LifecycleServerTask{
        .server = &server,
        .io = io,
        .actions = &.{ .reject, .reject },
    };
    const thread = try std.Thread.spawn(.{}, LifecycleServerTask.run, .{&task});
    var joined = false;
    defer if (!joined) thread.join();

    for (0..2) |index| {
        var attempt = try runtime.ClientSession.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = if (index == 0) "/reject-one" else "/reject-two",
                .limits = test_limits,
            },
            futureDeadline(io),
        );
        defer attempt.deinit();
        try std.testing.expectEqual(@as(u16, 404), attempt.status());
    }

    thread.join();
    joined = true;
    if (task.err) |err| return err;
}

test "WebTransport development accepted deinit cancels the control stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.receiveSessionRequestWithDeadline(
                futureDeadline(self.io),
            );
            var accepted = try first.accept();
            accepted.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );

            var second = try self.server.receiveSessionRequestWithDeadline(
                futureDeadline(self.io),
            );
            var rejected = try second.notFound();
            rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var first = try runtime.ClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/accept-then-drop",
            .limits = test_limits,
        },
        futureDeadline(io),
    );
    var first_owned = true;
    defer if (first_owned) first.deinit();
    try std.testing.expectError(
        error.RequestCancelled,
        first.receiveSessionEventWithDeadline(futureDeadline(io)),
    );
    first.deinit();
    first_owned = false;

    var second = try runtime.ClientSession.connectAttemptWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/after-accepted-drop",
            .limits = test_limits,
        },
        futureDeadline(io),
    );
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 404), second.status());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport development connect ignores informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http3.runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits.http3,
    );
    defer server.deinit();
    const Shared = struct {
        server: *http3.runtime.Server,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var event = try self.server.receiveRequestHeadWithDeadline(
                futureDeadline(self.io),
            );
            defer event.deinit(self.server.quic_server.endpoint.allocator);
            try std.testing.expect(event == .message);
            try std.testing.expect(event.message.value == .head);
            try self.server.sendResponseWithInformational(
                event.message.from,
                event.message.stream_id,
                &.{.{ .status = 103, .headers = &.{.{
                    .name = "x-informational",
                    .value = "ignored",
                }} }},
                .{
                    .status = 404,
                    .headers = &.{.{
                        .name = "x-final",
                        .value = "selected",
                    }},
                    .body = "after hint",
                    .trailers = &.{.{
                        .name = "x-trailer",
                        .value = "complete",
                    }},
                    .request_method = "CONNECT",
                    .extended_connect = true,
                },
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.ClientSession.connectAttemptWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/informational",
            .limits = blk: {
                var limits = test_limits;
                limits.max_rejection_body_bytes = 10;
                break :blk limits;
            },
        },
        futureDeadline(io),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 404), attempt.status());
    try std.testing.expectEqualStrings(
        "selected",
        attempt.responseHeader("x-final").?,
    );
    try std.testing.expectEqualStrings(
        "10",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("after hint", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "complete",
        attempt.trailers()[0].value,
    );
    try std.testing.expect(attempt.responseHeader("x-informational") == null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
