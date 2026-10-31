const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const shared = @import("../channel/shared.zig");
const http2 = @import("../../http2/mod.zig");

const allocator = std.testing.allocator;

const config_json =
    \\{"methodConfig":[{"name":[{"service":"demo.Timeout","method":"Unary"}],
    \\ "retryPolicy":{"maxAttempts":3,"initialBackoff":"0.001s",
    \\ "maxBackoff":"0.001s","backoffMultiplier":1,
    \\ "perAttemptRecvTimeout":"0.2s","retryableStatusCodes":["ABORTED"]}}]}
;

test "gRPC Channel retries per-attempt receive timeout before status retry" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        1024,
    );
    defer server.deinit();
    var peer = io.async(Peer.timeoutAbortedOk, .{&server});
    defer _ = peer.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parseWithOptions(
        allocator,
        config_json,
        .{ .enable_per_attempt_recv_timeout = true },
    );
    defer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{},
        &config,
    );
    defer client.deinit();
    var response = try client.unaryWithServiceConfig(.{
        .path = "/demo.Timeout/Unary",
        .message = "request",
        .timeout = try grpc.Timeout.init(2, .second),
    }, &config);
    defer response.deinit();
    try peer.await(io);
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("ok", response.message.?.payload);
}

test "gRPC per-attempt receive timeout on final attempt returns CANCELLED" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        1024,
    );
    defer server.deinit();
    var peer = io.async(Peer.timeoutTwice, .{&server});
    defer _ = peer.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parseWithOptions(
        allocator,
        \\{"methodConfig":[{"name":[{}],"retryPolicy":{
        \\ "maxAttempts":2,"initialBackoff":"0.001s",
        \\ "maxBackoff":"0.001s","backoffMultiplier":1,
        \\ "perAttemptRecvTimeout":"0.2s"}}]}
    ,
        .{ .enable_per_attempt_recv_timeout = true },
    );
    defer config.deinit();
    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{},
    );
    defer client.deinit();
    var response = try client.unaryWithServiceConfig(.{
        .path = "/demo.Timeout/Unary",
        .message = "request",
        .timeout = try grpc.Timeout.init(2, .second),
    }, &config);
    defer response.deinit();
    try peer.await(io);
    try std.testing.expectEqual(grpc.Status.cancelled, response.status);
    try std.testing.expectEqualStrings(
        "retry perAttemptRecvTimeout exceeded",
        response.status_message,
    );
    try std.testing.expect(response.transport == null);
}

test "gRPC SharedChannel retries per-attempt receive timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        1024,
    );
    defer server.deinit();
    var peer = io.async(Peer.timeoutThenOk, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{
            .service_config_json = config_json,
            .enable_per_attempt_recv_timeout = true,
        },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var response = try sender.unary(.{
        .path = "/demo.Timeout/Unary",
        .message = "request",
        .timeout = try grpc.Timeout.init(2, .second),
    });
    defer response.deinit();
    try peer.await(io);
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("ok", response.message.?.payload);
}

test "gRPC overall deadline wins per-attempt receive timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        1024,
    );
    defer server.deinit();
    var peer = io.async(Peer.timeoutOnce, .{&server});
    defer _ = peer.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parseWithOptions(
        allocator,
        config_json,
        .{ .enable_per_attempt_recv_timeout = true },
    );
    defer config.deinit();
    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{},
    );
    defer client.deinit();
    try std.testing.expectError(
        error.Timeout,
        client.unaryWithServiceConfig(.{
            .path = "/demo.Timeout/Unary",
            .message = "request",
            .timeout = try grpc.Timeout.init(50, .millisecond),
        }, &config),
    );
    try peer.await(io);
}

const Peer = struct {
    fn timeoutAbortedOk(server: *grpc.runtime.Server) !void {
        var first_connection = try server.acceptWithTimeout(.fromSeconds(3));
        var first = try acceptAttempt(&first_connection, null);
        try expectCancel(&first);
        first.deinit();
        first_connection.deinit();
        var second_connection = try server.acceptWithTimeout(.fromSeconds(3));
        defer second_connection.deinit();
        var second = try acceptAttempt(&second_connection, "1");
        try second.finish(
            .aborted,
            null,
            &.{},
            &.{},
        );
        second.deinit();
        var third = try acceptAttempt(&second_connection, "2");
        defer third.deinit();
        try third.startResponse(.{});
        try std.testing.expect(
            try third.writeMessage("ok") == .complete,
        );
        try third.finishOk();
    }

    fn timeoutTwice(server: *grpc.runtime.Server) !void {
        var first_connection = try server.acceptWithTimeout(.fromSeconds(3));
        var first = try acceptAttempt(&first_connection, null);
        try expectCancel(&first);
        first.deinit();
        first_connection.deinit();
        var second_connection = try server.acceptWithTimeout(.fromSeconds(3));
        defer second_connection.deinit();
        var second = try acceptAttempt(&second_connection, "1");
        defer second.deinit();
        try expectCancel(&second);
    }

    fn timeoutThenOk(server: *grpc.runtime.Server) !void {
        var connection = try server.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var first = try acceptAttempt(&connection, null);
        try expectCancel(&first);
        first.deinit();
        var second = try acceptAttempt(&connection, "1");
        defer second.deinit();
        try second.startResponse(.{});
        try std.testing.expect(
            try second.writeMessage("ok") == .complete,
        );
        try second.finishOk();
    }

    fn timeoutOnce(server: *grpc.runtime.Server) !void {
        var connection = try server.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var stream = try acceptAttemptExpectingWireTimeout(
            &connection,
            null,
            .shorter_than_per_attempt,
        );
        defer stream.deinit();
        try expectCancel(&stream);
        try std.Io.sleep(connection.connection.io, .fromMilliseconds(100), .awake);
    }

    fn expectCancel(stream: *grpc.ServerDuplex) !void {
        const reset = try stream.waitForPeerResetWithTimeout(.fromSeconds(3));
        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
    }

    fn acceptAttempt(
        connection: *grpc.runtime.ServerConnection,
        previous: ?[]const u8,
    ) !grpc.ServerDuplex {
        return acceptAttemptExpectingWireTimeout(
            connection,
            previous,
            .longer_than_per_attempt,
        );
    }

    const WireTimeoutExpectation = enum {
        shorter_than_per_attempt,
        longer_than_per_attempt,
    };

    fn acceptAttemptExpectingWireTimeout(
        connection: *grpc.runtime.ServerConnection,
        previous: ?[]const u8,
        timeout_expectation: WireTimeoutExpectation,
    ) !grpc.ServerDuplex {
        var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        errdefer stream.deinit();
        var message_count: usize = 0;
        const Consumer = struct {
            count: *usize,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expectEqualStrings("request", message.payload);
                self.count.* += 1;
            }
        };
        var consumer = Consumer{ .count = &message_count };
        while (true) {
            var event = try stream.readRequestEventWithTimeout(
                .fromSeconds(3),
                &consumer,
                Consumer.consume,
            );
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => break,
                .reset => return error.RequestResetBeforeFinished,
            }
        }
        try std.testing.expectEqual(@as(usize, 1), message_count);
        const actual = grpc.call.headerValue(
            stream.requestHeaders(),
            "grpc-previous-rpc-attempts",
        );
        if (previous) |expected| {
            try std.testing.expectEqualStrings(expected, actual.?);
        } else try std.testing.expect(actual == null);
        const timeout = grpc.call.headerValue(
            stream.requestHeaders(),
            "grpc-timeout",
        ) orelse return error.MissingGrpcTimeout;
        const timeout_ns = (try grpc.Timeout.parse(timeout))
            .duration().nanoseconds;
        switch (timeout_expectation) {
            .shorter_than_per_attempt => try std.testing.expect(
                timeout_ns < 200 * std.time.ns_per_ms,
            ),
            .longer_than_per_attempt => try std.testing.expect(
                timeout_ns > 200 * std.time.ns_per_ms,
            ),
        }
        return stream;
    }
};
