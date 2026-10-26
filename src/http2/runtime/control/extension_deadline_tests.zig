//! Extension metadata and receive-credit writes use the same absolute budget.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const Operation = enum {
    priority,
    origin,
    alternative_service,
    window_update,
    release_credit,
};

fn exercise(
    connection: *runtime.Connection,
    operation: Operation,
    timeout: std.Io.Duration,
) !void {
    switch (operation) {
        .priority => try connection.sendPriorityUpdateRawWithTimeout(
            1,
            "u=2, i, extension=?1",
            timeout,
        ),
        .origin => try connection.sendOriginsWithTimeout(
            &.{"https://example.com"},
            timeout,
        ),
        .alternative_service => try connection.sendAlternativeServiceWithTimeout(
            0,
            "https://example.com",
            "h3=\":443\"; ma=3600",
            timeout,
        ),
        .window_update => try connection.sendWindowUpdateWithTimeout(
            0,
            17,
            timeout,
        ),
        .release_credit => try connection.releaseReceivedCapacityWithTimeout(
            1,
            19,
            timeout,
        ),
    }
}

test "HTTP/2 extension output deadlines bound every remaining control write" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    inline for (std.meta.tags(Operation)) |operation| {
        const role: runtime.Role = if (operation == .priority)
            .client
        else
            .server;
        var fixture = try BlockedOutput.init(io, role);
        defer fixture.deinit();
        if (operation == .priority) {
            runtime.testing.enablePeerExtensiblePriorities(
                &fixture.connection,
            );
        }
        if (operation == .release_credit) {
            try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        }
        const connection_before =
            runtime.testing.recvConnectionWindowValue(&fixture.connection);
        const stream_before = if (operation == .release_credit)
            (try runtime.testing.recvStreamWindow(
                &fixture.connection,
                1,
            )).value
        else
            0;
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(io);
        try std.testing.expectError(
            error.Timeout,
            exercise(
                &fixture.connection,
                operation,
                .fromMilliseconds(30),
            ),
        );
        try std.testing.expect(
            started.untilNow(io, .awake).nanoseconds <
                400 * std.time.ns_per_ms,
        );
        try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(
            connection_before,
            runtime.testing.recvConnectionWindowValue(&fixture.connection),
        );
        if (operation == .release_credit) {
            try std.testing.expectEqual(
                stream_before,
                (try runtime.testing.recvStreamWindow(
                    &fixture.connection,
                    1,
                )).value,
            );
        }
        if (operation == .priority) {
            try std.testing.expect(
                !runtime.testing.hasPeerPriority(&fixture.connection, 1),
            );
        }
    }
}

test "HTTP/2 extension deadlines validate before priority and credit mutation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const wrong_clock = std.Io.Clock.Timestamp{
        .clock = .real,
        .raw = std.Io.Clock.real.now(io).addDuration(.fromSeconds(1)),
    };

    {
        var fixture = try BlockedOutput.init(io, .client);
        defer fixture.deinit();
        runtime.testing.enablePeerExtensiblePriorities(&fixture.connection);
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.sendPriorityUpdateWithDeadline(
                1,
                .{ .urgency = 2, .incremental = true },
                wrong_clock,
            ),
        );
        try std.testing.expect(
            !runtime.testing.hasPeerPriority(&fixture.connection, 1),
        );
        try fixture.connection.sendPriorityUpdateWithTimeout(
            1,
            .{ .urgency = 2, .incremental = true },
            .fromSeconds(1),
        );
        try std.testing.expect(
            runtime.testing.hasPeerPriority(&fixture.connection, 1),
        );
    }

    {
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        try runtime.testing.addActivePeerStream(&fixture.connection, 1);
        const connection_before =
            runtime.testing.recvConnectionWindowValue(&fixture.connection);
        const stream_before = (try runtime.testing.recvStreamWindow(
            &fixture.connection,
            1,
        )).value;
        try std.testing.expectError(
            error.Timeout,
            fixture.connection.releaseReceivedCapacityWithDeadline(
                1,
                23,
                wrong_clock,
            ),
        );
        try std.testing.expectEqual(
            connection_before,
            runtime.testing.recvConnectionWindowValue(&fixture.connection),
        );
        try std.testing.expectEqual(
            stream_before,
            (try runtime.testing.recvStreamWindow(
                &fixture.connection,
                1,
            )).value,
        );
        try fixture.connection.releaseReceivedCapacityWithTimeout(
            1,
            23,
            .fromSeconds(1),
        );
        try std.testing.expectEqual(
            connection_before + 23,
            runtime.testing.recvConnectionWindowValue(&fixture.connection),
        );
        try std.testing.expectEqual(
            stream_before + 23,
            (try runtime.testing.recvStreamWindow(
                &fixture.connection,
                1,
            )).value,
        );
    }
}

test "HTTP/2 extension deadline APIs deliver ORIGIN and ALTSVC metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Worker = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .fromSeconds(2),
            );
            defer connection.close();
            const deadline = std.Io.Clock.Timestamp.fromNow(
                connection.io,
                .{ .clock = .awake, .raw = .fromSeconds(2) },
            );
            try connection.sendOriginsWithDeadline(
                &.{
                    "https://example.com",
                    "https://cdn.example.com",
                },
                deadline,
            );
            try connection.sendAlternativeServiceWithDeadline(
                0,
                "https://example.com",
                "h3=\":443\"; ma=3600",
                deadline,
            );
            _ = try connection.readPingWithDeadline(deadline);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_peer_origins = 4,
            .max_alternative_services = 4,
        },
    );
    defer client.close();
    _ = try client.pingWithTimeout(
        [_]u8{0xa7} ** 8,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(@as(usize, 2), client.peerOrigins().len);
    try std.testing.expectEqualStrings(
        "https://example.com",
        client.peerOrigins()[0],
    );
    try std.testing.expectEqualStrings(
        "https://cdn.example.com",
        client.peerOrigins()[1],
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.alternativeServices().len,
    );
    try std.testing.expectEqualStrings(
        "h3=\":443\"; ma=3600",
        client.alternativeServices()[0].field_value,
    );
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
