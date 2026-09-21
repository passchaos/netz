const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect publish one attempt returns with durable inflight" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        release.set(io);
        if (!joined) thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "publish-one-attempt",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try client.connection().?.shutdown();

    const attempt = try client.publishOneAttempt(
        "one/attempt",
        "durable",
        .{ .qos = .at_least_once },
    );
    try std.testing.expect(attempt.transport_interrupted);
    try std.testing.expect(attempt.packet_id != null);
    try std.testing.expect(client.connection() == null);
    const stats = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);

    release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect publish one attempt does not queue past Receive Maximum" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        received: *std.Io.Event,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 1,
            });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("first", publish.publish.topic);
            self.received.set(self.server.io);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var received: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var shared = Shared{
        .server = &server,
        .received = &received,
        .release = &release,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        release.set(io);
        if (!joined) thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "one-attempt-window" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    const first = try client.publishOneAttempt(
        "first",
        "one",
        .{ .qos = .at_least_once },
    );
    try std.testing.expect(first.packet_id != null);
    try received.wait(io);
    try std.testing.expectError(
        error.InflightFull,
        client.publishOneAttempt(
            "second",
            "must-not-queue",
            .{ .qos = .at_least_once },
        ),
    );
    const stats = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 0), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);

    release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect immediate publish sends zero expiry on the wire" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("expires/now", publish.publish.topic);
            try std.testing.expectEqualStrings("visible", publish.publish.payload);
            try std.testing.expectEqual(
                @as(?u32, 0),
                mqtt.messageExpiryInterval(publish.publish.properties),
            );
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "one-attempt-expiry" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    const attempt = try client.publishOneAttempt(
        "expires/now",
        "visible",
        .{
            .qos = .at_least_once,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 0,
            } }},
        },
    );
    try std.testing.expectEqual(
        attempt.packet_id.?,
        try client.completeNextPublish(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect publish one attempt rolls back local rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 128 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        release.set(io);
        if (!joined) thread.join();
    }

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "one-attempt-local-reject" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try std.testing.expectError(
        error.OutgoingPacketTooLarge,
        client.publishOneAttempt(
            "too/large",
            "x" ** 256,
            .{ .qos = .at_least_once },
        ),
    );
    const stats = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 0), stats.queued_count);
    try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);
    try std.testing.expect(client.connection() != null);

    release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
