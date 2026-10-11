const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");
const outbound = @import("outbound.zig");

fn options(dir: std.Io.Dir, mode: outbound.CoordinatorMode) outbound.MultiOptions {
    return .{
        .source_connect = .{ .protocol = .v5, .client_id = "restore-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .protocol = .v5, .client_id = "restore-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .rules = &.{.{ .filter = "#", .qos = .exactly_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
        .coordinator = .{ .bridge_id = [_]u8{0x52} ** 16, .dir = dir, .sub_path = "bridge.log", .mode = mode },
    };
}

const Runner = struct {
    broker: *broker_mod.Broker,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = 4,
        }}, .{ .shutdown = &self.shutdown }) catch |err| {
            self.err = err;
        };
    }
};

test "local outbound bridge forwards all QoS without a source listener" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "broker.log", .{});
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var runner = Runner{ .broker = &remote };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    defer {
        runner.shutdown.set(io);
        thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "direct-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#", .qos = .at_most_once }}, .{});
    defer suback.deinit(allocator);
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x51} ** 16 }, .{ .address = remote.address() }, .{
        .source_connect = .{ .protocol = .v5, .client_id = "direct-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .protocol = .v5, .client_id = "direct-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .rules = &.{.{ .filter = "#", .qos = .exactly_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
        .coordinator = .{ .bridge_id = [_]u8{0x51} ** 16, .dir = tmp.dir, .sub_path = "bridge.log", .mode = .create },
    }, &shutdown);
    defer bridge.deinit();
    _ = try bridge.connect();
    for ([_]mqtt.QoS{ .at_most_once, .at_least_once, .exactly_once }) |qos| {
        try local.publishLocal(.{ .dup = false, .qos = qos, .retain = false, .topic = "local/value", .packet_id = null, .properties = &.{}, .payload = "direct" });
        // step alternates source/target and consumes a complete coordinated
        // transaction once selected. A bounded second step reaches the source.
        _ = try bridge.step(.{ .timeout = .fromSeconds(2) });
        _ = try bridge.step(.{ .timeout = .fromSeconds(2) });
        var delivered = try subscriber.readPublish();
        defer delivered.deinit(allocator);
        try std.testing.expectEqualStrings("remote/value", delivered.publish.topic);
        try std.testing.expectEqualStrings("direct", delivered.publish.payload);
    }
    try subscriber.ping();
    try std.testing.expect(!bridge.hasPendingDurableQoS2());
    try std.testing.expectEqual(@as(usize, 0), local.stats().session_inflight_messages);
}

test "local outbound bridge restores all QoS2 ownership boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var runner = Runner{ .broker = &remote };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&runner});
    defer {
        runner.shutdown.set(io);
        thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "restore-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    const poll: mqtt.reconnect.PollOptions = .{ .timeout = .fromSeconds(2) };
    for (0..5) |phase| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var shutdown: std.Io.Event = .unset;
        {
            var local = try broker_mod.Broker.init(allocator, io, .{});
            defer local.deinit();
            try local.createCommitLog(tmp.dir, "broker.log", .{});
            var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x52} ** 16 }, .{ .address = remote.address() }, options(tmp.dir, .create), &shutdown);
            defer bridge.deinit();
            _ = try bridge.connect();
            try local.publishLocal(.{ .dup = false, .qos = .exactly_once, .retain = false, .topic = "local/restart", .packet_id = null, .properties = &.{}, .payload = "once" });
            try outbound.testing.stageNextDurableQoS2(&bridge, poll);
            if (phase >= 1) {
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.stageTargetPubRec(&bridge, poll);
            }
            if (phase >= 2) {
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.completeDurableTarget(&bridge, poll);
            }
            if (phase == 3) {
                var release = (try bridge.source.pollWithOptions(poll)).?;
                defer release.deinit(allocator);
                try std.testing.expect(release == .pubrel);
            }
            if (phase == 4) try outbound.testing.stageDurableSourcePubRel(&bridge, poll);
            if (phase == 4) {
                // The coordinator is already empty while the broker still
                // holds PUBREL. Reopening must finish PUBCOMP, not republish.
                try std.testing.expect(!bridge.hasPendingDurableQoS2());
            }
        }
        {
            var local = try broker_mod.Broker.init(allocator, io, .{});
            defer local.deinit();
            try local.restoreCommitLog(tmp.dir, "broker.log", .{});
            var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x52} ** 16 }, .{ .address = remote.address() }, options(tmp.dir, .restore), &shutdown);
            defer bridge.deinit();
            _ = try bridge.connect();
            _ = try bridge.step(poll);
            _ = try bridge.step(poll);
            try std.testing.expect(!bridge.hasPendingDurableQoS2());
            try std.testing.expectEqual(@as(usize, 0), local.stats().session_inflight_messages);
        }
        var delivered = try subscriber.readPublish();
        defer delivered.deinit(allocator);
        try std.testing.expectEqualStrings("remote/restart", delivered.publish.topic);
        try std.testing.expectEqualStrings("once", delivered.publish.payload);
        try subscriber.ping();
    }
}

test "local outbound bridge initialization allocation failures release registrations" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initializeWithAllocator, .{threaded.io()});
}

fn initializeWithAllocator(allocator: std.mem.Allocator, io: std.Io) !void {
    var local = try broker_mod.Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    var bridge = outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x53} ** 16 }, .{ .address = .{ .ip4 = .loopback(1) } }, .{
        .source_connect = .{ .protocol = .v5, .client_id = "allocation-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .client_id = "allocation-target" },
        .rules = &.{.{ .filter = "allocation/#" }},
    }, &shutdown) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
        return err;
    };
    bridge.deinit();
    try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
}

test "local outbound bridge one-shot failure closes its local consumer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Connector = struct {
        fn refused(_: *anyopaque, _: std.mem.Allocator, _: std.Io, _: runtime.ConnectOptions) runtime.Error!runtime.ConnectAttempt {
            return error.ConnectionRefused;
        }
    };
    var context: u8 = 0;
    var local = try broker_mod.Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1 } });
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x54} ** 16 }, .{ .connector = .{ .context = &context, .connect_attempt = Connector.refused } }, .{
        .source_connect = .{ .client_id = "once-source" },
        .target_connect = .{ .client_id = "once-target" },
        .target_reconnect_policy = .{ .max_attempts = 1 },
        .rules = &.{.{ .filter = "once/#" }},
    }, &shutdown);
    defer bridge.deinit();
    try std.testing.expectEqual(@as(usize, 1), local.local_consumer_routes.count());
    try std.testing.expectError(error.ConnectionUnavailable, bridge.runOnce(.{ .timeout = .fromSeconds(1) }));
    try std.testing.expectEqual(@as(usize, 0), local.local_consumer_routes.count());
}

test "local outbound lazy bridge connects at threshold and retires when idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    var remote_runner = Runner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, Runner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }
    var subscriber = try runtime.Client.connect(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "lazy-observer" },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{
        .{ .topic_filter = "bridge/lazy/state", .qos = .at_least_once },
        .{ .topic_filter = "remote/#", .qos = .at_least_once },
    }, .{});
    defer suback.deinit(allocator);

    const CountingConnector = struct {
        address: std.Io.net.IpAddress,
        attempts: std.atomic.Value(usize) = .init(0),

        fn connectAttempt(
            context: *anyopaque,
            connect_allocator: std.mem.Allocator,
            connect_io: std.Io,
            connect_options: runtime.ConnectOptions,
        ) runtime.Error!runtime.ConnectAttempt {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.attempts.fetchAdd(1, .monotonic);
            return runtime.Client.connectAttempt(
                connect_allocator,
                connect_io,
                self.address,
                connect_options,
            );
        }
    };
    var connector = CountingConnector{ .address = remote.address() };
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(
        allocator,
        io,
        .{ .broker = &local, .id = [_]u8{0x55} ** 16 },
        .{ .connector = .{
            .context = &connector,
            .connect_attempt = CountingConnector.connectAttempt,
        } },
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "lazy-source",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "lazy-target",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = 60,
                } }},
            },
            .rules = &.{.{
                .filter = "#",
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            }},
            .notifications = .{
                .topic = "bridge/lazy/state",
                .publish_remote = true,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    const LazyRunner = struct {
        bridge: *outbound.LocalBridge,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.bridge.source.io);
            self.bridge.runLazy(
                .{
                    .timeout = .fromSeconds(2),
                    .cancellation_check_interval = .fromMilliseconds(10),
                },
                2,
                .fromMilliseconds(100),
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var lazy_runner = LazyRunner{ .bridge = &bridge };
    const lazy_thread = try std.Thread.spawn(.{}, LazyRunner.run, .{&lazy_runner});
    var lazy_joined = false;
    defer if (!lazy_joined) {
        shutdown.set(io);
        lazy_thread.join();
    };
    try lazy_runner.started.wait(io);
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    try std.testing.expectEqual(
        @as(usize, 0),
        connector.attempts.load(.monotonic),
    );

    try publishLazy(&local, "one");
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    try std.testing.expectEqual(
        @as(usize, 0),
        connector.attempts.load(.monotonic),
    );
    try publishLazy(&local, "two");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "1");
    try expectLazyPublish(&subscriber, "remote/value", "one");
    try expectLazyPublish(&subscriber, "remote/value", "two");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "0");
    try std.testing.expectEqual(
        @as(usize, 1),
        connector.attempts.load(.monotonic),
    );

    try publishLazy(&local, "three");
    try std.Io.sleep(io, .fromMilliseconds(150), .awake);
    try std.testing.expectEqual(
        @as(usize, 1),
        connector.attempts.load(.monotonic),
    );
    try publishLazy(&local, "four");
    try expectLazyPublish(&subscriber, "bridge/lazy/state", "1");
    try expectLazyPublish(&subscriber, "remote/value", "three");
    try expectLazyPublish(&subscriber, "remote/value", "four");

    shutdown.set(io);
    lazy_thread.join();
    lazy_joined = true;
    try std.testing.expect(lazy_runner.err == null);
}

fn publishLazy(broker: *broker_mod.Broker, payload: []const u8) !void {
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "local/value",
        .packet_id = null,
        .properties = &.{},
        .payload = payload,
    });
}

fn expectLazyPublish(
    subscriber: *runtime.Connection,
    expected_topic: []const u8,
    expected_payload: []const u8,
) !void {
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(subscriber.allocator);
    try std.testing.expectEqualStrings(expected_topic, delivered.publish.topic);
    try std.testing.expectEqualStrings(
        expected_payload,
        delivered.publish.payload,
    );
}
