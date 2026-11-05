//! Recovery of local-source completion after the target already accepted it.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");
const forwarding = @import("outbound_forward.zig");

const BrokerRunner = struct {
    broker: *broker_mod.Broker,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{ .source = self.broker.server.?.pendingSource(), .accept_concurrency = 4 }}, .{ .shutdown = &self.shutdown }) catch |err| {
            self.err = err;
        };
    }
};

const RetryRunner = struct {
    bridge: *outbound.LocalBridge,
    done: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        _ = self.bridge.step(.{ .timeout = .fromMilliseconds(50) }) catch |err| {
            self.err = err;
            return self.done.set(self.bridge.source.io);
        };
        self.done.set(self.bridge.source.io);
    }
};

fn retryWithinBudget(bridge: *outbound.LocalBridge, shutdown: *std.Io.Event) !void {
    const io = bridge.source.io;
    var runner = RetryRunner{ .bridge = bridge };
    const thread = try std.Thread.spawn(.{}, RetryRunner.run, .{&runner});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    const Wake = union(enum) { done: std.Io.Cancelable!void, expired: std.Io.Cancelable!void };
    var buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &buffer);
    defer select.cancelDiscard();
    try select.concurrent(.done, std.Io.Event.wait, .{ &runner.done, io });
    try select.concurrent(.expired, std.Io.sleep, .{ io, std.Io.Duration.fromSeconds(2), std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.Timeout;
        },
    }
    thread.join();
    joined = true;
    if (runner.err) |err| return err;
}

fn expectDelivery(subscriber: *runtime.Connection, payload: []const u8) !void {
    const allocator = std.testing.allocator;
    var delivered = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer delivered.deinit(allocator);
    try std.testing.expect(delivered == .publish);
    try std.testing.expectEqualStrings("remote/completion", delivered.publish.publish.topic);
    try std.testing.expectEqualStrings(payload, delivered.publish.publish.payload);
    // Read the next packet directly: ping() would buffer an extra PUBLISH.
    try subscriber.writePingReq();
    var barrier = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer barrier.deinit(allocator);
    try std.testing.expect(barrier == .pingresp);
}

test "local outbound QoS2 completion retries journal failures without target redelivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var remote_runner = BrokerRunner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, BrokerRunner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "completion-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    const poll: mqtt.reconnect.PollOptions = .{ .timeout = .fromSeconds(2) };
    for ([_]bool{ false, true }) |broker_failure| {
        var tmp = test_tmp.tmpDir(.{});
        defer tmp.cleanup();
        var broker_alloc = std.testing.FailingAllocator.init(allocator, .{});
        var local = try broker_mod.Broker.init(broker_alloc.allocator(), io, .{});
        defer local.deinit();
        try local.createCommitLog(tmp.dir, "broker.log", .{});
        var shutdown: std.Io.Event = .unset;
        var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x94} ** 16 }, .{ .address = remote.address() }, .{
            .source_connect = .{ .protocol = .v5, .client_id = "completion-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
            .target_connect = .{ .protocol = .v5, .client_id = "completion-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
            .rules = &.{.{ .filter = "#", .qos = .exactly_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
            .coordinator = .{ .bridge_id = [_]u8{0x94} ** 16, .dir = tmp.dir, .sub_path = "bridge.log", .mode = .create },
        }, &shutdown);
        defer bridge.deinit();
        _ = try bridge.connect();
        try local.publishLocal(.{ .dup = false, .qos = .exactly_once, .retain = false, .topic = "local/completion", .packet_id = null, .properties = &.{}, .payload = "once" });
        try outbound.testing.stageNextDurableQoS2(&bridge, poll);
        try outbound.testing.flushDurableTarget(&bridge);
        try outbound.testing.stageTargetPubRec(&bridge, poll);
        try outbound.testing.flushDurableTarget(&bridge);
        try outbound.testing.completeDurableTarget(&bridge, poll);
        var journal_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        if (broker_failure) {
            try outbound.testing.stageDurableSourcePubRel(&bridge, poll);
            broker_alloc.fail_index = broker_alloc.alloc_index;
            const selected = bridge.source.selected orelse return error.TestUnexpectedResult;
            try std.testing.expect(selected == .pubrel);
            try std.testing.expectError(error.OutOfMemory, bridge.source.writeStagedIncomingQoS2Completion(selected.pubrel, .{}));
            broker_alloc.fail_index = std.math.maxInt(usize);
        } else {
            bridge.coordinator.?.allocator = journal_alloc.allocator();
            defer bridge.coordinator.?.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, outbound.testing.stageDurableSourcePubRel(&bridge, poll));
            bridge.coordinator.?.allocator = allocator;
            try std.testing.expect(journal_alloc.has_induced_failure);
        }
        try retryWithinBudget(&bridge, &shutdown);
        try std.testing.expect(!bridge.hasPendingDurableQoS2());
        try std.testing.expectEqual(@as(usize, 0), local.stats().session_inflight_messages);
        try expectDelivery(&subscriber, "once");
    }
}

test "local outbound QoS0 completion retries journal failure without blocking or redelivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var remote_runner = BrokerRunner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, BrokerRunner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "zero-completion-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    for ([_]bool{ false, true }) |reconnect_source| {
        var tmp = test_tmp.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var local = try broker_mod.Broker.init(failing.allocator(), io, .{ .queue_qos0_messages = true });
        defer local.deinit();
        try local.createCommitLog(tmp.dir, "zero-broker.log", .{});
        var shutdown: std.Io.Event = .unset;
        var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x96} ** 16 }, .{ .address = remote.address() }, .{
            .source_connect = .{ .protocol = .v5, .client_id = "zero-completion-source", .clean_start = false },
            .target_connect = .{ .protocol = .v5, .client_id = "zero-completion-target" },
            .rules = &.{.{ .filter = "#", .local_prefix = "local/", .remote_prefix = "remote/" }},
        }, &shutdown);
        defer bridge.deinit();
        _ = try bridge.connect();
        for ([_][]const u8{ "sent", "next" }) |payload| {
            try local.publishLocal(.{ .dup = false, .qos = .at_most_once, .retain = false, .topic = "local/completion", .packet_id = null, .properties = &.{}, .payload = payload });
        }
        var sent = (try bridge.source.pollWithOptions(.{ .timeout = .fromMilliseconds(50) })).?;
        defer sent.deinit(allocator);
        try forwarding.Operations(outbound.LocalBridge).forward(&bridge, &sent.publish.publish, .{ .timeout = .fromSeconds(2) });
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, bridge.source.completeQoS0());
        try std.testing.expect(failing.has_induced_failure);
        failing.fail_index = std.math.maxInt(usize);
        if (reconnect_source) bridge.source.disconnectTransport();
        try retryWithinBudget(&bridge, &shutdown);
        {
            var restored = try broker_mod.Broker.init(allocator, io, .{ .queue_qos0_messages = true });
            defer restored.deinit();
            try restored.restoreCommitLog(tmp.dir, "zero-broker.log", .{});
            try std.testing.expectEqual(@as(usize, 1), restored.stats().session_queued_messages);
        }
        try expectDelivery(&subscriber, "sent");
        // The alternating target and source turns must deliver the next item.
        try retryWithinBudget(&bridge, &shutdown);
        try retryWithinBudget(&bridge, &shutdown);
        try std.testing.expectEqual(@as(usize, 0), try bridge.source.pendingCount());
        try expectDelivery(&subscriber, "next");
    }
}
