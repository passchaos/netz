//! Resume already-started deliveries before applying a lazy activation threshold.
const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");
const forwarding = @import("outbound_forward.zig");

const BrokerRunner = struct {
    broker: *broker_mod.Broker,
    shutdown: std.Io.Event = .unset,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{ .source = self.broker.server.?.pendingSource(), .accept_concurrency = 4 }}, .{ .shutdown = &self.shutdown }) catch {};
    }
};

const LazyRunner = struct {
    bridge: *outbound.LocalBridge,
    err: ?anyerror = null,
    reload_pending: std.atomic.Value(bool) = .init(false),
    connected: std.atomic.Value(bool) = .init(true),

    fn run(self: *@This()) void {
        self.bridge.runLazyUntilReload(.{ .timeout = .fromMilliseconds(50), .cancellation_check_interval = .fromMilliseconds(10) }, 2, .fromMilliseconds(20), &self.reload_pending, &self.connected) catch |err| {
            self.err = err;
        };
    }
};

fn journalSequence(broker: *broker_mod.Broker) u64 {
    broker.persistence_mutex.lockUncancelable(broker.io);
    defer broker.persistence_mutex.unlock(broker.io);
    return broker.commit_log.?.next_sequence;
}

fn waitForCommit(broker: *broker_mod.Broker, previous: u64) !void {
    const deadline: std.Io.Clock.Timestamp = .fromNow(broker.io, .{ .raw = .fromSeconds(2), .clock = .awake });
    while (journalSequence(broker) == previous) {
        if (deadline.durationFromNow(broker.io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(broker.io, .fromMilliseconds(1), .awake);
    }
}

test "local lazy recovery finishes journal retries below the activation threshold" {
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
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "lazy-recovery-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    const Failure = enum { qos0_completion, pubcomp, coordinator_clear };
    for ([_]Failure{ .qos0_completion, .pubcomp, .coordinator_clear }) |failure| {
        for ([_]bool{ false, true }) |disconnect_target| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            var local = try broker_mod.Broker.init(failing.allocator(), io, .{ .queue_qos0_messages = true });
            defer local.deinit();
            try local.createCommitLog(tmp.dir, "broker.log", .{});
            var shutdown: std.Io.Event = .unset;
            const qos: mqtt.QoS = if (failure == .qos0_completion) .at_most_once else .exactly_once;
            var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x97} ** 16 }, .{ .address = remote.address() }, .{
                .source_connect = .{ .protocol = .v5, .client_id = "lazy-recovery-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
                .target_connect = .{ .protocol = .v5, .client_id = "lazy-recovery-target", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
                .rules = &.{.{ .filter = "#", .qos = qos, .local_prefix = "local/", .remote_prefix = "remote/" }},
                .coordinator = if (qos == .exactly_once) .{ .bridge_id = [_]u8{0x97} ** 16, .dir = tmp.dir, .sub_path = "bridge.log", .mode = .create } else null,
            }, &shutdown);
            defer bridge.deinit();
            _ = try bridge.connect();
            try local.publishLocal(.{ .dup = false, .qos = qos, .retain = false, .topic = "local/recovery", .packet_id = null, .properties = &.{}, .payload = "once" });
            const poll: mqtt.reconnect.PollOptions = .{ .timeout = .fromSeconds(2) };
            if (qos == .at_most_once) {
                var sent = (try bridge.source.pollWithOptions(poll)).?;
                defer sent.deinit(allocator);
                try forwarding.Operations(outbound.LocalBridge).forward(&bridge, &sent.publish.publish, poll);
                failing.fail_index = failing.alloc_index;
                try std.testing.expectError(error.OutOfMemory, bridge.source.completeQoS0());
                failing.fail_index = std.math.maxInt(usize);
            } else {
                try outbound.testing.stageNextDurableQoS2(&bridge, poll);
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.stageTargetPubRec(&bridge, poll);
                try outbound.testing.flushDurableTarget(&bridge);
                try outbound.testing.completeDurableTarget(&bridge, poll);
                if (failure == .pubcomp) {
                    try outbound.testing.stageDurableSourcePubRel(&bridge, poll);
                    failing.fail_index = failing.alloc_index;
                    try std.testing.expectError(error.OutOfMemory, bridge.source.writeStagedIncomingQoS2Completion(bridge.source.selected.?.pubrel, .{}));
                    failing.fail_index = std.math.maxInt(usize);
                } else {
                    var journal_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
                    bridge.coordinator.?.allocator = journal_alloc.allocator();
                    defer bridge.coordinator.?.allocator = allocator;
                    try std.testing.expectError(error.OutOfMemory, outbound.testing.stageDurableSourcePubRel(&bridge, poll));
                    bridge.coordinator.?.allocator = allocator;
                }
            }
            var delivered = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
            defer delivered.deinit(allocator);
            try std.testing.expect(delivered == .publish);
            try std.testing.expectEqualStrings("once", delivered.publish.publish.payload);
            if (disconnect_target) bridge.target.disconnectTransport();
            const previous = journalSequence(&local);
            var runner = LazyRunner{ .bridge = &bridge };
            const thread = try std.Thread.spawn(.{}, LazyRunner.run, .{&runner});
            var joined = false;
            defer if (!joined) {
                shutdown.set(io);
                thread.join();
            };
            try waitForCommit(&local, previous);
            if (!disconnect_target) {
                const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
                while (runner.connected.load(.acquire)) {
                    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
                    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
                }
            }
            shutdown.set(io);
            thread.join();
            joined = true;
            try std.testing.expect(runner.err == null);
            try std.testing.expect(!bridge.hasPendingDurableQoS2());
            var restored = try broker_mod.Broker.init(allocator, io, .{});
            defer restored.deinit();
            try restored.restoreCommitLog(tmp.dir, "broker.log", .{});
            try std.testing.expectEqual(@as(usize, 0), restored.stats().session_queued_messages);
            try std.testing.expectEqual(@as(usize, 0), restored.stats().session_inflight_messages);
            try subscriber.writePingReq();
            var barrier = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
            defer barrier.deinit(allocator);
            try std.testing.expect(barrier == .pingresp);
        }
    }
}

test "local lazy recovery resumes an in-flight QoS1 delivery after source reopen" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "broker.log", .{});
    var remote = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer remote.deinit();
    var remote_runner = BrokerRunner{ .broker = &remote };
    const remote_thread = try std.Thread.spawn(.{}, BrokerRunner.run, .{&remote_runner});
    defer {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    }
    var subscriber = try runtime.Client.connect(allocator, io, remote.address(), .{ .protocol = .v5, .client_id = "lazy-inflight-observer" });
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "remote/#" }}, .{});
    defer suback.deinit(allocator);
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = &local, .id = [_]u8{0x98} ** 16 }, .{ .address = remote.address() }, .{
        .source_connect = .{ .protocol = .v5, .client_id = "lazy-inflight-source", .clean_start = false, .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} },
        .target_connect = .{ .protocol = .v5, .client_id = "lazy-inflight-target" },
        .rules = &.{.{ .filter = "#", .qos = .at_least_once, .local_prefix = "local/", .remote_prefix = "remote/" }},
    }, &shutdown);
    defer bridge.deinit();
    try local.publishLocal(.{ .dup = false, .qos = .at_least_once, .retain = false, .topic = "local/recovery", .packet_id = null, .properties = &.{}, .payload = "retry" });
    var selected = (try bridge.source.pollWithOptions(.{ .timeout = .fromMilliseconds(50) })).?;
    defer selected.deinit(allocator);
    bridge.source.disconnectTransport();
    try std.testing.expectEqual(@as(usize, 1), local.stats().session_inflight_messages);
    var runner = LazyRunner{ .bridge = &bridge };
    const thread = try std.Thread.spawn(.{}, LazyRunner.run, .{&runner});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        thread.join();
    };
    var delivered = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer delivered.deinit(allocator);
    try std.testing.expect(delivered == .publish);
    try std.testing.expectEqualStrings("remote/recovery", delivered.publish.publish.topic);
    try std.testing.expectEqualStrings("retry", delivered.publish.publish.payload);
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake });
    while (local.stats().session_inflight_messages != 0) {
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    shutdown.set(io);
    thread.join();
    joined = true;
    try std.testing.expect(runner.err == null);
    var restored = try broker_mod.Broker.init(allocator, io, .{});
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "broker.log", .{});
    try std.testing.expectEqual(@as(usize, 0), restored.stats().session_inflight_messages);
    try subscriber.writePingReq();
    var barrier = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(2));
    defer barrier.deinit(allocator);
    try std.testing.expect(barrier == .pingresp);
}
