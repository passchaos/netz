const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");

const Broker = broker_mod.Broker;

fn createBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
) !Broker {
    return Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
            },
        },
    );
}

fn createAutosaveBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    max_changes: usize,
) !Broker {
    return createAutosaveBrokerEnabled(
        allocator,
        io,
        dir,
        sub_path,
        max_changes,
        true,
    );
}

fn createAutosaveBrokerEnabled(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    max_changes: usize,
    enabled: bool,
) !Broker {
    return Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
            },
            .persistent_change_autosave = .{
                .dir = dir,
                .sub_path = sub_path,
                .max_changes = max_changes,
                .enabled = enabled,
            },
        },
    );
}

test "MQTT persistent change autosave switches runtime policy atomically" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var no_target = try createBroker(allocator, io);
    defer no_target.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        no_target.setPersistentChangeAutosaveThreshold(1),
    );

    var broker = try createAutosaveBrokerEnabled(
        allocator,
        io,
        tmp.dir,
        "dynamic.db",
        1,
        false,
    );
    defer broker.deinit();
    try std.testing.expectEqual(
        @as(?usize, null),
        broker.persistentChangeAutosaveThreshold(),
    );
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/dynamic/baseline",
        .packet_id = null,
        .properties = &.{},
        .payload = "baseline",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "dynamic.db", .{}),
    );

    // A periodic/manual snapshot acknowledges the configured target even while
    // mutation-count autosave is disabled. Enabling must not duplicate it.
    try broker.saveLiveSnapshot(tmp.dir, "dynamic.db");
    try tmp.dir.deleteFile(io, "dynamic.db");
    try broker.setPersistentChangeAutosaveThreshold(1);
    try std.testing.expectEqual(
        @as(?usize, 1),
        broker.persistentChangeAutosaveThreshold(),
    );
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "dynamic.db", .{}),
    );

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/dynamic/enabled",
        .packet_id = null,
        .properties = &.{},
        .payload = "enabled",
    });
    _ = try tmp.dir.statFile(io, "dynamic.db", .{});

    try broker.setPersistentChangeAutosaveThreshold(null);
    try tmp.dir.deleteFile(io, "dynamic.db");
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/dynamic/disabled",
        .packet_id = null,
        .properties = &.{},
        .payload = "disabled",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "dynamic.db", .{}),
    );
    try broker.setPersistentChangeAutosaveThreshold(1);
    _ = try tmp.dir.statFile(io, "dynamic.db", .{});
}

fn delayedWill(
    delay_seconds: u32,
    retain: bool,
) mqtt.LastWill {
    const Properties = struct {
        var values: [2]mqtt.Property = undefined;
    };
    Properties.values[0] = .{ .four_byte = .{
        .id = .will_delay_interval,
        .value = delay_seconds,
    } };
    Properties.values[1] = .{ .utf8 = .{
        .id = .content_type,
        .value = "text/plain",
    } };
    return .{
        .topic = "persist/will",
        .payload = "offline",
        .qos = .at_least_once,
        .retain = retain,
        .properties = &Properties.values,
    };
}

test "MQTT persistent change autosave validates options and owns path" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(
        error.InvalidProperty,
        createAutosaveBroker(allocator, io, tmp.dir, "", 1),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        createAutosaveBroker(allocator, io, tmp.dir, "zero.db", 0),
    );

    var path = [_]u8{ 'o', 'w', 'n', 'e', 'd', '.', 'd', 'b' };
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        &path,
        1,
    );
    defer broker.deinit();
    path[0] = 'x';
    try std.testing.expectEqualStrings(
        "owned.db",
        broker.options.persistent_change_autosave.?.sub_path,
    );
}

test "MQTT persistent change autosave waits for threshold" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "changes.db",
        2,
    );
    defer broker.deinit();

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/one",
        .packet_id = null,
        .properties = &.{},
        .payload = "one",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "changes.db", .{}),
    );

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/two",
        .packet_id = null,
        .properties = &.{},
        .payload = "two",
    });
    _ = try tmp.dir.statFile(io, "changes.db", .{});

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "changes.db");
    var matches_storage: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "autosave/two",
        std.Io.Clock.awake.now(io),
        &matches_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("two", matches[0].payload);
}

test "MQTT persistent change autosave ignores volatile and retained no-op publishes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "ignored.db",
        1,
    );
    defer broker.deinit();

    // With no durable subscribers, an ordinary PUBLISH changes only process
    // counters and transient routing state. Deleting a missing retained entry
    // is likewise a durable no-op. Neither reaches the autosave threshold.
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "volatile/only",
        .packet_id = null,
        .properties = &.{},
        .payload = "value",
    });
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "retained/missing",
        .packet_id = null,
        .properties = &.{},
        .payload = "",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "ignored.db", .{}),
    );
}

test "MQTT persistent change autosave retains threshold across SnapshotBusy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "busy.db",
        1,
    );
    defer broker.deinit();

    broker.slots[0].state.active = true;
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/busy",
        .packet_id = null,
        .properties = &.{},
        .payload = "pending",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "busy.db", .{}),
    );

    broker.slots[0].state.active = false;
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "retained/no-op",
        .packet_id = null,
        .properties = &.{},
        .payload = "",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "busy.db", .{}),
    );

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/retry",
        .packet_id = null,
        .properties = &.{},
        .payload = "saved",
    });
    _ = try tmp.dir.statFile(io, "busy.db", .{});
}

test "MQTT manual snapshot does not acknowledge another autosave target" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "autosave.db",
        2,
    );
    defer broker.deinit();

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/first",
        .packet_id = null,
        .properties = &.{},
        .payload = "first",
    });
    try broker.saveLiveSnapshot(tmp.dir, "manual.db");
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "autosave.db", .{}),
    );

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/second",
        .packet_id = null,
        .properties = &.{},
        .payload = "second",
    });
    _ = try tmp.dir.statFile(io, "autosave.db", .{});
}

test "MQTT snapshot to autosave target acknowledges captured generation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "autosave.db",
        2,
    );
    defer broker.deinit();

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/baseline",
        .packet_id = null,
        .properties = &.{},
        .payload = "baseline",
    });
    try broker.saveLiveSnapshot(tmp.dir, "autosave.db");
    const baseline = try tmp.dir.readFileAlloc(
        io,
        "autosave.db",
        allocator,
        .unlimited,
    );
    defer allocator.free(baseline);

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/one-after-baseline",
        .packet_id = null,
        .properties = &.{},
        .payload = "pending",
    });
    const still_baseline = try tmp.dir.readFileAlloc(
        io,
        "autosave.db",
        allocator,
        .unlimited,
    );
    defer allocator.free(still_baseline);
    try std.testing.expectEqualSlices(u8, baseline, still_baseline);
}

test "MQTT equivalent path through another directory does not suppress autosave" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "autosave.db",
        2,
    );
    defer broker.deinit();

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/first",
        .packet_id = null,
        .properties = &.{},
        .payload = "first",
    });
    var alias = try tmp.dir.openDir(io, ".", .{});
    defer alias.close(io);
    try broker.saveLiveSnapshot(alias, "autosave.db");
    try tmp.dir.deleteFile(io, "autosave.db");

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/second",
        .packet_id = null,
        .properties = &.{},
        .payload = "second",
    });
    // Conservative destination matching can cause a redundant checkpoint,
    // but must never treat a separately opened handle as the configured one.
    _ = try tmp.dir.statFile(io, "autosave.db", .{});
}

test "MQTT restore starts a fresh persistent change threshold" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "autosave.db",
        2,
    );
    defer broker.deinit();

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/pre-restore",
        .packet_id = null,
        .properties = &.{},
        .payload = "dirty",
    });
    try broker.saveLiveSnapshot(tmp.dir, "baseline.db");
    try broker.restoreSnapshot(tmp.dir, "baseline.db");

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/post-restore",
        .packet_id = null,
        .properties = &.{},
        .payload = "one",
    });
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile(io, "autosave.db", .{}),
    );
}

test "MQTT persistent change autosave failure is best effort and retryable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "missing/checkpoint.db",
        1,
    );
    defer broker.deinit();

    // The retained mutation succeeds even though the optional checkpoint
    // target cannot be created. The generation remains dirty for a later
    // successful retry, and the failure is available to operators.
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/failure",
        .packet_id = null,
        .properties = &.{},
        .payload = "committed",
    });
    try std.testing.expect(broker.persistentChangeAutosaveError() != null);
    try tmp.dir.createDir(io, "missing", .default_dir);

    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "retained/no-op",
        .packet_id = null,
        .properties = &.{},
        .payload = "",
    });
    // A no-op does not itself trigger autosave; retry is coupled to the next
    // persistent operation so harmless traffic cannot create I/O churn.
    try std.testing.expect(broker.persistentChangeAutosaveError() != null);
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "autosave/retry-after-error",
        .packet_id = null,
        .properties = &.{},
        .payload = "saved",
    });
    try std.testing.expectEqual(
        @as(?anyerror, null),
        broker.persistentChangeAutosaveError(),
    );
    _ = try tmp.dir.statFile(io, "missing/checkpoint.db", .{});
}

test "MQTT journal failure still services change autosave" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "fallback.db",
        1,
    );
    defer broker.deinit();

    // The initial empty snapshot fits, but any retained publication makes the
    // next journal record exceed this deliberately tiny record bound.
    try broker.createCommitLog(tmp.dir, "broker.log", .{
        .max_record_bytes = 128,
        .max_file_bytes = 4096,
    });
    try std.testing.expectError(
        error.CommitRecordTooLarge,
        broker.publishLocal(.{
            .dup = false,
            .qos = .at_most_once,
            .retain = true,
            .topic = "autosave/journal-failure",
            .packet_id = null,
            .properties = &.{},
            .payload = "this durable mutation must reach the independent autosave",
        }),
    );
    _ = try tmp.dir.statFile(io, "fallback.db", .{});

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "fallback.db");
    var storage: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "autosave/journal-failure",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings(
        "this durable mutation must reach the independent autosave",
        matches[0].payload,
    );
}

test "MQTT persistent change autosave counts durable Session enqueue" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "session.db",
        1,
    );
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    const opened = try broker.sessions.open(
        "autosave-session",
        false,
        std.math.maxInt(u32),
        now,
    );
    try broker.sessions.disconnect(opened.handle, null, now);

    try broker.enqueueSessionPublish(
        "autosave-session",
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "autosave/session",
            .packet_id = null,
            .properties = &.{},
            .payload = "queued",
        },
        .at_least_once,
        false,
        null,
    );
    _ = try tmp.dir.statFile(io, "session.db", .{});

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "session.db");
    const handle = restored.sessions.find(
        "autosave-session",
        std.Io.Clock.awake.now(io),
    ).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.sessions.stats(handle)).queued_count,
    );
}

test "MQTT persistent change autosave tracks durable subscription lifecycle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try createAutosaveBroker(
        allocator,
        io,
        tmp.dir,
        "subscription.db",
        2,
    );
    defer broker.deinit();

    var serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, @TypeOf(serve).run, .{&serve});
    var joined = false;
    defer if (!joined) {
        broker.shutdownActiveConnections();
        thread.join();
    };

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var client = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "autosave-subscription",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer client.close();
    // Durable CONNECT is the first operation; SUBSCRIBE reaches the threshold.
    var suback = try client.subscribe(
        &.{.{
            .topic_filter = "autosave/subscription",
            .qos = .at_least_once,
        }},
        .{},
    );
    suback.deinit(allocator);
    _ = try tmp.dir.statFile(io, "subscription.db", .{});

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "subscription.db");
    const restored_handle = restored.sessions.find(
        "autosave-subscription",
        std.Io.Clock.awake.now(io),
    ).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.sessions.stats(restored_handle)).subscription_count,
    );

    try client.disconnect(0);
    thread.join();
    joined = true;
    if (serve.err) |err| return err;
}

test "MQTT broker shutdown persists an armed Session expiry deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var source = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 8,
        } },
    );
    var source_owned = true;
    defer if (source_owned) source.deinit();
    var serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &source };
    const thread = try std.Thread.spawn(.{}, @TypeOf(serve).run, .{&serve});
    var joined = false;
    defer if (!joined) {
        source.shutdownActiveConnections();
        thread.join();
    };

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var client = try mqtt.runtime.Client.connect(
        allocator,
        io,
        source.address(),
        .{
            .protocol = .v5,
            .client_id = "shutdown-expiry-session",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    var suback = try client.subscribe(
        &.{.{
            .topic_filter = "shutdown/expiry",
            .qos = .at_least_once,
        }},
        .{},
    );
    suback.deinit(allocator);

    source.shutdownActiveConnections();
    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    client.close();

    const now = std.Io.Clock.awake.now(io);
    const source_handle = source.sessions.find(
        "shutdown-expiry-session",
        now,
    ) orelse return error.TestUnexpectedResult;
    const source_stats = try source.sessions.stats(source_handle);
    try std.testing.expect(!source_stats.connected);
    try std.testing.expectEqual(@as(u32, 60), source_stats.expiry_interval);
    try std.testing.expectEqual(@as(usize, 1), source_stats.subscription_count);
    try source.saveSnapshot(tmp.dir, "shutdown-expiry.db");
    source.deinit();
    source_owned = false;

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "shutdown-expiry.db");
    const restored_now = std.Io.Clock.awake.now(io);
    const restored_handle = restored.sessions.find(
        "shutdown-expiry-session",
        restored_now,
    ) orelse return error.TestUnexpectedResult;
    const restored_stats = try restored.sessions.stats(restored_handle);
    try std.testing.expect(!restored_stats.connected);
    try std.testing.expectEqual(@as(u32, 60), restored_stats.expiry_interval);
    try std.testing.expectEqual(
        @as(usize, 1),
        restored_stats.subscription_count,
    );

    const after_expiry = std.Io.Timestamp.fromNanoseconds(
        restored_now.nanoseconds + 61 * std.time.ns_per_s,
    );
    try std.testing.expect(restored.sessions.find(
        "shutdown-expiry-session",
        after_expiry,
    ) == null);
}

test "MQTT broker snapshot restores retained and durable Session state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    defer source.deinit();

    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "durable",
        false,
        std.math.maxInt(u32),
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{
            .topic_filter = "persist/+",
            .qos = .exactly_once,
            .retain_as_published = true,
        },
        17,
    );
    _ = try source.sessions.enqueuePublish(
        opened.handle,
        "persist/queued",
        "offline",
        .{
            .qos = .at_least_once,
            .now = now,
        },
    );
    var first_send: [1]mqtt.session.Transmission = undefined;
    const sent = try source.sessions.drainInto(
        opened.handle,
        now,
        1,
        &first_send,
    );
    try std.testing.expectEqual(@as(usize, 1), sent.len);
    try std.testing.expectEqualStrings(
        "persist/queued",
        sent[0].publish.topic,
    );
    try source.sessions.disconnect(opened.handle, null, now);

    _ = try source.retained.applyPublish(
        "persist/retained",
        "value",
        .{
            .retain = true,
            .qos = .at_least_once,
            .source_client_id = "persist-retained-writer",
            .source_username = "writer",
            .source_listener_id = 1883,
            .now = now,
        },
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        const stat = try tmp.dir.statFile(io, "broker.db", .{});
        try std.testing.expectEqual(
            @as(std.posix.mode_t, 0o600),
            stat.permissions.toMode() & 0o777,
        );
    }

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");

    var retained_matches: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "persist/retained",
        std.Io.Clock.awake.now(io),
        &retained_matches,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("value", matches[0].payload);
    try std.testing.expectEqualStrings(
        "persist-retained-writer",
        matches[0].source_client_id.?,
    );
    try std.testing.expectEqualStrings(
        "writer",
        matches[0].source_username.?,
    );
    try std.testing.expectEqual(
        @as(?u64, 1883),
        matches[0].source_listener_id,
    );

    const handle = restored.sessions.find(
        "durable",
        std.Io.Clock.awake.now(io),
    ).?;
    const stats = try restored.sessions.stats(handle);
    try std.testing.expect(!stats.connected);
    try std.testing.expectEqual(@as(usize, 1), stats.subscription_count);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);
    try std.testing.expectEqual(@as(usize, 0), stats.incoming_qos2_count);
    var subscriptions: [1]mqtt.session.Subscription = undefined;
    const restored_subscriptions =
        try restored.sessions.subscriptionsInto(handle, &subscriptions);
    try std.testing.expectEqualStrings(
        "persist/+",
        restored_subscriptions[0].topic_filter,
    );
    try std.testing.expectEqual(
        @as(?usize, 17),
        restored_subscriptions[0].subscription_identifier,
    );
    var retransmit: [1]mqtt.session.Transmission = undefined;
    const retransmissions = try restored.sessions.drainInto(
        handle,
        std.Io.Clock.awake.now(io),
        1,
        &retransmit,
    );
    try std.testing.expectEqual(@as(usize, 1), retransmissions.len);
    try std.testing.expect(retransmissions[0].publish.dup);
    try std.testing.expectEqual(@as(usize, 1), restored.router.subscriptionCount());
}

test "MQTT broker snapshot corruption preserves current state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    _ = try broker.retained.applyPublish(
        "existing",
        "safe",
        .{ .retain = true, .now = now },
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.saveSnapshot(tmp.dir, "broker.db");
    const bytes = try tmp.dir.readFileAlloc(
        io,
        "broker.db",
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(bytes);
    const version_offset = "netz-mqtt-db\x00\x01".len;
    try std.testing.expectEqual(
        @as(u32, 7),
        std.mem.readInt(
            u32,
            bytes[version_offset..][0..@sizeOf(u32)],
            .big,
        ),
    );
    std.mem.writeInt(
        u32,
        bytes[version_offset..][0..@sizeOf(u32)],
        6,
        .big,
    );
    std.mem.writeInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        std.hash.crc.Crc32.hash(bytes[0 .. bytes.len - @sizeOf(u32)]),
        .big,
    );
    try tmp.dir.writeFile(io, .{
        .sub_path = "broker.db",
        .data = bytes,
        .flags = .{ .truncate = true },
    });
    try std.testing.expectError(
        error.UnsupportedSnapshotVersion,
        broker.restoreSnapshot(tmp.dir, "broker.db"),
    );
    std.mem.writeInt(
        u32,
        bytes[version_offset..][0..@sizeOf(u32)],
        7,
        .big,
    );
    std.mem.writeInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        std.hash.crc.Crc32.hash(bytes[0 .. bytes.len - @sizeOf(u32)]),
        .big,
    );
    bytes[bytes.len - 1] ^= 0xff;
    try tmp.dir.writeFile(io, .{
        .sub_path = "broker.db",
        .data = bytes,
        .flags = .{ .truncate = true },
    });
    try std.testing.expectError(
        error.CorruptSnapshot,
        broker.restoreSnapshot(tmp.dir, "broker.db"),
    );
    var out: [1]mqtt.retained.Match = undefined;
    const matches = try broker.retained.matchInto("existing", now, &out);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("safe", matches[0].payload);
}

test "MQTT broker commit log restores newest state generation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var source = try createBroker(allocator, io);
    const now = std.Io.Clock.awake.now(io);
    _ = try source.retained.applyPublish(
        "journal/old",
        "old",
        .{ .retain = true, .now = now },
    );
    try source.createCommitLog(tmp.dir, "broker.log", .{});

    _ = try source.retained.applyPublish(
        "journal/current",
        "current",
        .{ .retain = true, .now = now },
    );
    const opened = try source.sessions.open(
        "journal-session",
        false,
        60,
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{ .topic_filter = "journal/+", .qos = .at_least_once },
        23,
    );
    try source.sessions.disconnect(opened.handle, null, now);
    try std.testing.expectEqual(@as(u64, 2), try source.appendCommit());
    try std.testing.expect(source.retained.remove("journal/old"));
    try std.testing.expectEqual(@as(u64, 3), try source.appendCommit());
    source.deinit();

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "broker.log", .{});
    var retained_matches: [1]mqtt.retained.Match = undefined;
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored.retained.matchInto(
            "journal/old",
            std.Io.Clock.awake.now(io),
            &retained_matches,
        )).len,
    );
    const current = try restored.retained.matchInto(
        "journal/current",
        std.Io.Clock.awake.now(io),
        &retained_matches,
    );
    try std.testing.expectEqualStrings("current", current[0].payload);
    const restored_session = restored.sessions.find(
        "journal-session",
        std.Io.Clock.awake.now(io),
    ).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.sessions.stats(restored_session)).subscription_count,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        restored.router.subscriptionCount(),
    );

    _ = try restored.retained.applyPublish(
        "journal/after-restart",
        "continued",
        .{ .retain = true, .now = std.Io.Clock.awake.now(io) },
    );
    try std.testing.expectEqual(@as(u64, 4), try restored.appendCommit());
}

test "MQTT broker commit log decode failure preserves current state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var raw_log = try mqtt.persistence.commit_log.Log.create(
        allocator,
        io,
        tmp.dir,
        "invalid.log",
        .{},
    );
    _ = try raw_log.append("not-a-broker-snapshot");
    raw_log.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    _ = try broker.retained.applyPublish(
        "existing",
        "safe",
        .{ .retain = true, .now = std.Io.Clock.awake.now(io) },
    );
    try std.testing.expectError(
        error.CorruptSnapshot,
        broker.restoreCommitLog(tmp.dir, "invalid.log", .{}),
    );
    var out: [1]mqtt.retained.Match = undefined;
    const matches = try broker.retained.matchInto(
        "existing",
        std.Io.Clock.awake.now(io),
        &out,
    );
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("safe", matches[0].payload);
    try std.testing.expect(broker.commit_log == null);
}

test "MQTT broker commit log persists acknowledgement boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
            },
        },
    );
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.createCommitLog(tmp.dir, "broker.log", .{});

    var serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &source };
    const thread = try std.Thread.spawn(.{}, @TypeOf(serve).run, .{&serve});
    var joined = false;
    defer if (!joined) {
        source.shutdownActiveConnections();
        thread.join();
    };

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        source.address(),
        .{
            .protocol = .v5,
            .client_id = "journal-live-subscriber",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    var subscriber_closed = false;
    defer if (!subscriber_closed) subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "journal/live",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try subscriber.disconnect(0);
    while (true) {
        var scratch: [1]u8 = undefined;
        var bufs = [_][]u8{&scratch};
        const read_result = subscriber.transport.tcp.io.vtable.netRead(
            subscriber.transport.tcp.io.userdata,
            subscriber.transport.tcp.stream.socket.handle,
            &bufs,
        );
        if (read_result) |count| {
            if (count == 0) break;
        } else |err| switch (err) {
            error.SocketUnconnected,
            error.ConnectionResetByPeer,
            => break,
            else => return err,
        }
    }
    subscriber.close();
    subscriber_closed = true;

    var publisher = try mqtt.runtime.Client.connect(
        allocator,
        io,
        source.address(),
        .{
            .protocol = .v5,
            .client_id = "journal-live-publisher",
        },
    );
    var publisher_closed = false;
    defer if (!publisher_closed) publisher.close();
    const packet_id = (try publisher.writePublish(
        "journal/live",
        "durable-before-puback",
        .{ .qos = .at_least_once },
    )).?;
    var puback = try publisher.readPubAck();
    defer puback.deinit(allocator);
    try std.testing.expectEqual(packet_id, puback.ack.packet_id);

    // Model SIGKILL at the exact observable boundary: do not let unregister
    // or orderly broker teardown append another transaction.
    publisher.close();
    publisher_closed = true;
    source.shutdownActiveConnections();
    thread.join();
    joined = true;
    source.deinit();

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "broker.log", .{});
    const handle = restored.sessions.find(
        "journal-live-subscriber",
        std.Io.Clock.awake.now(io),
    ).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.sessions.stats(handle)).queued_count,
    );
}

test "MQTT broker commit log persists graceful Session removal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var source = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 8,
        } },
    );
    var source_owned = true;
    defer if (source_owned) source.deinit();
    try source.createCommitLog(tmp.dir, "disconnect.log", .{});

    var serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &source };
    const thread = try std.Thread.spawn(.{}, @TypeOf(serve).run, .{&serve});
    var joined = false;
    defer if (!joined) {
        source.shutdownActiveConnections();
        thread.join();
    };

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var client = try mqtt.runtime.Client.connect(
        allocator,
        io,
        source.address(),
        .{
            .protocol = .v5,
            .client_id = "journal-disconnect",
            .clean_start = false,
            .properties = &expiry,
            .will = delayedWill(30, false),
        },
    );
    var client_owned = true;
    defer if (client_owned) client.close();
    var suback = try client.subscribe(
        &.{.{
            .topic_filter = "journal/disconnect/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    suback.deinit(allocator);
    const remove_session = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 0,
    } }};
    try client.writeDisconnectWithProperties(0, &remove_session);
    while (true) {
        var scratch: [1]u8 = undefined;
        var bufs = [_][]u8{&scratch};
        const read_result = client.transport.tcp.io.vtable.netRead(
            client.transport.tcp.io.userdata,
            client.transport.tcp.stream.socket.handle,
            &bufs,
        );
        if (read_result) |count| {
            if (count == 0) break;
        } else |err| switch (err) {
            error.SocketUnconnected, error.ConnectionResetByPeer => break,
            else => return err,
        }
    }
    client.close();
    client_owned = false;
    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    source.deinit();
    source_owned = false;

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "disconnect.log", .{});
    try std.testing.expect(restored.sessions.find(
        "journal-disconnect",
        std.Io.Clock.awake.now(io),
    ) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        restored.router.subscriptionCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
}

test "MQTT snapshot deducts downtime from message and Session expiry" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var will_publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer will_publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    var bridge_qos2 = try mqtt.broker.BridgeQoS2Store.init(allocator, .{});
    defer bridge_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.fromNanoseconds(
        100 * std.time.ns_per_s,
    );
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 5,
    } }};
    _ = try retained.applyPublish(
        "expires/retained",
        "gone",
        .{
            .retain = true,
            .properties = &expiry,
            .now = saved_monotonic,
        },
    );
    const short = try sessions.open(
        "expires-session",
        false,
        5,
        saved_monotonic,
    );
    try sessions.disconnect(short.handle, null, saved_monotonic);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &will_publishers,
            .pending_qos2 = &pending_qos2,
            .bridge_qos2 = &bridge_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(1_006 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    defer restored.bridge_qos2.deinit();

    var out: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto(
        "expires/retained",
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        &out,
    );
    try std.testing.expectEqual(@as(usize, 0), matches.len);
    try std.testing.expect(
        restored.sessions.find(
            "expires-session",
            std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        ) == null,
    );
}

test "MQTT atomic snapshot replacement keeps latest complete state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    _ = try broker.retained.applyPublish(
        "replace",
        "first",
        .{ .retain = true, .now = now },
    );
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.saveSnapshot(tmp.dir, "broker.db");
    _ = try broker.retained.applyPublish(
        "replace",
        "second",
        .{ .retain = true, .now = now },
    );
    try broker.saveSnapshot(tmp.dir, "broker.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");
    var out: [1]mqtt.retained.Match = undefined;
    const matches = try restored.retained.matchInto("replace", now, &out);
    try std.testing.expectEqualStrings("second", matches[0].payload);
}

test "MQTT snapshot save rejects live transient broker state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    broker.slots[0].state.active = true;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(
        error.SnapshotBusy,
        broker.saveSnapshot(tmp.dir, "broker.db"),
    );
}

test "MQTT live snapshot checkpoints connected durable state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    defer source.deinit();
    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "live-checkpoint",
        false,
        std.math.maxInt(u32),
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{
            .topic_filter = "live/#",
            .qos = .at_least_once,
        },
        23,
    );
    _ = try source.sessions.enqueuePublish(
        opened.handle,
        "live/queued",
        "persisted",
        .{ .qos = .at_least_once, .now = now },
    );
    var transmission_storage: [1]mqtt.session.Transmission = undefined;
    const transmissions = try source.sessions.drainInto(
        opened.handle,
        now,
        1,
        &transmission_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), transmissions.len);
    const packet_id = transmissions[0].publish.packet_id;

    const will_handle = try source.wills.setWithSource(
        "live-checkpoint",
        delayedWill(10, true),
        "will-writer",
        8883,
        60,
    );
    try source.will_publishers.put(
        allocator,
        will_handle,
        sessionRouteSubscriberId(opened.route_id),
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveLiveSnapshot(tmp.dir, "broker.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    const restore_started = std.Io.Clock.awake.now(io);
    try restored.restoreSnapshot(tmp.dir, "broker.db");

    const restored_handle = restored.sessions.find(
        "live-checkpoint",
        std.Io.Clock.awake.now(io),
    ).?;
    const stats = try restored.sessions.stats(restored_handle);
    try std.testing.expect(!stats.connected);
    try std.testing.expectEqual(@as(usize, 1), stats.subscription_count);
    try std.testing.expectEqual(@as(usize, 1), stats.inflight_count);
    var retransmission_storage: [1]mqtt.session.Transmission = undefined;
    const retransmissions = try restored.sessions.drainInto(
        restored_handle,
        std.Io.Clock.awake.now(io),
        1,
        &retransmission_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), retransmissions.len);
    try std.testing.expect(retransmissions[0].publish.dup);
    try std.testing.expectEqual(packet_id, retransmissions[0].publish.packet_id);
    try std.testing.expectEqualStrings(
        "persisted",
        retransmissions[0].publish.payload,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        restored.router.subscriptionCount(),
    );

    const restored_will = restored.wills.handleForClient(
        "live-checkpoint",
    ).?;
    try std.testing.expectEqual(
        sessionRouteSubscriberId(opened.route_id),
        restored.will_publishers.get(restored_will).?,
    );
    const deadline = restored.wills.nextDeadline().?;
    // A slow or instrumented test runner can spend the entire ten-second Will
    // Delay between the checkpoint and restore. In that valid case downtime
    // deduction makes the Will immediately due rather than manufacturing a
    // fresh delay. Compare with a clock sample taken before restore: the
    // implementation's internal restore timestamp is necessarily at or after
    // it, while a sample taken after the file read could race an immediate
    // deadline and recreate the original flaky assertion.
    try std.testing.expect(deadline.nanoseconds >= restore_started.nanoseconds);
}

test "MQTT live snapshot Will delay deducts deterministic downtime" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    var bridge_qos2 = try mqtt.broker.BridgeQoS2Store.init(allocator, .{});
    defer bridge_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.fromNanoseconds(
        100 * std.time.ns_per_s,
    );
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const handle = try wills.setWithSource(
        "live-will-source",
        delayedWill(10, true),
        "will-writer",
        8883,
        60,
    );
    try publishers.put(allocator, handle, 91);

    const encoded = try mqtt.persistence.encodeLive(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &publishers,
            .pending_qos2 = &pending_qos2,
            .bridge_qos2 = &bridge_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    const restored_now = std.Io.Timestamp.fromNanoseconds(
        50 * std.time.ns_per_s,
    );

    var before_due = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        restored_now,
        std.Io.Timestamp.fromNanoseconds(
            1_004 * std.time.ns_per_s,
        ),
    );
    defer before_due.retained.deinit();
    defer before_due.sessions.deinit();
    defer before_due.wills.deinit();
    defer before_due.will_publishers.deinit(allocator);
    defer before_due.pending_qos2.deinit();
    defer before_due.bridge_qos2.deinit();
    try std.testing.expectEqual(
        @as(i96, restored_now.nanoseconds + 6 * std.time.ns_per_s),
        before_due.wills.nextDeadline().?.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(?u64, 91),
        before_due.will_publishers.get(
            before_due.wills.handleForClient("live-will-source").?,
        ).?,
    );
    const restored_will = try before_due.wills.view(
        before_due.wills.handleForClient("live-will-source").?,
    );
    try std.testing.expectEqualStrings(
        "will-writer",
        restored_will.source_username.?,
    );
    try std.testing.expectEqual(
        @as(?u64, 8883),
        restored_will.source_listener_id,
    );

    var overdue = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        restored_now,
        std.Io.Timestamp.fromNanoseconds(
            1_011 * std.time.ns_per_s,
        ),
    );
    defer overdue.retained.deinit();
    defer overdue.sessions.deinit();
    defer overdue.wills.deinit();
    defer overdue.will_publishers.deinit(allocator);
    defer overdue.pending_qos2.deinit();
    defer overdue.bridge_qos2.deinit();
    try std.testing.expectEqual(
        restored_now.nanoseconds,
        overdue.wills.nextDeadline().?.nanoseconds,
    );
    var due_storage: [1]mqtt.will_scheduler.Handle = undefined;
    const due = try overdue.wills.pollDue(restored_now, &due_storage);
    try std.testing.expectEqual(@as(usize, 1), due.len);
    try std.testing.expectEqual(
        @as(?u64, 91),
        overdue.will_publishers.get(due[0]).?,
    );
}

test "MQTT live snapshot omits transient inbound QoS 2" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    defer source.deinit();
    const now = std.Io.Clock.awake.now(io);
    const transient_publisher: u64 = 11;
    _ = try source.pending_qos2.record(
        transient_publisher,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "transient/qos2",
            .packet_id = 7,
            .properties = &.{},
            .payload = "not-durable",
        },
        now,
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveLiveSnapshot(tmp.dir, "broker.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");
    try std.testing.expectEqual(@as(usize, 0), restored.pending_qos2.count());
}

test "MQTT live snapshot omits route-tagged transient inbound QoS 2" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    defer source.deinit();
    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "transient-canonical-qos2",
        true,
        0,
        now,
    );
    _ = try source.pending_qos2.record(
        sessionRouteSubscriberId(opened.route_id),
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "transient/canonical-qos2",
            .packet_id = 8,
            .properties = &.{},
            .payload = "not-durable",
        },
        now,
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveLiveSnapshot(tmp.dir, "broker.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");
    try std.testing.expectEqual(@as(usize, 0), restored.pending_qos2.count());
}

test "MQTT live snapshot rejects provisional registrations" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    broker.slots[0].state.active = true;

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(
        error.SnapshotBusy,
        broker.saveLiveSnapshot(tmp.dir, "broker.db"),
    );
}

test "MQTT live snapshot checkpoints an active broker connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                // Include an unused slot so the checkpoint also proves that
                // inactive connection state cannot block live persistence.
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
            },
        },
    );
    var serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    }{ .broker = &source };
    const thread = try std.Thread.spawn(.{}, @TypeOf(serve).run, .{&serve});
    var joined = false;
    defer if (!joined) {
        source.shutdownActiveConnections();
        thread.join();
    };

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = std.math.maxInt(u32),
    } }};
    var live = try mqtt.runtime.Client.connect(
        allocator,
        io,
        source.address(),
        .{
            .protocol = .v5,
            .client_id = "active-checkpoint",
            .clean_start = false,
            .properties = &expiry,
            .will = delayedWill(10, false),
        },
    );
    defer live.close();
    var suback = try live.subscribe(
        &.{.{ .topic_filter = "active/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    const packet_id = try live.writePublish(
        "active/inbound-qos2",
        "pending",
        .{ .qos = .exactly_once },
    );
    var pubrec = try live.readPubRec();
    defer pubrec.deinit(allocator);
    try std.testing.expectEqual(packet_id.?, pubrec.ack.packet_id);

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveLiveSnapshot(tmp.dir, "broker.db");
    // Checkpointing must not disconnect or otherwise poison the live client.
    try live.ping();
    try live.disconnect(0);
    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    // The source's post-checkpoint DISCONNECT intentionally canceled its live
    // Will. The restored broker below models a crash at the checkpoint, so it
    // must recover the independently encoded pre-disconnect Will instead.
    source.deinit();

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "broker.db");
    const restored_handle = restored.sessions.find(
        "active-checkpoint",
        std.Io.Clock.awake.now(io),
    ).?;
    const stats = try restored.sessions.stats(restored_handle);
    try std.testing.expect(!stats.connected);
    try std.testing.expectEqual(@as(usize, 1), stats.subscription_count);
    try std.testing.expect(
        restored.wills.handleForClient("active-checkpoint") != null,
    );
    try std.testing.expectEqual(@as(usize, 1), restored.pending_qos2.count());
}

test "MQTT broker restart resumes Session and live routing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const now = std.Io.Clock.awake.now(io);
    const opened = try source.sessions.open(
        "restart-client",
        false,
        std.math.maxInt(u32),
        now,
    );
    _ = try source.sessions.setSubscription(
        opened.handle,
        .{
            .topic_filter = "restart/#",
            .qos = .at_least_once,
        },
        null,
    );
    _ = try source.sessions.enqueuePublish(
        opened.handle,
        "restart/before",
        "queued",
        .{ .qos = .at_least_once, .now = now },
    );
    try source.sessions.disconnect(opened.handle, null, now);

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = std.math.maxInt(u32),
    } }};
    var resumed_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "restart-client",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer resumed_result.connack.deinit(allocator);
    var resumed = resumed_result.connection;
    defer resumed.close();
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var queued = try resumed.readPublish();
    defer queued.deinit(allocator);
    try std.testing.expect(!queued.publish.dup);
    try std.testing.expectEqualStrings(
        "queued",
        queued.publish.payload,
    );
    try resumed.writePubAck(queued.publish.packet_id.?, 0);

    var publisher = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "restart-publisher",
        },
    );
    defer publisher.close();
    try publisher.publish(
        "restart/after",
        "routed",
        .{ .qos = .at_least_once },
    );
    var routed = try resumed.readPublish();
    defer routed.deinit(allocator);
    try std.testing.expectEqualStrings("routed", routed.publish.payload);
    try resumed.writePubAck(routed.publish.packet_id.?, 0);
    try resumed.disconnect(0);
    try publisher.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
}

test "MQTT snapshot preserves PUBREL after message expiry" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var will_publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer will_publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    var bridge_qos2 = try mqtt.broker.BridgeQoS2Store.init(allocator, .{});
    defer bridge_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.zero;
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const opened = try sessions.open(
        "qos2-pubrel",
        false,
        std.math.maxInt(u32),
        saved_monotonic,
    );
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 1,
    } }};
    _ = try sessions.enqueuePublish(
        opened.handle,
        "qos2/expiry",
        "payload",
        .{
            .qos = .exactly_once,
            .properties = &expiry,
            .now = saved_monotonic,
        },
    );
    var transmission: [1]mqtt.session.Transmission = undefined;
    const initial = try sessions.drainInto(
        opened.handle,
        saved_monotonic,
        1,
        &transmission,
    );
    const packet_id = initial[0].publish.packet_id;
    try std.testing.expectEqual(
        mqtt.session.AckAction.send_pubrel,
        try sessions.handleAck(
            opened.handle,
            .pubrec,
            packet_id,
            0,
        ),
    );
    try sessions.disconnect(opened.handle, null, saved_monotonic);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &will_publishers,
            .pending_qos2 = &pending_qos2,
            .bridge_qos2 = &bridge_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(1_010 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    defer restored.bridge_qos2.deinit();
    const handle = restored.sessions.find(
        "qos2-pubrel",
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
    ).?;
    const resumed = try restored.sessions.drainInto(
        handle,
        std.Io.Timestamp.fromNanoseconds(10 * std.time.ns_per_s),
        1,
        &transmission,
    );
    try std.testing.expectEqual(@as(usize, 1), resumed.len);
    try std.testing.expectEqual(packet_id, resumed[0].pubrel.packet_id);
}

test "MQTT scheduled Will snapshot deducts downtime and restores publisher" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    var bridge_qos2 = try mqtt.broker.BridgeQoS2Store.init(allocator, .{});
    defer bridge_qos2.deinit();
    const saved_monotonic = std.Io.Timestamp.fromNanoseconds(
        100 * std.time.ns_per_s,
    );
    const saved_realtime = std.Io.Timestamp.fromNanoseconds(
        1_000 * std.time.ns_per_s,
    );
    const handle = try wills.set(
        "will-source",
        delayedWill(10, true),
        60,
    );
    _ = try wills.close(handle, .ungraceful, saved_monotonic);
    try publishers.put(allocator, handle, 77);

    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &publishers,
            .pending_qos2 = &pending_qos2,
            .bridge_qos2 = &bridge_qos2,
        },
        saved_monotonic,
        saved_realtime,
    );
    defer allocator.free(encoded);
    const restored_now = std.Io.Timestamp.fromNanoseconds(
        50 * std.time.ns_per_s,
    );
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        restored_now,
        std.Io.Timestamp.fromNanoseconds(1_004 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    defer restored.bridge_qos2.deinit();

    try std.testing.expectEqual(
        @as(i96, restored_now.nanoseconds + 6 * std.time.ns_per_s),
        restored.wills.nextDeadline().?.nanoseconds,
    );
    var due_storage: [1]mqtt.will_scheduler.Handle = undefined;
    const due = try restored.wills.pollDue(
        std.Io.Timestamp.fromNanoseconds(
            restored_now.nanoseconds + 6 * std.time.ns_per_s,
        ),
        &due_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), due.len);
    try std.testing.expectEqual(
        @as(?u64, 77),
        restored.will_publishers.get(due[0]).?,
    );
    const publish = try restored.wills.view(due[0]);
    try std.testing.expectEqualStrings("offline", publish.payload);
    try std.testing.expect(publish.retain);
}

test "MQTT restored scheduled Will is canceled by continued Session" {
    const allocator = std.testing.allocator;
    var retained = mqtt.retained.Store.init(allocator, .{});
    defer retained.deinit();
    var sessions = mqtt.session.Store.init(allocator, .{});
    defer sessions.deinit();
    var wills = mqtt.will_scheduler.Scheduler.init(allocator, .{});
    defer wills.deinit();
    var publishers: mqtt.will_scheduler.PublisherMap = .empty;
    defer publishers.deinit(allocator);
    var pending_qos2 = try mqtt.broker.PendingQoS2Store.init(allocator, 16);
    defer pending_qos2.deinit();
    var bridge_qos2 = try mqtt.broker.BridgeQoS2Store.init(allocator, .{});
    defer bridge_qos2.deinit();
    const handle = try wills.set(
        "resume-will",
        delayedWill(30, false),
        60,
    );
    _ = try wills.close(handle, .ungraceful, .zero);
    try publishers.put(allocator, handle, null);
    const encoded = try mqtt.persistence.encode(
        allocator,
        .{
            .retained = &retained,
            .sessions = &sessions,
            .wills = &wills,
            .will_publishers = &publishers,
            .pending_qos2 = &pending_qos2,
            .bridge_qos2 = &bridge_qos2,
        },
        .zero,
        std.Io.Timestamp.fromNanoseconds(1_000 * std.time.ns_per_s),
    );
    defer allocator.free(encoded);
    var restored = try mqtt.persistence.decode(
        allocator,
        encoded,
        .{},
        .{},
        .{},
        16,
        .{},
        .zero,
        std.Io.Timestamp.fromNanoseconds(1_001 * std.time.ns_per_s),
    );
    defer restored.retained.deinit();
    defer restored.sessions.deinit();
    defer restored.wills.deinit();
    defer restored.will_publishers.deinit(allocator);
    defer restored.pending_qos2.deinit();
    defer restored.bridge_qos2.deinit();

    const restored_handle =
        restored.wills.handleForClient("resume-will").?;
    try std.testing.expectEqual(
        mqtt.will_scheduler.CloseResult.canceled,
        restored.wills.onReconnect("resume-will", false, .zero),
    );
    _ = restored.will_publishers.remove(restored_handle);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
}

test "MQTT broker restart publishes due retained Will" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const scheduled = try source.wills.set(
        "broker-will-source",
        delayedWill(1, true),
        60,
    );
    _ = try source.wills.close(
        scheduled,
        .ungraceful,
        std.Io.Clock.awake.now(io),
    );
    try source.will_publishers.put(
        allocator,
        scheduled,
        null,
    );
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try mqtt.runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "will-after-restart",
        },
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "persist/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings("persist/will", publish.publish.topic);
    try std.testing.expectEqualStrings("offline", publish.publish.payload);
    // Depending on whether the restored deadline or SUBSCRIBE wins, this is
    // either live fanout (default RAP=false, RETAIN=0) or retained replay
    // (RETAIN=1). The retained-store assertion below is path-independent.
    try subscriber.writePubAck(publish.publish.packet_id.?, 0);
    try subscriber.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
    var retained_match: [1]mqtt.retained.Match = undefined;
    const retained = try broker.retained.matchInto(
        "persist/will",
        std.Io.Clock.awake.now(io),
        &retained_match,
    );
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings("offline", retained[0].payload);
}

test "MQTT broker restart releases inbound QoS 2 exactly once at PUBREL" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var source = try createBroker(allocator, io);
    const saved_now = std.Io.Clock.awake.now(io);
    const publisher_session = try source.sessions.open(
        "durable-qos2-publisher",
        false,
        std.math.maxInt(u32),
        saved_now,
    );
    const durable_publisher_id = sessionRouteSubscriberId(
        publisher_session.route_id,
    );
    const packet_id: u16 = 71;
    _ = try source.pending_qos2.record(
        durable_publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "restart/inbound-qos2",
            .packet_id = packet_id,
            .payload = "exactly-once-after-restart",
        },
        saved_now,
    );
    try source.sessions.disconnect(
        publisher_session.handle,
        null,
        saved_now,
    );
    const subscriber_session = try source.sessions.open(
        "durable-qos2-subscriber",
        false,
        std.math.maxInt(u32),
        saved_now,
    );
    _ = try source.sessions.setSubscription(
        subscriber_session.handle,
        .{
            .topic_filter = "restart/inbound-qos2",
            .qos = .at_least_once,
        },
        null,
    );
    try source.sessions.disconnect(
        subscriber_session.handle,
        null,
        saved_now,
    );

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try source.saveSnapshot(tmp.dir, "broker.db");
    source.deinit();

    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    try broker.restoreSnapshot(tmp.dir, "broker.db");
    try std.testing.expectEqual(@as(usize, 1), broker.pending_qos2.count());
    const Serve = struct {
        broker: *Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(2) catch |err| {
                self.err = err;
            };
        }
    };
    var serve = Serve{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = std.math.maxInt(u32),
    } }};
    var subscriber_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "durable-qos2-subscriber",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer subscriber_result.connack.deinit(allocator);
    var subscriber = subscriber_result.connection;
    defer subscriber.close();
    try std.testing.expect(
        subscriber_result.connack.connack.session_present,
    );

    var publisher_result = try mqtt.runtime.Client.connectWithConnAck(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "durable-qos2-publisher",
            .clean_start = false,
            .properties = &expiry,
        },
    );
    defer publisher_result.connack.deinit(allocator);
    var publisher = publisher_result.connection;
    defer publisher.close();
    try std.testing.expect(
        publisher_result.connack.connack.session_present,
    );

    try publisher.writePubRel(packet_id, 0);
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "exactly-once-after-restart",
        delivered.publish.payload,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    var pubcomp = try publisher.readPubComp();
    defer pubcomp.deinit(allocator);
    try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
    try std.testing.expectEqual(@as(usize, 0), broker.pending_qos2.count());

    // A repeated PUBREL acknowledges idempotently but has no pending body to
    // route a second time.
    try publisher.writePubRel(packet_id, 0);
    var repeated = try publisher.readPubComp();
    defer repeated.deinit(allocator);
    try std.testing.expectEqual(packet_id, repeated.ack.packet_id);
    try publisher.disconnect(0);
    try subscriber.disconnect(0);

    thread.join();
    joined = true;
    if (serve.err) |err| return err;
}

test "MQTT Clean Start removes pending inbound QoS 2 transaction" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    const old = try broker.sessions.open(
        "qos2-clean-start",
        false,
        std.math.maxInt(u32),
        now,
    );
    const old_publisher_id = sessionRouteSubscriberId(old.route_id);
    _ = try broker.pending_qos2.record(
        old_publisher_id,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/clean",
            .packet_id = 9,
            .payload = "discard",
        },
        now,
    );

    // Mirror register's Clean Start transition: opening a new Session changes
    // the stable route, then the old route's pending transactions are retired.
    const replacement = try broker.sessions.open(
        "qos2-clean-start",
        true,
        0,
        now,
    );
    try std.testing.expect(replacement.route_id != old.route_id);
    _ = broker.pending_qos2.removePublisher(old_publisher_id);
    try std.testing.expectEqual(@as(usize, 0), broker.pending_qos2.count());
}

fn sessionRouteSubscriberId(route_id: u64) u64 {
    return (@as(u64, 1) << 63) | route_id;
}

test "MQTT broker snapshot restores bridge QoS2 transactions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try createBroker(allocator, io);
    defer broker.deinit();
    const key = mqtt.broker.bridge_qos2_mod.Key{
        .bridge_id = [_]u8{0x5a} ** 16,
        .session_epoch = 7,
        .packet_id = 44,
    };
    _ = try broker.bridge_qos2.stage(key, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "bridge/persisted",
        .packet_id = null,
        .payload = "payload",
    }, std.Io.Clock.awake.now(io));

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.saveSnapshot(tmp.dir, "bridge-qos2.db");

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreSnapshot(tmp.dir, "bridge-qos2.db");
    try std.testing.expectEqual(
        mqtt.broker.bridge_qos2_mod.Phase.pending,
        restored.bridge_qos2.getPhase(key).?,
    );
    try std.testing.expectEqualStrings(
        "payload",
        restored.bridge_qos2.getPending(key).?.payload,
    );

    try std.testing.expectEqual(
        mqtt.broker.BridgeQoS2ReleaseResult.applied,
        (try restored.releaseBridgeQoS2(key)).disposition,
    );
    try std.testing.expectEqual(
        mqtt.broker.BridgeQoS2ReleaseResult.already_applied,
        (try restored.releaseBridgeQoS2(key)).disposition,
    );
    try std.testing.expect(try restored.completeBridgeQoS2(key));
    try std.testing.expect(!restored.containsBridgeQoS2(key));
}

test "MQTT broker persists bridge epoch without an active transaction" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    const bridge_id = [_]u8{0x6b} ** 16;

    var source = try createBroker(allocator, io);
    defer source.deinit();
    try source.createCommitLog(tmp.dir, "bridge-epoch.log", .{});
    try std.testing.expectEqual(
        @as(u64, 1),
        try source.beginBridgeQoS2Session(bridge_id),
    );
    try std.testing.expectEqual(
        @as(?u64, 1),
        source.latestBridgeQoS2SessionEpoch(bridge_id),
    );
    const stale_key = mqtt.broker.BridgeQoS2Key{
        .bridge_id = bridge_id,
        .session_epoch = 1,
        .packet_id = 9,
    };
    _ = try source.stageBridgeQoS2(stale_key, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "bridge/stale",
        .packet_id = null,
        .payload = "old-session",
    }, .{});
    try std.testing.expectEqual(
        @as(u64, 2),
        try source.beginBridgeQoS2Session(bridge_id),
    );
    try std.testing.expect(!source.containsBridgeQoS2(stale_key));

    var restored = try createBroker(allocator, io);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "bridge-epoch.log", .{});
    try std.testing.expectEqual(
        @as(?u64, 2),
        restored.latestBridgeQoS2SessionEpoch(bridge_id),
    );
    try std.testing.expect(!restored.containsBridgeQoS2(stale_key));
    try std.testing.expectEqual(
        @as(u64, 3),
        try restored.beginBridgeQoS2Session(bridge_id),
    );
}
