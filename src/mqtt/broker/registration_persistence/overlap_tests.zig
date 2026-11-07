//! Durable reader and takeover admission overlap regressions.
const std = @import("std");
const test_tmp = @import("../../../internal/test_tmp_dir.zig");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const context = @import("../../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const support = @import("test_support.zig");
const AdmissionOverlap = support.AdmissionOverlap;
const OverlapService = support.OverlapService;
const OverlapClient = support.OverlapClient;
const waitOverlap = support.waitOverlap;
const expectOverlapEof = support.expectOverlapEof;
const writeOverlapDisconnect = support.writeOverlapDisconnect;

test "broker durable DISCONNECT waits for the following provisional CONNECT without holding persistence locks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = AdmissionOverlap{ .delegate = io, .freeze_disconnect = true, .park_second = true };
    AdmissionOverlap.active = &observer;
    defer AdmissionOverlap.active = null;
    var vtable = io.vtable.*;
    vtable.netRead = AdmissionOverlap.netRead;
    vtable.netWrite = AdmissionOverlap.netWrite;
    vtable.sleep = AdmissionOverlap.sleep;
    vtable.netClose = AdmissionOverlap.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "disconnect-overlap.log", .{});
    var service = OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        observer.unblock();
        service.shutdown.set(io);
        server_thread.join();
    };
    var will_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 30 } }};
    var first = try runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "disconnect-before-connect",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
        .will = .{ .topic = "overlap/will", .payload = "must-not-revive", .retain = true, .properties = &will_properties },
    });
    defer first.close();
    try first.ping();
    try writeOverlapDisconnect(&first);
    try waitOverlap(&observer.disconnect_read, io);
    try std.testing.expectError(error.Timeout, first.transport.readPacketWithDeadline(allocator, 4096, first.transport.deadlineFromNow(.fromMilliseconds(10))));
    // Preserve the fixture's DISCONNECT-before-CONNECT wire order. No EOF
    // barrier is inserted before starting this second admission.
    var client = OverlapClient{ .io = io, .address = broker.address(), .client_id = "overlap-replay" };
    const client_thread = try std.Thread.spawn(.{}, OverlapClient.run, .{&client});
    var client_joined = false;
    defer {
        observer.unblock();
        if (!client_joined) client_thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    try waitOverlap(&observer.connack_parked, io);
    try std.testing.expectError(error.SnapshotBusy, broker.appendCommit());
    try std.testing.expectError(error.SnapshotBusy, broker.saveLiveSnapshot(tmp.dir, "busy-overlap.db"));
    observer.release_disconnect.set(io);
    try waitOverlap(&observer.retry_entered, io);
    const lock_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try timed_mutex.lock(&broker.persistence_mutex, io, lock_deadline);
    broker.persistence_mutex.unlock(io);
    const observed = state: {
        try timed_mutex.lock(&broker.state_mutex, io, lock_deadline);
        defer broker.state_mutex.unlock(io);
        const handle = broker.sessions.find("disconnect-before-connect", std.Io.Clock.awake.now(io)) orelse return error.SessionNotFound;
        break :state .{ .disconnected = !(try broker.sessions.stats(handle)).connected, .wills = broker.wills.count() };
    };
    try std.testing.expect(observed.disconnected);
    try std.testing.expectEqual(@as(usize, 0), observed.wills);
    observer.release_connack.set(io);
    client_thread.join();
    client_joined = true;
    if (client.err) |err| return err;
    var second = client.result.?;
    client.result = null;
    defer second.deinit(allocator);
    observer.release_retry.set(io);
    // Receiving DISCONNECT shuts down the server read transport before the
    // broker mutation completes. Physical close in unregister follows its
    // journal fsync, so wait for that retirement before ending the service.
    try waitOverlap(&observer.first_retired, io);
    try expectOverlapEof(&first);
    try second.connection.ping();
    try writeOverlapDisconnect(&second.connection);
    try waitOverlap(&observer.second_retired, io);
    try expectOverlapEof(&second.connection);
    service.shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "disconnect-overlap.log", .{});
    try std.testing.expectEqual(@as(usize, 1), restored.sessions.count());
    const recovered = restored.sessions.find("disconnect-before-connect", std.Io.Clock.awake.now(io)).?;
    try std.testing.expect(!(try restored.sessions.stats(recovered)).connected);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
    try std.testing.expectEqual(@as(usize, 0), restored.will_publishers.count());
}

test "broker accepted takeover attaches before waiting for the displaced durable writer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = AdmissionOverlap{ .delegate = io };
    AdmissionOverlap.active = &observer;
    defer AdmissionOverlap.active = null;
    var vtable = io.vtable.*;
    vtable.futexWaitUncancelable = AdmissionOverlap.waitUncancelable;
    vtable.netClose = AdmissionOverlap.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "takeover-overlap.log", .{});
    var service = OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        service.shutdown.set(io);
        server_thread.join();
    };
    var first = try runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "held-writer-takeover",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
    });
    defer first.close();
    try first.ping();
    const old_writer = &broker.slots[0].writer_mutex;
    observer.old_writer.store(old_writer, .release);
    old_writer.lockUncancelable(io);
    var writer_held = true;
    defer if (writer_held) old_writer.unlock(io);
    var client = OverlapClient{ .io = io, .address = broker.address(), .client_id = "held-writer-takeover", .clean_start = false, .expiry = 120 };
    const client_thread = try std.Thread.spawn(.{}, OverlapClient.run, .{&client});
    var client_joined = false;
    defer {
        if (!client_joined) client_thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    try waitOverlap(&observer.writer_parked, io);
    client_thread.join();
    client_joined = true;
    if (client.err) |err| return err;
    var second = client.result.?;
    client.result = null;
    defer second.deinit(allocator);
    try std.testing.expect(second.connack.connack.session_present);
    // The replacement has received CONNACK but cannot close the old transport
    // or start its ClientTask until this held writer is released. Its attached
    // state must already support another caller's coherent durable boundary.
    try broker.saveLiveSnapshot(tmp.dir, "attached-takeover.db");
    _ = try broker.appendCommit();
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "takeover-overlap.log", .{});
    try std.testing.expectEqual(@as(usize, 1), restored.sessions.count());
    const handle = restored.sessions.find("held-writer-takeover", std.Io.Clock.awake.now(io)).?;
    try std.testing.expect(!(try restored.sessions.stats(handle)).connected);
    old_writer.unlock(io);
    writer_held = false;
    var packet = try first.transport.readPacketWithDeadline(allocator, 4096, first.transport.deadlineFromNow(.fromSeconds(5)));
    defer packet.deinit(allocator);
    var terminal = try mqtt.Disconnect.parse(allocator, .v5, packet.bytes);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8e), terminal.reason_code);
    try waitOverlap(&observer.first_retired, io);
    try expectOverlapEof(&first);
    try second.connection.ping();
    try writeOverlapDisconnect(&second.connection);
    try waitOverlap(&observer.second_retired, io);
    try expectOverlapEof(&second.connection);
    service.shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
}
