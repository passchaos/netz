const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const reconnect = @import("../../reconnect.zig");
const Pair = @import("../../runtime/acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const Mode = enum { pubrec, pubrel, auth };
const method = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }};
const diagnostics = [_]mqtt.Property{.{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "owned metadata" } }};

test "MQTT interrupted automatic control replies preserve ordered owned events" {
    for (std.enums.values(Mode)) |mode| try retainedControl(mode);
}

fn retainedControl(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fault = BlockedWrite{ .delegate = io, .packet_type = switch (mode) {
        .pubrec => .pubrel,
        .pubrel => .pubcomp,
        .auth => .auth,
    } };
    BlockedWrite.active = &fault;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    const Handler = struct {
        calls: usize = 0,
        fn respond(context: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return &method;
        }
    };
    var handler: Handler = .{};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = "retained-control",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
        .authentication = if (mode == .auth) .{ .context = &handler, .respond = Handler.respond } else null,
    }, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(observed_io, .v5);
    client.connection_state = pair.client;
    client.connection().?.session_expiry_interval = 60;
    var peer = pair.peer;
    defer peer.close();
    switch (mode) {
        .pubrec => {
            const attempt = try client.publishOneAttempt("retained/outgoing", "body", .{ .qos = .exactly_once });
            var publish = try peer.readPublish();
            publish.deinit(allocator);
            try peer.writePubRecWithProperties(attempt.packet_id.?, 0, &diagnostics);
        },
        .pubrel => {
            const id = (try peer.writePublish("retained/incoming", "body", .{ .qos = .exactly_once })).?;
            var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
            publish.deinit(allocator);
            var received = try peer.readPubRec();
            received.deinit(allocator);
            try peer.writePubRelWithProperties(id, 0, &diagnostics);
        },
        .auth => {
            try client.connection().?.authentication.beginConnect(allocator, &method);
            client.connection().?.authentication.phase = .reauthenticating;
            try peer.writeAuth(0x18, &.{ method[0], diagnostics[0] });
        },
    }
    fault.armed.store(true, .release);
    try std.testing.expect((try client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false })) == null);
    try std.testing.expect(fault.canceled.load(.acquire));
    try std.testing.expect(client.connection() == null);
    var snapshot: std.ArrayList(u8) = .empty;
    defer snapshot.deinit(allocator);
    try std.testing.expectError(error.SnapshotBusy, client.writeSessionSnapshot(&snapshot));
    var event = (try client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromSeconds(1)), .{})).?;
    defer event.deinit(allocator);
    const fields = switch (mode) {
        .pubrec => blk: {
            try std.testing.expect(event == .pubrec);
            try std.testing.expectEqual(.await_pubcomp, (try client.outgoing.outgoingQoSState(client.outgoing_handle, event.pubrec.ack.packet_id)).?);
            break :blk event.pubrec.ack.properties;
        },
        .pubrel => blk: {
            try std.testing.expect(event == .pubrel);
            try std.testing.expect(!try client.outgoing.containsIncomingQoS2(client.outgoing_handle, event.pubrel.ack.packet_id));
            break :blk event.pubrel.ack.properties;
        },
        .auth => blk: {
            try std.testing.expect(event == .auth);
            try std.testing.expectEqual(@as(usize, 1), handler.calls);
            break :blk event.auth.auth.properties[1..];
        },
    };
    try std.testing.expectEqualStrings("owned metadata", fields[0].utf8_pair.value);
    try client.writeSessionSnapshot(&snapshot);
}

test "MQTT local authentication callbacks retain network-shaped errors without reconnecting" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Handler = struct {
        calls: usize = 0,
        fn respond(context: *anyopaque, _: mqtt.Auth) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.ConnectionResetByPeer;
        }
    };
    var handler: Handler = .{};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{ .protocol = .v5, .client_id = "local-network-error", .authentication = .{ .context = &handler, .respond = Handler.respond } }, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(io, .v5);
    client.connection_state = pair.client;
    var peer = pair.peer;
    defer peer.close();
    try client.connection().?.authentication.beginConnect(allocator, &method);
    client.connection().?.authentication.phase = .reauthenticating;
    try peer.writeAuth(0x18, &method);
    try std.testing.expectError(error.ConnectionResetByPeer, client.pollWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expect(client.connection() == null);
    try std.testing.expect(client.pending_event == null);
}
