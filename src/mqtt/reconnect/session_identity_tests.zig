//! Allocation failure cannot invalidate local QoS handles or owned identities.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const identity = @import("session_identity.zig");

fn makeClient(allocator: std.mem.Allocator, io: std.Io, shutdown: *std.Io.Event, client_id: []const u8) !reconnect.Client {
    return reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = client_id,
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, shutdown);
}

fn adoptionFailure(allocator: std.mem.Allocator, io: std.Io) !void {
    var shutdown: std.Io.Event = .unset;
    var client = try makeClient(allocator, io, &shutdown, "");
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "desired/#" }, &.{});
    identity.adopt(&client, "assigned-id") catch |err| {
        try std.testing.expectEqualStrings("", client.clientId());
        try std.testing.expectEqualStrings("", try client.outgoing.clientId(client.outgoing_handle));
        try std.testing.expect(client.subscription_replay_index == null);
        try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
        return err;
    };
    try std.testing.expectEqualStrings("assigned-id", client.clientId());
    try std.testing.expectEqualStrings("assigned-id", try client.outgoing.clientId(client.outgoing_handle));
    try std.testing.expectEqual(@as(?usize, 0), client.subscription_replay_index);
    try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
}

test "MQTT reconnect assigned identity adoption rolls back every allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, adoptionFailure, .{threaded.io()});
}

fn replacementFailure(allocator: std.mem.Allocator, io: std.Io) !void {
    var shutdown: std.Io.Event = .unset;
    var client = try makeClient(allocator, io, &shutdown, "stable-id");
    defer client.deinit();
    const pending = try client.outgoing.beginImmediatePublish(client.outgoing_handle, "pending", "payload", .{ .qos = .exactly_once, .now = .zero }, 8);
    var fresh = identity.FreshSession.init(allocator, client.clientId(), .zero) catch |err| {
        try std.testing.expectEqualStrings("stable-id", client.clientId());
        try std.testing.expect((try client.outgoingQoSState(pending.packet_id)) != null);
        return err;
    };
    defer fresh.deinit();
    fresh.install(&client);
    try std.testing.expectEqualStrings("stable-id", client.clientId());
    try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
}

test "MQTT reconnect fresh Session allocation failure preserves the previous Store" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, replacementFailure, .{threaded.io()});
}

test "MQTT reconnect assigned identities must fit valid MQTT UTF8" {
    try std.testing.expectError(error.InvalidClientId, identity.clone(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidUtf8, identity.clone(std.testing.allocator, "bad\x00id"));
    const maximum = try std.testing.allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer std.testing.allocator.free(maximum);
    @memset(maximum, 'a');
    try std.testing.expectError(error.InvalidClientId, identity.clone(std.testing.allocator, maximum));
    const valid = try identity.clone(std.testing.allocator, maximum[0..std.math.maxInt(u16)]);
    defer std.testing.allocator.free(valid);
    try std.testing.expectEqual(@as(usize, std.math.maxInt(u16)), valid.len);
}
