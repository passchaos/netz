//! Small journal fixtures shared by coordinator and real-wire expiry tests.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const coordinator = @import("outbound_coordinator.zig");
const codec = @import("../persistence/codec.zig");

pub const identity = [_]u8{0x71} ** 32;
pub const path = "expiry.log";

pub fn client(allocator: std.mem.Allocator, io: std.Io, shutdown: *std.Io.Event, id: []const u8, lifetime: u32) !reconnect.Client {
    return reconnect.Client.initWithOptions(allocator, io, .{ .ip4 = .loopback(1) }, .{
        .client_id = id,
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = lifetime } }},
    }, .{}, shutdown, .{ .manual_acknowledgements = true, .inbound_qos2_release_policy = .deferred });
}

pub fn stage(source: *reconnect.Client, target: *reconnect.Client, store: *coordinator.Store, phase: coordinator.Phase) !void {
    return stageWithExpiry(source, target, store, phase, null);
}

pub fn stageWithExpiry(source: *reconnect.Client, target: *reconnect.Client, store: *coordinator.Store, phase: coordinator.Phase, expiry: ?u32) !void {
    const expiry_property = [_]mqtt.Property{.{ .four_byte = .{ .id = .message_expiry_interval, .value = expiry orelse 0 } }};
    const properties: []const mqtt.Property = if (expiry != null) &expiry_property else &.{};
    _ = try source.outgoing.recordIncomingQoS2(source.outgoing_handle, 77);
    const publish = try target.outgoing.beginImmediatePublish(target.outgoing_handle, "target/topic", "old", .{
        .qos = .exactly_once,
        .now = std.Io.Clock.awake.now(target.io),
        .properties = properties,
    }, 8);
    const reason: u8 = if (phase == .target_rejected) 0x87 else 0;
    if (phase != .target_await_pubrec) _ = try target.outgoing.handleAck(target.outgoing_handle, .pubrec, publish.packet_id, reason);
    if (phase == .target_complete) _ = try target.outgoing.handleAck(target.outgoing_handle, .pubcomp, publish.packet_id, 0);
    _ = try store.commit(source, target, 1, 1, .{
        .phase = phase,
        .source_session_epoch = 1,
        .target_session_epoch = 1,
        .source_packet_id = 77,
        .target_packet_id = publish.packet_id,
        .target_reason_code = reason,
        .source_retain = false,
        .source_topic = "source/topic",
        .source_payload = "old",
        .source_properties = properties,
        .source_expiry_interval = expiry,
    });
}

pub fn writeJournal(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, shutdown: *std.Io.Event, source_lifetime: u32, target_lifetime: u32, phase: coordinator.Phase) !void {
    var source = try client(allocator, io, shutdown, "expiry-source", source_lifetime);
    defer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "desired/#", .qos = .exactly_once }, &.{});
    var target = try client(allocator, io, shutdown, "expiry-target", target_lifetime);
    defer target.deinit();
    var store = try coordinator.Store.create(allocator, io, dir, path, .{}, identity, &source, &target);
    defer store.deinit();
    try stage(&source, &target, &store, phase);
}

/// Keep every CRC valid while breaking the cross-record Packet Identifier
/// binding. This must still be rejected when Session expiry prunes markers.
pub fn corruptSourceId(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    var log = try @import("../persistence/commit_log.zig").Log.open(allocator, io, dir, path, .{});
    defer log.deinit();
    const bytes = try log.latestAlloc();
    defer allocator.free(bytes);
    var cursor = codec.Cursor.init(bytes[0 .. bytes.len - 4]);
    try cursor.inner.skip("netz-mqtt-outbound-bridge\x00".len + 4 + 32 + 16);
    _ = try cursor.readBlob();
    _ = try cursor.readBlob();
    try std.testing.expect(try cursor.readBool());
    try cursor.inner.skip(1 + 16);
    std.mem.writeInt(u16, bytes[cursor.inner.pos..][0..2], 78, .big);
    std.mem.writeInt(u32, bytes[bytes.len - 4 ..][0..4], std.hash.crc.Crc32.hash(bytes[0 .. bytes.len - 4]), .big);
    _ = try log.append(bytes);
}

pub fn futureTime(io: std.Io) std.Io.Timestamp {
    return .fromNanoseconds(std.Io.Clock.real.now(io).nanoseconds + 2 * std.time.ns_per_s);
}
