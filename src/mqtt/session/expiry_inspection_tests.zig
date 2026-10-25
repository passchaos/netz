const std = @import("std");
const session = @import("mod.zig");

test "session Message Expiry inspection preserves ownership and excludes accepted QoS2 release" {
    var store = session.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const opened = try store.open("inspect-expiry", false, 60, .zero);
    const publish = try store.beginImmediatePublish(opened.handle, "topic", "payload", .{
        .qos = .exactly_once,
        .now = .zero,
        .properties = &.{.{ .four_byte = .{ .id = .message_expiry_interval, .value = 1 } }},
    }, 8);
    const before: std.Io.Timestamp = .fromNanoseconds(std.time.ns_per_s - 1);
    const expired: std.Io.Timestamp = .fromNanoseconds(std.time.ns_per_s);
    try std.testing.expect(!try store.outgoingPublishExpired(opened.handle, publish.packet_id, before));
    try std.testing.expect(try store.outgoingPublishExpired(opened.handle, publish.packet_id, expired));
    try std.testing.expectEqual(@as(usize, 1), (try store.stats(opened.handle)).inflight_count);
    _ = try store.handleAck(opened.handle, .pubrec, publish.packet_id, 0);
    try std.testing.expect(!try store.outgoingPublishExpired(opened.handle, publish.packet_id, expired));
    try std.testing.expectEqual(session.OutgoingQoSState.await_pubcomp, (try store.outgoingQoSState(opened.handle, publish.packet_id)).?);
    var transmissions: [1]session.Transmission = undefined;
    const remaining = try store.drainInto(opened.handle, expired, 8, &transmissions);
    try std.testing.expectEqual(@as(usize, 1), remaining.len);
    try std.testing.expect(remaining[0] == .pubrel);
    try std.testing.expect(!try store.outgoingPublishExpired(opened.handle, 77, expired));
}
