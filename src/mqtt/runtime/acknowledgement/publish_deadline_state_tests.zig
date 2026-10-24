const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pending = @import("pending.zig").State;
const Transport = @import("../packet_transport.zig").Transport;

const allocator = std.testing.allocator;

const ExpiringClock = struct {
    calls: usize = 0,
    valid_calls: usize = 1,

    fn now(userdata: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        self.calls += 1;
        return .fromNanoseconds(if (self.calls <= self.valid_calls) 0 else std.time.ns_per_s);
    }
};

fn borrowed(bytes: []const u8) runtime.OwnedPacket {
    return .{ .bytes = @constCast(bytes), .fixed = mqtt.FixedHeader.parse(bytes) catch unreachable, .owns_bytes = false };
}

test "MQTT publish deadline before PUBREL preserves the accepted PUBREC for retry" {
    for ([_]bool{ false, true }) |queued| {
        for ([_]bool{ false, true }) |repeated| try expiryAtPubRel(queued, repeated);
    }
}

fn expiryAtPubRel(queued: bool, repeated: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);
    var clock: ExpiringClock = .{ .valid_calls = if (queued) 1 else 2 };
    var vtable = io.vtable.*;
    vtable.now = ExpiringClock.now;
    const observed_io = std.Io{ .userdata = &clock, .vtable = &vtable };
    var client = runtime.Connection{ .allocator = allocator, .transport = .initTcp(observed_io, sender), .outgoing_inflight = 1 };
    defer client.packet_identifiers.deinit(allocator);
    const stage: @import("../packet_identifiers.zig").State.Stage = if (repeated) .outgoing_qos2_pubrel else .outgoing_qos2;
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, stage));
    const pending = try allocator.create(Pending);
    defer allocator.destroy(pending);
    pending.* = .{};
    defer pending.deinit(allocator);
    client.pending_packets = pending;
    const ack = "\x50\x0a\x00\x2a\x00\x06\x1f\x00\x03yes";
    if (queued) {
        try pending.append(allocator, borrowed(ack), 2, 100);
        // A preexisting overflow slot must remain intact when the accepted
        // PUBREC is retained at its original ordinary-queue position.
        pending.retainOverflow(borrowed("\x30\x05\x00\x01x\x001"));
    } else {
        @memcpy(client.transport.tcp.input[0..ack.len], ack);
        client.transport.tcp.input_end = ack.len;
    }
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(50 * std.time.ns_per_ms) };
    if (repeated) try std.testing.expectError(error.Timeout, client.completePublishPubCompWithDeadline(42, deadline)) else try std.testing.expectError(error.Timeout, client.completePublishPubRecWithDeadline(42, deadline));
    try std.testing.expectEqual(clock.valid_calls + 1, clock.calls);
    try std.testing.expect(client.isUsable());
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expect(client.packet_identifiers.contains(42, stage));
    try std.testing.expectEqual(@as(usize, if (queued) 2 else 1), pending.count());
    if (queued) try std.testing.expectEqual(@as(usize, ack.len), pending.queued_bytes);

    client.transport.tcp.io = io;
    if (repeated) {
        if (!queued) {
            // Move the retained emergency ACK into ordinary queue storage
            // before admitting the peer's subsequent final PUBCOMP.
            const retained = pending.pop().?;
            try pending.append(allocator, retained, 2, 100);
        }
        var writer = receiver.writer(io, &.{});
        try writer.interface.writeAll("\x70\x02\x00\x2a");
        // The existing application overflow does not prevent retrying the
        // accepted control packet; the final ACK waits until it is drained.
        if (queued) {
            var application = pending.overflow.?;
            pending.overflow = null;
            application.deinit(allocator);
        }
        try client.completePublishPubCompWithTimeout(42, .fromSeconds(1));
        try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    } else {
        try std.testing.expectEqual(@as(u16, 42), try client.completePublishPubRecWithTimeout(42, .fromSeconds(1)));
        try std.testing.expect(client.packet_identifiers.contains(42, .outgoing_qos2_pubrel));
    }
    var transport = Transport.initTcp(io, receiver);
    var sent = try transport.readPacketWithDeadline(allocator, 16, transport.deadlineFromNow(.fromSeconds(1)));
    defer sent.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "\x62\x02\x00\x2a", sent.bytes);
}

test "MQTT publish expired deadline leaves queued ACK and identifier state unchanged" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var client = runtime.Connection{ .allocator = allocator, .transport = .initTcp(threaded.io(), undefined), .outgoing_inflight = 1 };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
    var pending: Pending = .{};
    defer pending.deinit(allocator);
    client.pending_packets = &pending;
    try pending.append(allocator, borrowed("\x40\x02\x00\x2a"), 1, 4);
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    try std.testing.expectError(error.Timeout, client.completePublishPubAckWithDeadline(42, expired));
    try std.testing.expectEqual(@as(usize, 1), pending.count());
    try std.testing.expectEqual(@as(usize, 4), pending.queued_bytes);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expectEqual(@as(u16, 1), client.next_packet_id);
    var progress: runtime.PublishProgress = .{};
    try std.testing.expectError(error.Timeout, client.publishWithDeadline("x", "y", .{ .qos = .at_least_once }, &progress, expired));
    try std.testing.expect(!progress.publish_sent);
    try std.testing.expect(progress.packet_id == null);
}

test "MQTT publish deadline also bounds interleaved packets already buffered by transport" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var clock: ExpiringClock = .{ .valid_calls = 2 };
    var vtable = io.vtable.*;
    vtable.now = ExpiringClock.now;
    const observed_io = std.Io{ .userdata = &clock, .vtable = &vtable };
    var client = runtime.Connection{ .allocator = allocator, .transport = .initTcp(observed_io, undefined), .outgoing_inflight = 1 };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
    const pending = try allocator.create(Pending);
    defer allocator.destroy(pending);
    pending.* = .{};
    defer pending.deinit(allocator);
    client.pending_packets = pending;
    const bytes = "\x30\x05\x00\x01x\x001\x40\x02\x00\x2a";
    @memcpy(client.transport.tcp.input[0..bytes.len], bytes);
    client.transport.tcp.input_end = bytes.len;
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(50 * std.time.ns_per_ms) };
    try std.testing.expectError(error.Timeout, client.completePublishPubAckWithDeadline(42, deadline));
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expectEqual(@as(usize, 1), pending.count());
    client.transport.tcp.io = io;
    try client.completePublishPubAckWithTimeout(42, .fromSeconds(1));
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    var incoming = try client.readPublish();
    defer incoming.deinit(allocator);
    try std.testing.expectEqualStrings("1", incoming.publish.payload);
}

test "MQTT publish budget reserves pending storage before PUBLISH is submitted" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var client = runtime.Connection{ .allocator = failing.allocator(), .transport = .initTcp(threaded.io(), undefined) };
    var progress: runtime.PublishProgress = .{};
    try std.testing.expectError(error.OutOfMemory, client.publishWithTimeout("x", "y", .{ .qos = .at_least_once }, &progress, .fromSeconds(1)));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(!progress.publish_sent);
    try std.testing.expect(progress.packet_id == null);
    try std.testing.expect(client.pending_packets == null);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try std.testing.expectEqual(@as(u16, 1), client.next_packet_id);
}
