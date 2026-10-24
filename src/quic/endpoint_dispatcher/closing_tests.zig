const std = @import("std");
const quic = @import("../mod.zig");
const dispatcher_mod = @import("../endpoint_dispatcher.zig");
const closing = @import("../handshake/closing.zig");
const failure = @import("../handshake/failure.zig");

test "QUIC closing handshake preserves aliases and releases bounded capacity at expiry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer peer.deinit();
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    dispatcher.closing_handshake_capacity = 1;
    var inbox = try quic.handshake_inbox.Inbox.init(std.testing.allocator, threaded.io(), &.{ "closing-origin", "closing-server" }, peer.address(), 2);
    var inbox_owned = true;
    defer if (inbox_owned) inbox.deinit();
    try dispatcher.registerPendingHandshake(1, &inbox);
    var packet: ?closing.Packet = null;
    var budget: @import("../handshake/retransmit.zig").AntiAmplificationBudget = .{};
    budget.recordReceived(1200);
    const keys = quic.protection.deriveInitialSecrets("closing-origin");
    var close_state: failure.State = .{ .endpoint = &endpoint, .peer = peer.address(), .packet_type = .initial, .keys = keys.server, .version = 1, .destination_connection_id = "closing-client", .source_connection_id = "closing-server", .next_packet_number = 0, .anti_amplification = &budget, .closing_out = &packet };
    try close_state.send(0x178, "no ALPN");
    var first = try peer.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer first.deinit(std.testing.allocator);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        dispatcher.allocator = failing.allocator();
        defer dispatcher.allocator = std.testing.allocator;
        try std.testing.expect(dispatcher.closePendingHandshake(1, packet, std.time.ns_per_s));
    }
    try std.testing.expect(!failing.has_induced_failure);
    inbox.deinit();
    inbox_owned = false;
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.closingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 2), dispatcher.pending_router.count());
    var other = try quic.handshake_inbox.Inbox.init(std.testing.allocator, threaded.io(), &.{"other-origin"}, peer.address(), 2);
    defer other.deinit();
    try std.testing.expectError(error.PendingHandshakeLimitReached, dispatcher.registerPendingHandshake(2, &other));
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{UnexpectedPacket}!void {
            return error.UnexpectedPacket;
        }
    };
    var bytes: [1280]u8 = undefined;
    const payload = &.{@intFromEnum(quic.FrameType.ping)};
    const retry = try quic.protection.sealInitialPacketInto(&bytes, keys.client, .{ .destination_connection_id = "closing-server", .source_connection_id = "closing-client", .packet_number = 1, .payload = payload });
    {
        dispatcher.allocator = failing.allocator();
        defer dispatcher.allocator = std.testing.allocator;
        var event = try dispatcher.dispatchVisitingDatagram(.{ .from = peer.address(), .bytes = retry }, {}, Visitor.visit);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .consumed);
    }
    try std.testing.expect(!failing.has_induced_failure);
    var response = try peer.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, first.bytes, response.bytes);
    const expiry = dispatcher.nextTimerDeadline().?.timer.deadline_ns;
    _ = try dispatcher.serviceNextTimerAt(expiry);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.closingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pending_router.count());
    try std.testing.expect(dispatcher.nextTimerDeadline() == null);
    try dispatcher.registerPendingHandshake(2, &other);
    try std.testing.expect(try dispatcher.unregisterPendingHandshake(2));
}

test "QUIC closing handshake rate limit and amplification budget preserve the final packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer peer.deinit();
    var other = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer other.deinit();
    var packet: closing.Packet = .{ .len = 64, .bytes_received = 0, .bytes_sent = 0 };
    @memset(packet.bytes[0..packet.len], 0x5a);
    var state = closing.State.init(peer.address(), 1, packet, 0, 3 * std.time.ns_per_s);
    var request = [_]u8{0} ** 32;
    request[0] = 0xc0;
    std.mem.writeInt(u32, request[1..5], 1, .big);
    try state.receive(&endpoint, .{ .from = other.address(), .bytes = &request }, 0);
    try std.testing.expectEqual(@as(u64, 0), state.bytes_received);
    std.mem.writeInt(u32, request[1..5], 2, .big);
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = &request }, 0);
    try std.testing.expectEqual(@as(u64, 0), state.bytes_received);
    std.mem.writeInt(u32, request[1..5], 1, .big);
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = request[0..6] }, 0);
    try std.testing.expectEqual(@as(u64, 0), state.bytes_sent);
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = &request }, 0);
    var response = try peer.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, packet.slice(), response.bytes);
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = &request }, 1);
    try std.testing.expectEqual(@as(u64, 64), state.bytes_sent);
    try std.testing.expectError(error.Timeout, peer.receiveBytesWithTimeout(.fromMilliseconds(5)));
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = &request }, closing.minimum_response_interval_ns);
    var second = try peer.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, packet.slice(), second.bytes);
    try std.testing.expect(state.bytes_sent <= state.bytes_received * 3);
    const received_before_expiry = state.bytes_received;
    try state.receive(&endpoint, .{ .from = peer.address(), .bytes = &request }, state.deadline_ns);
    try std.testing.expectEqual(received_before_expiry, state.bytes_received);
}

test "QUIC closing handshake socket failure retains a response for the next permitted turn" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var packet: closing.Packet = .{ .len = 64, .bytes_received = 1200, .bytes_sent = 0 };
    @memset(packet.bytes[0..64], 0x5a);
    var state = closing.State.init(endpoint.address(), 1, packet, 0, std.time.ns_per_s);
    const FailedSend = struct {
        fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            return .{ error.SystemResources, 0 };
        }
    };
    const original = endpoint.io;
    var request = [_]u8{0x40};
    {
        var vtable = original.vtable.*;
        vtable.netSend = FailedSend.send;
        endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
        defer endpoint.io = original;
        try std.testing.expectError(error.SystemResources, state.receive(&endpoint, .{ .from = endpoint.address(), .bytes = &request }, 0));
        try std.testing.expectEqual(@as(u64, 0), state.bytes_sent);
    }
    try state.receive(&endpoint, .{ .from = endpoint.address(), .bytes = &request }, state.next_response_ns);
    var response = try endpoint.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, packet.slice(), response.bytes);
    try std.testing.expectEqual(@as(u64, 64), state.bytes_sent);
}

test "QUIC closing handshake batch receive consumes retries without new admissions" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer peer.deinit();
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(std.testing.allocator, threaded.io(), &.{ "batch-origin", "batch-server" }, peer.address(), 2);
    var inbox_owned = true;
    defer if (inbox_owned) inbox.deinit();
    try dispatcher.registerPendingHandshake(1, &inbox);
    var packet: closing.Packet = .{ .len = 64, .bytes_received = 1200, .bytes_sent = 0, .lifetime_ns = 3 * std.time.ns_per_s };
    @memset(packet.bytes[0..64], 0x5a);
    std.mem.writeInt(u32, packet.bytes[1..5], 1, .big);
    const before = std.Io.Clock.awake.now(threaded.io()).nanoseconds;
    try std.testing.expect(dispatcher.closePendingHandshake(1, packet, 1000));
    try std.testing.expect(dispatcher.nextTimerDeadline().?.timer.deadline_ns >= @as(u64, @intCast(before)) + 3 * std.time.ns_per_s);
    inbox.deinit();
    inbox_owned = false;
    var bytes: [1280]u8 = undefined;
    const keys = quic.protection.deriveInitialSecrets("batch-origin");
    for (0..3) |index| {
        const encoded = try quic.protection.sealInitialPacketInto(&bytes, keys.client, .{ .destination_connection_id = if (index == 1) "batch-server" else "batch-origin", .source_connection_id = "batch-client", .packet_number = @intCast(index), .payload = &.{1} });
        try peer.sendBytes(endpoint.address(), encoded);
    }
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{UnexpectedPacket}!void {
            return error.UnexpectedPacket;
        }
    };
    var storage: [196608]u8 = undefined;
    var events: [4]dispatcher_mod.VisitEvent = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .raw = .fromSeconds(1), .clock = .awake });
    var count: usize = 0;
    while (count != 3) {
        const received = try dispatcher.receiveManyVisitingWithDeadline(&.{1}, &storage, events[0 .. 3 - count], deadline, {}, Visitor.visit);
        for (events[0..received]) |*event| {
            defer event.deinit(std.testing.allocator);
            try std.testing.expect(event.* == .consumed);
        }
        count += received;
    }
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    var response = try peer.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, packet.slice(), response.bytes);
}

test "QUIC closing handshake peer close retains silent draining routes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var dispatcher = dispatcher_mod.Dispatcher.init(std.testing.allocator, &endpoint);
    defer dispatcher.deinit();
    var inbox = try quic.handshake_inbox.Inbox.init(std.testing.allocator, threaded.io(), &.{"drain-origin"}, endpoint.address(), 2);
    var inbox_owned = true;
    defer if (inbox_owned) inbox.deinit();
    try dispatcher.registerPendingHandshake(1, &inbox);
    try std.testing.expect(dispatcher.closePendingHandshake(1, null, std.time.ns_per_s));
    inbox.deinit();
    inbox_owned = false;
    var bytes: [1280]u8 = undefined;
    const encoded = try quic.protection.sealInitialPacketInto(&bytes, quic.protection.deriveInitialSecrets("drain-origin").client, .{ .destination_connection_id = "drain-origin", .source_connection_id = "drain-client", .packet_number = 0, .payload = &.{1} });
    const Visitor = struct {
        fn visit(_: void, _: dispatcher_mod.RoutedPacketView) error{UnexpectedPacket}!void {
            return error.UnexpectedPacket;
        }
    };
    var event = try dispatcher.dispatchVisitingDatagram(.{ .from = endpoint.address(), .bytes = encoded }, {}, Visitor.visit);
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .consumed);
    try std.testing.expectError(error.Timeout, endpoint.receiveBytesWithTimeout(.fromMilliseconds(5)));
}
