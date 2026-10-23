const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const support = @import("../session_control/test_support/handshake_pair.zig");
const Pair = support.Pair;
const Role = support.Role;

fn opposite(role: Role) Role {
    return if (role == .client) .server else .client;
}

fn open(pair: *Pair, role: Role, direction: webtransport.StreamDirection) !u62 {
    return switch (role) {
        .client => if (direction == .bidirectional) pair.client.openBidirectionalStream() else pair.client.openUnidirectionalStream(),
        .server => if (direction == .bidirectional) pair.server.openBidirectionalStream() else pair.server.openUnidirectionalStream(),
    };
}

fn send(pair: *Pair, role: Role, id: u62, payload: []const u8, fin: bool) !void {
    switch (role) {
        .client => try pair.client.sendStream(id, payload, fin),
        .server => try pair.server.sendStream(id, payload, fin),
    }
}

fn reset(pair: *Pair, role: Role, id: u62) !void {
    switch (role) {
        .client => try pair.client.resetStream(id, 71),
        .server => try pair.server.resetStream(id, 71),
    }
}

fn wait(pair: *Pair, role: Role, id: u62, timeout: std.Io.Duration, absolute: bool) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(role).endpoint.io, .{ .raw = timeout, .clock = .awake });
    switch (role) {
        .client => if (absolute) try pair.client.waitForStreamRecoveryIdleWithDeadline(id, deadline) else try pair.client.waitForStreamRecoveryIdleWithTimeout(id, timeout),
        .server => if (absolute) try pair.server.waitForStreamRecoveryIdleWithDeadline(id, deadline) else try pair.server.waitForStreamRecoveryIdleWithTimeout(id, timeout),
    }
}

fn ack(pair: *Pair, role: Role, first: u64, end: u64) !void {
    try std.testing.expect(end > first);
    try pair.connection(opposite(role)).send(&.{.{ .ack = .{
        .largest_acknowledged = end - 1,
        .ack_delay = 0,
        .first_ack_range = end - first - 1,
        .ranges = &.{},
    } }});
}

test "WebTransport stream recovery wait excludes sibling DATA FIN and RESET" {
    for (std.enums.values(Role)) |role| {
        for ([_]webtransport.StreamDirection{ .bidirectional, .unidirectional }) |direction| {
            for ([_]bool{ false, true }) |reset_target| {
                for ([_]bool{ false, true }) |absolute| try isolation(role, direction, reset_target, absolute);
            }
        }
    }
}

fn isolation(role: Role, direction: webtransport.StreamDirection, reset_target: bool, absolute: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const connection = pair.connection(role);
    const first = connection.next_packet_number;
    const target = try open(&pair, role, direction);
    try send(&pair, role, target, "target", !reset_target);
    if (reset_target) try reset(&pair, role, target);
    const end = connection.next_packet_number;
    const sibling = try open(&pair, role, direction);
    try send(&pair, role, sibling, "sibling", true);
    const inbound = try open(&pair, opposite(role), .bidirectional);
    try send(&pair, opposite(role), inbound, "inbound", false);
    try std.testing.expect(connection.pendingStreamDeliveryRecovery(target));
    try std.testing.expect(connection.pendingStreamDeliveryRecovery(sibling));
    try ack(&pair, role, first, end);
    try wait(&pair, role, target, .fromSeconds(1), absolute);
    try std.testing.expect(!connection.pendingStreamDeliveryRecovery(target));
    try std.testing.expect(connection.pendingStreamDeliveryRecovery(sibling));
    try std.testing.expect(connection.pendingDeliveryRecovery());
    var output: [16]u8 = undefined;
    const event = switch (role) {
        .client => try pair.client.readStreamWithTimeout(&output, .fromSeconds(1)),
        .server => try pair.server.readStreamWithTimeout(&output, .fromSeconds(1)),
    };
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(inbound, event.data.stream_id);
    try std.testing.expectEqualStrings("inbound", output[0..event.data.bytes]);
}

test "WebTransport stream recovery timeout remains retryable for only that stream" {
    for (std.enums.values(Role)) |role| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const connection = pair.connection(role);
        const first = connection.next_packet_number;
        const target = try open(&pair, role, .bidirectional);
        try send(&pair, role, target, "retry", true);
        const end = connection.next_packet_number;
        try std.testing.expectError(error.Timeout, wait(&pair, role, target, .fromMilliseconds(10), false));
        try std.testing.expect(connection.pendingStreamDeliveryRecovery(target));
        try ack(&pair, role, first, end);
        try wait(&pair, role, target, .fromSeconds(1), true);
        try std.testing.expect(!connection.pendingStreamDeliveryRecovery(target));
    }
}

test "WebTransport stream recovery validates ownership clock and reader before progress" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const before = pair.connection(.client).next_packet_number;
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .raw = .fromSeconds(1), .clock = .awake });
    try std.testing.expectError(error.UnknownStream, pair.client.waitForStreamRecoveryIdleWithDeadline(100, deadline));
    try std.testing.expectError(error.Timeout, pair.client.waitForStreamRecoveryIdleWithTimeout(100, .zero));
    try std.testing.expectError(error.Timeout, pair.client.waitForStreamRecoveryIdleWithDeadline(100, .{ .raw = .zero, .clock = .real }));
    pair.client.h3.callback_reader_active = true;
    try std.testing.expectError(error.ConcurrentRead, pair.client.waitForStreamRecoveryIdleWithDeadline(100, deadline));
    pair.client.h3.callback_reader_active = false;
    const peer_uni = try pair.server.openUnidirectionalStream();
    try pair.server.sendStream(peer_uni, "peer", false);
    var output: [8]u8 = undefined;
    _ = try pair.client.readStreamWithDeadline(&output, deadline);
    try std.testing.expectError(error.InvalidStreamState, pair.client.waitForStreamRecoveryIdleWithDeadline(peer_uni, deadline));
    const after = pair.connection(.client).next_packet_number;
    pair.client.dispatcher = @ptrFromInt(@alignOf(quic.endpoint_dispatcher.Dispatcher));
    defer pair.client.dispatcher = null;
    try std.testing.expectError(error.InvalidDispatcherState, pair.client.waitForStreamRecoveryIdleWithDeadline(100, deadline));
    try std.testing.expectEqual(after, pair.connection(.client).next_packet_number);
    try std.testing.expect(after >= before);
}

const DropOnce = struct {
    delegate: std.Io,
    dropped: bool = false,

    fn netSend(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        if (!self.dropped) {
            self.dropped = true;
            return .{ null, messages.len };
        }
        return self.delegate.vtable.netSend(self.delegate.userdata, socket, messages, flags);
    }
};

test "WebTransport stream recovery wait drives PTO after target packet loss" {
    for (std.enums.values(Role)) |role| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const connection = pair.connection(role);
        const target = try open(&pair, role, .unidirectional);
        const original_io = connection.endpoint.io;
        var drop = DropOnce{ .delegate = original_io };
        var vtable = original_io.vtable.*;
        vtable.netSend = DropOnce.netSend;
        connection.endpoint.io = .{ .userdata = &drop, .vtable = &vtable };
        defer connection.endpoint.io = original_io;
        try send(&pair, role, target, "recover", true);
        const sent_before_wait = connection.next_packet_number;
        const Peer = struct {
            pair: *Pair,
            role: Role,
            target: u62,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.receive() catch |err| {
                    self.err = err;
                };
            }

            fn receive(self: *@This()) !void {
                var output: [32]u8 = undefined;
                var count: usize = 0;
                const deadline = std.Io.Clock.Timestamp.fromNow(self.pair.connection(self.role).endpoint.io, .{ .raw = .fromSeconds(3), .clock = .awake });
                while (true) {
                    const event = switch (self.role) {
                        .client => try self.pair.client.readStreamWithDeadline(output[count..], deadline),
                        .server => try self.pair.server.readStreamWithDeadline(output[count..], deadline),
                    };
                    if (event != .data or event.data.stream_id != self.target) return error.TestUnexpectedResult;
                    count += event.data.bytes;
                    if (event.data.fin) break;
                }
                try std.testing.expectEqualStrings("recover", output[0..count]);
                try self.pair.connection(self.role).sendAck(0);
            }
        };
        var peer = Peer{ .pair = &pair, .role = opposite(role), .target = target };
        const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
        var joined = false;
        defer if (!joined) thread.join();
        try wait(&pair, role, target, .fromSeconds(3), true);
        thread.join();
        joined = true;
        if (peer.err) |err| return err;
        try std.testing.expect(drop.dropped);
        try std.testing.expect(connection.next_packet_number > sent_before_wait);
        try std.testing.expect(!connection.pendingStreamDeliveryRecovery(target));
    }
}
