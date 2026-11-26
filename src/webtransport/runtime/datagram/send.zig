const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const codec = @import("codec.zig");
const socket_budget = @import("socket_budget.zig");

pub const DevelopmentBatchScratch = struct {
    encoded_datagrams: std.ArrayList(u8) = .empty,
    frame_datagrams: std.ArrayList(u8) = .empty,

    pub fn deinit(
        self: *DevelopmentBatchScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.frame_datagrams.deinit(allocator);
        self.encoded_datagrams.deinit(allocator);
        self.* = undefined;
    }
};

pub const ProtectedBatchScratch = struct {
    encoded_datagrams: std.ArrayList(u8) = .empty,
    quic_payloads: std.ArrayList(u8) = .empty,
    protected_packets: std.ArrayList(u8) = .empty,

    pub fn deinit(
        self: *ProtectedBatchScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.protected_packets.deinit(allocator);
        self.quic_payloads.deinit(allocator);
        self.encoded_datagrams.deinit(allocator);
        self.* = undefined;
    }
};

pub fn developmentPayloadLimit(
    max_datagram_size: usize,
    session_id: webtransport.SessionId,
) ?usize {
    if (!session_id.isClientInitiatedBidirectional()) return null;
    const datagram_payload = maxDatagramFramePayloadSize(
        max_datagram_size,
    ) orelse return null;
    return webtransport.maxDatagramPayloadSize(
        datagram_payload,
        session_id,
    );
}

pub fn protectedPayloadLimit(
    max_datagram_size: usize,
    destination_connection_id_len: usize,
    packet_number: u64,
    session_id: webtransport.SessionId,
) ?usize {
    if (!session_id.isClientInitiatedBidirectional()) return null;
    const packet_overhead = quic.protection.shortPacketLenForPayloadLen(
        destination_connection_id_len,
        packet_number,
        4,
        0,
    ) catch return null;
    if (packet_overhead > max_datagram_size) return null;
    const datagram_payload = maxDatagramFramePayloadSize(
        max_datagram_size - packet_overhead,
    ) orelse return null;
    return webtransport.maxDatagramPayloadSize(
        datagram_payload,
        session_id,
    );
}

fn maxDatagramFramePayloadSize(frame_size: usize) ?usize {
    if (frame_size == 0) return null;
    var candidate = frame_size - 1;
    while (true) : (candidate -= 1) {
        const length_len = quic.varint.length(candidate) catch return null;
        if (candidate <= frame_size -| (1 + @as(usize, length_len))) {
            return candidate;
        }
        if (candidate == 0) return null;
    }
}

test "WebTransport DATAGRAM payload limits are exact across varint boundaries" {
    const session_ids = [_]webtransport.SessionId{
        .init(0),
        .init(63 * 4),
        .init(64 * 4),
        .init(16_383 * 4),
        .init(16_384 * 4),
    };
    for (session_ids) |session_id| {
        const prefix_len: usize = try quic.varint.length(
            session_id.quarterStreamId(),
        );
        var max_datagram_size: usize = 1;
        while (max_datagram_size <= 512) : (max_datagram_size += 1) {
            const limit = developmentPayloadLimit(
                max_datagram_size,
                session_id,
            );
            if (limit) |payload_len| {
                const encoded_len = prefix_len + payload_len;
                const wire_len = 1 +
                    @as(usize, try quic.varint.length(encoded_len)) +
                    encoded_len;
                try std.testing.expect(wire_len <= max_datagram_size);
                const larger_encoded_len = encoded_len + 1;
                const larger_wire_len = 1 +
                    @as(usize, try quic.varint.length(larger_encoded_len)) +
                    larger_encoded_len;
                try std.testing.expect(larger_wire_len > max_datagram_size);
            } else {
                const minimum_encoded_len = prefix_len + 1;
                const minimum_wire_len = 1 +
                    @as(usize, try quic.varint.length(minimum_encoded_len)) +
                    minimum_encoded_len;
                try std.testing.expect(minimum_wire_len > max_datagram_size);
            }

            const packet_number: u64 = 16_383;
            const protected_limit = protectedPayloadLimit(
                max_datagram_size,
                4,
                packet_number,
                session_id,
            );
            if (protected_limit) |payload_len| {
                const encoded_len = prefix_len + payload_len;
                const frame_len = 1 +
                    @as(usize, try quic.varint.length(encoded_len)) +
                    encoded_len;
                const packet_len = try quic.protection
                    .shortPacketLenForPayloadLen(
                    4,
                    packet_number,
                    4,
                    frame_len,
                );
                try std.testing.expect(packet_len <= max_datagram_size);
                const larger_encoded_len = encoded_len + 1;
                const larger_frame_len = 1 +
                    @as(usize, try quic.varint.length(larger_encoded_len)) +
                    larger_encoded_len;
                const larger_packet_len = try quic.protection
                    .shortPacketLenForPayloadLen(
                    4,
                    packet_number,
                    4,
                    larger_frame_len,
                );
                try std.testing.expect(larger_packet_len > max_datagram_size);
            }
        }
    }
}

pub fn development(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    return developmentUntil(
        endpoint,
        to,
        session_id,
        payload,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return err,
    };
}

pub fn developmentWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    return developmentUntil(endpoint, to, session_id, payload, deadline);
}

/// Encode and submit one ordered development-runtime DATAGRAM batch. All
/// inputs are validated before scratch growth or the first socket call.
pub fn developmentBatch(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *DevelopmentBatchScratch,
) !void {
    return developmentBatchUntil(
        endpoint,
        to,
        session_id,
        payloads,
        committed_count,
        scratch,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return err,
    };
}

pub fn developmentBatchWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *DevelopmentBatchScratch,
    deadline: std.Io.Clock.Timestamp,
) !void {
    committed_count.* = 0;
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    return developmentBatchUntil(
        endpoint,
        to,
        session_id,
        payloads,
        committed_count,
        scratch,
        deadline,
    );
}

fn developmentBatchUntil(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *DevelopmentBatchScratch,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    committed_count.* = 0;
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    if (payloads.len > quic.one_rtt.max_batch_packets) {
        return error.DatagramTooLarge;
    }
    if (payloads.len == 0) return;

    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    var encoded_len: usize = 0;
    var frame_len: usize = 0;
    for (payloads) |payload| {
        const item_len = std.math.add(usize, prefix_len, payload.len) catch
            return error.IntegerOverflow;
        encoded_len = std.math.add(usize, encoded_len, item_len) catch
            return error.IntegerOverflow;
        const item_frame_len = std.math.add(
            usize,
            1 + @as(usize, try quic.varint.length(item_len)),
            item_len,
        ) catch return error.InvalidFrameLength;
        if (item_frame_len > endpoint.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        frame_len = std.math.add(usize, frame_len, item_frame_len) catch
            return error.InvalidFrameLength;
    }

    try scratch.encoded_datagrams.resize(endpoint.allocator, encoded_len);
    try scratch.frame_datagrams.resize(endpoint.allocator, frame_len);
    var datagrams: [quic.one_rtt.max_batch_packets][]const u8 = undefined;
    var encoded_offset: usize = 0;
    var frame_offset: usize = 0;
    for (payloads, 0..) |payload, index| {
        const item_len = prefix_len + payload.len;
        const encoded = try codec.encodeInto(
            scratch.encoded_datagrams.items[encoded_offset..][0..item_len],
            session_id,
            payload,
        );
        const output = scratch.frame_datagrams.items[frame_offset..];
        var frame_list = std.ArrayList(u8).initBuffer(output);
        try (quic.Frame{ .datagram = .{
            .data = encoded,
            .length_present = true,
        } }).writeAssumeCapacity(&frame_list);
        datagrams[index] = frame_list.items;
        encoded_offset += item_len;
        frame_offset += frame_list.items.len;
    }
    std.debug.assert(encoded_offset == encoded_len);
    std.debug.assert(frame_offset == frame_len);

    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(endpoint.io, absolute);
    }
    try socket_budget.developmentBatch(endpoint, to, datagrams[0..payloads.len], committed_count, deadline);
}

fn developmentUntil(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    const encoded_len = std.math.add(usize, prefix_len, payload.len) catch
        return error.IntegerOverflow;
    const frame_len = std.math.add(
        usize,
        1 + @as(usize, try quic.varint.length(encoded_len)),
        encoded_len,
    ) catch return error.InvalidFrameLength;
    if (frame_len > endpoint.limits.max_datagram_size) {
        return error.DatagramTooLarge;
    }
    var stack: [codec.stack_capacity]u8 = undefined;
    var encoded = try codec.encodeStackFirst(
        endpoint.allocator,
        &stack,
        session_id,
        payload,
    );
    defer encoded.deinit(endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{
        .data = encoded.bytes,
        .length_present = true,
    } }};
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(endpoint.io, absolute);
    }
    try socket_budget.frames(endpoint, to, &frames, deadline);
}

test "WebTransport development DATAGRAM deadline rechecks before UDP send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const ExpiringIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        now_calls: usize = 0,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.now_calls += 1;
            const advance: i96 = if (self.now_calls == 1)
                0
            else
                std.time.ns_per_s;
            return .fromNanoseconds(self.now_ns + advance);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var expiring = ExpiringIo{ .delegate = sender.io };
    var vtable = sender.io.vtable.*;
    vtable.now = ExpiringIo.now;
    vtable.netSend = ExpiringIo.netSend;
    sender.io = .{ .userdata = &expiring, .vtable = &vtable };
    defer sender.io = expiring.delegate;

    const original_allocator = sender.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    const oversized = [_]u8{0xa5} ** 4096;
    try std.testing.expectError(
        error.DatagramTooLarge,
        development(
            &sender,
            receiver.address(),
            .init(0),
            &oversized,
        ),
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), expiring.send_calls);
    sender.allocator = original_allocator;

    try std.testing.expectError(
        error.Timeout,
        developmentWithDeadline(
            &sender,
            receiver.address(),
            .init(0),
            "not-sent",
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(expiring.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), expiring.now_calls);
    try std.testing.expectEqual(@as(usize, 0), expiring.send_calls);

    sender.io = expiring.delegate;
    try developmentWithDeadline(
        &sender,
        receiver.address(),
        .init(0),
        "sent",
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    var raw = try receiver.receiveWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer raw.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), raw.frames.len);
    try std.testing.expect(raw.frames[0] == .datagram);
    const decoded = try webtransport.Datagram.parse(raw.frames[0].datagram.data);
    try std.testing.expectEqual(@as(u62, 0), decoded.session_id.value);
    try std.testing.expectEqualStrings("sent", decoded.payload);
}

test "WebTransport development DATAGRAM batch commits only socket prefix" {
    const allocator = std.testing.allocator;
    const ObservedBatchSend =
        @import("../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128, .enable_gso_send = false },
    );
    defer sender.deinit();
    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    sender.io = partial.io();
    defer sender.io = partial.delegate;

    var scratch: DevelopmentBatchScratch = .{};
    defer scratch.deinit(allocator);
    var committed: usize = 99;
    var too_many: [quic.one_rtt.max_batch_packets + 1][]const u8 = undefined;
    @memset(&too_many, "x");
    try std.testing.expectError(
        error.DatagramTooLarge,
        developmentBatch(
            &sender,
            receiver.address(),
            .init(0),
            &too_many,
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.encoded_datagrams.capacity,
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.frame_datagrams.capacity);

    const oversized = [_]u8{0xaa} ** 128;
    try std.testing.expectError(
        error.DatagramTooLarge,
        developmentBatch(
            &sender,
            receiver.address(),
            .init(0),
            &.{ "valid", &oversized },
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.encoded_datagrams.capacity,
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.frame_datagrams.capacity);

    const payloads = [_][]const u8{ "one", "two", "three" };
    try std.testing.expectError(
        error.NetworkDown,
        developmentBatch(
            &sender,
            receiver.address(),
            .init(0),
            &payloads,
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expectEqual(@as(usize, 1), partial.calls);
    try std.testing.expectEqual(@as(usize, 3), partial.last_message_count);

    var first = try receiver.receiveWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer first.deinit(allocator);
    const first_datagram = try webtransport.Datagram.parse(
        first.frames[0].datagram.data,
    );
    try std.testing.expectEqualStrings("one", first_datagram.payload);

    sender.io = partial.delegate;
    var suffix_committed: usize = 99;
    try developmentBatch(
        &sender,
        receiver.address(),
        .init(0),
        payloads[committed..],
        &suffix_committed,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 2), suffix_committed);
    for ([_][]const u8{ "two", "three" }) |expected| {
        var packet = try receiver.receiveWithDeadline(.fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ));
        defer packet.deinit(allocator);
        const datagram = try webtransport.Datagram.parse(
            packet.frames[0].datagram.data,
        );
        try std.testing.expectEqualStrings(expected, datagram.payload);
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    var reused_committed: usize = 99;
    try developmentBatch(
        &sender,
        receiver.address(),
        .init(0),
        &payloads,
        &reused_committed,
        &scratch,
    );
    sender.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 3), reused_committed);
    try std.testing.expect(!failing.has_induced_failure);
}

pub fn protected(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
) !void {
    return protectedUntil(
        endpoint,
        to,
        keys,
        destination_connection_id,
        packet_number,
        session_id,
        payload,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return err,
    };
}

pub fn protectedWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    return protectedUntil(
        endpoint,
        to,
        keys,
        destination_connection_id,
        packet_number,
        session_id,
        payload,
        deadline,
    );
}

/// Encode, protect, and submit at most one transport batch. `committed_count`
/// counts the socket-visible input prefix, while `packet_number` advances over
/// every protected packet so an unsent encrypted suffix can never reuse a
/// nonce. All inputs are sized before the first socket call.
pub fn protectedBatch(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *ProtectedBatchScratch,
) !void {
    return protectedBatchUntil(
        endpoint,
        to,
        keys,
        destination_connection_id,
        packet_number,
        session_id,
        payloads,
        committed_count,
        scratch,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return err,
    };
}

pub fn protectedBatchWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *ProtectedBatchScratch,
    deadline: std.Io.Clock.Timestamp,
) !void {
    committed_count.* = 0;
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    return protectedBatchUntil(
        endpoint,
        to,
        keys,
        destination_connection_id,
        packet_number,
        session_id,
        payloads,
        committed_count,
        scratch,
        deadline,
    );
}

fn protectedBatchUntil(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payloads: []const []const u8,
    committed_count: *usize,
    scratch: *ProtectedBatchScratch,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    committed_count.* = 0;
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    if (payloads.len > quic.one_rtt.max_batch_packets) {
        return error.DatagramTooLarge;
    }
    if (payloads.len == 0) return;

    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    var encoded_len: usize = 0;
    var quic_payload_len: usize = 0;
    var protected_len: usize = 0;
    for (payloads, 0..) |payload, index| {
        const item_len = std.math.add(
            usize,
            prefix_len,
            payload.len,
        ) catch return error.IntegerOverflow;
        encoded_len = std.math.add(usize, encoded_len, item_len) catch
            return error.IntegerOverflow;
        const frame_len = std.math.add(
            usize,
            1 + @as(usize, try quic.varint.length(item_len)),
            item_len,
        ) catch return error.InvalidFrameLength;
        quic_payload_len = std.math.add(
            usize,
            quic_payload_len,
            frame_len,
        ) catch return error.InvalidFrameLength;
        const next_packet_number = std.math.add(
            u64,
            packet_number.*,
            std.math.cast(u64, index) orelse
                return error.InvalidPacketNumber,
        ) catch return error.InvalidPacketNumber;
        const packet_len = try quic.protection.shortPacketLenForPayloadLen(
            destination_connection_id.len,
            next_packet_number,
            4,
            frame_len,
        );
        if (packet_len > endpoint.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        protected_len = std.math.add(
            usize,
            protected_len,
            packet_len,
        ) catch return error.InvalidPayloadLength;
    }
    scratch.encoded_datagrams.clearRetainingCapacity();
    try scratch.encoded_datagrams.ensureTotalCapacityPrecise(
        endpoint.allocator,
        encoded_len,
    );
    scratch.encoded_datagrams.items.len = encoded_len;

    var frames: [quic.one_rtt.max_batch_packets]quic.Frame = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    var encoded_offset: usize = 0;
    for (payloads, 0..) |payload, index| {
        const item_len = prefix_len + payload.len;
        const encoded = try codec.encodeInto(
            scratch.encoded_datagrams.items[encoded_offset..][0..item_len],
            session_id,
            payload,
        );
        frames[index] = .{ .datagram = .{
            .data = encoded,
            .length_present = true,
        } };
        packets[index] = frames[index .. index + 1];
        encoded_offset += item_len;
    }
    std.debug.assert(encoded_offset == encoded_len);

    const options: quic.one_rtt.BatchSendOptions = .{
        .destination_connection_id = destination_connection_id,
        .first_packet_number = packet_number.*,
        .packets = packets[0..payloads.len],
    };
    try scratch.quic_payloads.resize(endpoint.allocator, quic_payload_len);
    try scratch.protected_packets.resize(endpoint.allocator, protected_len);
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(endpoint.io, absolute);
    }
    try socket_budget.protectedBatch(endpoint, to, keys, options, scratch.quic_payloads.items, scratch.protected_packets.items, packet_number, committed_count, deadline);
}

fn protectedUntil(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    const encoded_len = std.math.add(usize, prefix_len, payload.len) catch
        return error.IntegerOverflow;
    const frame_len = std.math.add(
        usize,
        1 + @as(usize, try quic.varint.length(encoded_len)),
        encoded_len,
    ) catch return error.InvalidFrameLength;
    const packet_len = try quic.protection.shortPacketLenForPayloadLen(
        destination_connection_id.len,
        packet_number.*,
        4,
        frame_len,
    );
    if (packet_len > endpoint.limits.max_datagram_size) {
        return error.DatagramTooLarge;
    }
    var datagram_stack: [codec.stack_capacity]u8 = undefined;
    var encoded = try codec.encodeStackFirst(
        endpoint.allocator,
        &datagram_stack,
        session_id,
        payload,
    );
    defer encoded.deinit(endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{
        .data = encoded.bytes,
        .length_present = true,
    } }};
    const options: quic.one_rtt.SendOptions = .{
        .destination_connection_id = destination_connection_id,
        .packet_number = packet_number.*,
        .frames = &frames,
    };
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(endpoint.io, absolute);
    try socket_budget.protectedOne(endpoint, to, keys, options, packet_number, deadline);
}

test "WebTransport protected DATAGRAM deadline rechecks before UDP send" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );

    const ExpiringIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        now_calls: usize = 0,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.now_calls += 1;
            const advance: i96 = if (self.now_calls == 1)
                0
            else
                std.time.ns_per_s;
            return .fromNanoseconds(
                self.now_ns + advance,
            );
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var expiring = ExpiringIo{ .delegate = sender.io };
    var vtable = sender.io.vtable.*;
    vtable.now = ExpiringIo.now;
    vtable.netSend = ExpiringIo.netSend;
    sender.io = .{ .userdata = &expiring, .vtable = &vtable };
    defer sender.io = expiring.delegate;

    var packet_number: u64 = 7;
    const original_allocator = sender.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    const oversized = [_]u8{0xa5} ** 4096;
    try std.testing.expectError(
        error.DatagramTooLarge,
        protected(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &oversized,
        ),
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), expiring.send_calls);
    try std.testing.expectEqual(@as(u64, 7), packet_number);
    sender.allocator = original_allocator;

    try std.testing.expectError(
        error.Timeout,
        protectedWithDeadline(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            "not-sent",
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(expiring.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), expiring.now_calls);
    try std.testing.expectEqual(@as(usize, 0), expiring.send_calls);
    try std.testing.expectEqual(@as(u64, 7), packet_number);

    sender.io = expiring.delegate;
    try protectedWithDeadline(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(0),
        "sent",
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(u64, 8), packet_number);
    var raw = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer raw.deinit(allocator);
    var packet = try quic.one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "receiver".len,
        7,
        4,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packet.frames.len);
    try std.testing.expect(packet.frames[0] == .datagram);
    const decoded = try webtransport.Datagram.parse(
        packet.frames[0].datagram.data,
    );
    try std.testing.expectEqual(@as(u62, 0), decoded.session_id.value);
    try std.testing.expectEqualStrings("sent", decoded.payload);
}

test "WebTransport lightweight protected DATAGRAM retires a sealed nonce after zero socket progress" {
    const allocator = std.testing.allocator;
    const ObservedBatchSend =
        @import("../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 8192 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 8192 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var failed = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 0,
    };
    sender.io = failed.io();
    defer sender.io = failed.delegate;

    var packet_number: u64 = 7;
    try std.testing.expectError(
        error.NetworkDown,
        protected(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            "first",
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), failed.calls);
    try std.testing.expectEqual(@as(u64, 8), packet_number);

    sender.io = failed.delegate;
    try protected(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(0),
        "retry",
    );
    try std.testing.expectEqual(@as(u64, 9), packet_number);

    var raw = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer raw.deinit(allocator);
    var received = try quic.one_rtt.openReceivedBytes(
        &receiver,
        raw.from,
        raw.bytes,
        keys,
        "receiver".len,
        8,
        4,
    );
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), received.packet.packet_number);
    const datagram = try webtransport.Datagram.parse(
        received.frames[0].datagram.data,
    );
    try std.testing.expectEqualStrings("retry", datagram.payload);

    // Exercise the allocating packet-storage branch as well. Encoding and
    // allocation finish before sealing, but a failed socket submission still
    // consumes packet number 9.
    const large_payload = [_]u8{0xed} ** (codec.stack_capacity + 128);
    sender.io = failed.io();
    try std.testing.expectError(
        error.NetworkDown,
        protected(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &large_payload,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), failed.calls);
    try std.testing.expectEqual(@as(u64, 10), packet_number);

    sender.io = failed.delegate;
    try protected(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(0),
        "after-large-failure",
    );
    try std.testing.expectEqual(@as(u64, 11), packet_number);
    var after_large_raw = try receiver.receiveBytesWithTimeout(.fromSeconds(1));
    defer after_large_raw.deinit(allocator);
    var after_large = try quic.one_rtt.openReceivedBytes(
        &receiver,
        after_large_raw.from,
        after_large_raw.bytes,
        keys,
        "receiver".len,
        10,
        4,
    );
    defer after_large.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 10),
        after_large.packet.packet_number,
    );
}

test "WebTransport lightweight protected DATAGRAM batch preserves nonce and socket prefix" {
    const allocator = std.testing.allocator;
    const ObservedBatchSend =
        @import("../../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdb} ** quic.protection.secret_len,
    );
    var partial = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    sender.io = partial.io();
    defer sender.io = partial.delegate;

    var scratch: ProtectedBatchScratch = .{};
    defer scratch.deinit(allocator);
    var packet_number: u64 = 7;
    var committed: usize = 99;

    var too_many: [quic.one_rtt.max_batch_packets + 1][]const u8 = undefined;
    @memset(&too_many, "x");
    try std.testing.expectError(
        error.DatagramTooLarge,
        protectedBatch(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &too_many,
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 7), packet_number);
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.encoded_datagrams.capacity,
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.quic_payloads.capacity);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.protected_packets.capacity,
    );

    const oversized = [_]u8{0xaa} ** 4096;
    try std.testing.expectError(
        error.DatagramTooLarge,
        protectedBatch(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &.{ "valid", &oversized },
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 7), packet_number);
    try std.testing.expectEqual(@as(usize, 0), partial.calls);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.encoded_datagrams.capacity,
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.quic_payloads.capacity);
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.protected_packets.capacity,
    );

    const payloads = [_][]const u8{ "one", "two", "three" };
    try std.testing.expectError(
        error.NetworkDown,
        protectedBatch(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &payloads,
            &committed,
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), committed);
    try std.testing.expectEqual(@as(u64, 10), packet_number);
    try std.testing.expectEqual(@as(usize, 1), partial.calls);
    try std.testing.expectEqual(@as(usize, 3), partial.last_message_count);

    var first_bytes = try receiver.receiveBytes();
    defer first_bytes.deinit(allocator);
    var first = try quic.one_rtt.openReceivedBytes(
        &receiver,
        first_bytes.from,
        first_bytes.bytes,
        keys,
        "receiver".len,
        7,
        4,
    );
    defer first.deinit(allocator);
    const first_datagram = try webtransport.Datagram.parse(
        first.frames[0].datagram.data,
    );
    try std.testing.expectEqualStrings("one", first_datagram.payload);

    sender.io = partial.delegate;
    var suffix_committed: usize = 99;
    try protectedBatch(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(0),
        payloads[committed..],
        &suffix_committed,
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 2), suffix_committed);
    try std.testing.expectEqual(@as(u64, 12), packet_number);

    for ([_][]const u8{ "two", "three" }, 10..) |expected, expected_pn| {
        var raw = try receiver.receiveBytes();
        defer raw.deinit(allocator);
        var received = try quic.one_rtt.openReceivedBytes(
            &receiver,
            raw.from,
            raw.bytes,
            keys,
            "receiver".len,
            expected_pn,
            4,
        );
        defer received.deinit(allocator);
        const datagram = try webtransport.Datagram.parse(
            received.frames[0].datagram.data,
        );
        try std.testing.expectEqualStrings(expected, datagram.payload);
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    var reused_committed: usize = 99;
    try protectedBatch(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(0),
        &payloads,
        &reused_committed,
        &scratch,
    );
    sender.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 3), reused_committed);
    try std.testing.expectEqual(@as(u64, 15), packet_number);
    try std.testing.expect(!failing.has_induced_failure);

    const AlwaysHold = struct {
        fn hold(_: *anyopaque, _: []const u8) bool {
            return true;
        }
    };
    var interceptor_context: u8 = 0;
    sender.limits.send_interceptor = .{
        .context = &interceptor_context,
        .should_hold = AlwaysHold.hold,
    };
    failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    sender.allocator = failing.allocator();
    var failed_committed: usize = 99;
    try std.testing.expectError(
        error.OutOfMemory,
        protectedBatch(
            &sender,
            receiver.address(),
            keys,
            "receiver",
            &packet_number,
            .init(0),
            &payloads,
            &failed_committed,
            &scratch,
        ),
    );
    sender.allocator = allocator;
    sender.limits.send_interceptor = null;
    try std.testing.expectEqual(@as(usize, 0), failed_committed);
    try std.testing.expectEqual(@as(u64, 18), packet_number);
    try std.testing.expect(failing.has_induced_failure);
}
