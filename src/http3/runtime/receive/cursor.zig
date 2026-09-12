const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");

const Error = runtime_error.Error;
const ReceiveTimeoutError = runtime_error.ReceiveTimeoutError;

/// Lazily drains one QUIC/GRO receive batch a packet at a time.
///
/// HTTP/3 stream readers intentionally observe only one packet before
/// returning control to the application. Retaining the unconsumed suffix here
/// preserves bounded DATA windows while amortizing receive and decryption.
pub const Connection = struct {
    batch: ?quic.one_rtt.ReceivedPacketBatch = null,
    ack_pending: bool = false,

    pub fn deinit(self: *Connection) void {
        if (self.batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    pub fn visit(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) Error!void {
        if (self.ack_pending) {
            try connection.sendAck(0);
            self.ack_pending = false;
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet_value| {
                var packet = packet_value;
                defer packet.deinit(connection.endpoint.allocator);
                return visitor(context, packetView(packet));
            }
            batch.deinit();
            self.batch = null;
        }
        if (!connection.endpoint.groReceiveEnabled()) {
            const Context = @TypeOf(context);
            const AdapterContext = struct {
                cursor: *Connection,
                connection: *quic.one_rtt.Connection,
                context: Context,
            };
            const Adapter = struct {
                fn visit(
                    adapter: *AdapterContext,
                    packet: quic.one_rtt.ReceivedPacketView,
                ) Error!void {
                    _ = adapter.connection.sendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch {
                        // QUIC and HTTP/3 state already accepted the packet.
                        // Retry a cumulative ACK before the next receive.
                        adapter.cursor.ack_pending = true;
                    };
                    try visitor(adapter.context, packet);
                }
            };
            var adapter: AdapterContext = .{
                .cursor = self,
                .connection = connection,
                .context = context,
            };
            return connection.visitPacketServicingTimers(
                &adapter,
                Adapter.visit,
            );
        }
        var batch = try connection.receivePacketBatchServicingTimers();
        errdefer batch.deinit();
        _ = connection.sendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch {
            self.ack_pending = true;
        };
        var packet = batch.takeNext() orelse return error.MissingStreamFrame;
        defer packet.deinit(connection.endpoint.allocator);
        self.batch = batch;
        return visitor(context, packetView(packet));
    }

    pub fn visitWithDeadline(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        // Validate before ACK emission or retained-GRO cursor advancement. An
        // expired or wrong-clock deadline is a side-effect-free operation.
        _ = try deadline_policy.usableAwake(
            connection.endpoint.io,
            deadline,
        );
        if (self.ack_pending) {
            try connection.sendAck(0);
            self.ack_pending = false;
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet_value| {
                var packet = packet_value;
                defer packet.deinit(connection.endpoint.allocator);
                return visitor(context, packetView(packet));
            }
            batch.deinit();
            self.batch = null;
        }
        if (connection.endpoint.groReceiveEnabled()) {
            return self.visitBatchWithDeadline(
                connection,
                deadline,
                context,
                visitor,
            );
        }

        const Context = @TypeOf(context);
        const AdapterContext = struct {
            cursor: *Connection,
            connection: *quic.one_rtt.Connection,
            context: Context,
        };
        const Adapter = struct {
            fn visit(
                adapter: *AdapterContext,
                packet: quic.one_rtt.ReceivedPacketView,
            ) Error!void {
                _ = adapter.connection.sendAckForPacketIfNeeded(
                    packet.packet_number,
                    packet.frames,
                ) catch {
                    adapter.cursor.ack_pending = true;
                };
                try visitor(adapter.context, packet);
            }
        };
        var adapter: AdapterContext = .{
            .cursor = self,
            .connection = connection,
            .context = context,
        };
        return connection.visitPacketServicingTimersDeadline(
            deadline,
            &adapter,
            Adapter.visit,
        );
    }

    fn visitBatchWithDeadline(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        var batch = try connection.receivePacketBatchServicingTimersDeadline(
            deadline,
        );
        errdefer batch.deinit();
        _ = connection.sendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch {
            self.ack_pending = true;
        };
        var packet = batch.takeNext() orelse return error.MissingStreamFrame;
        defer packet.deinit(connection.endpoint.allocator);
        self.batch = batch;
        return visitor(context, packetView(packet));
    }
};

pub fn packetView(
    packet: quic.one_rtt.ReceivedPacket,
) quic.one_rtt.ReceivedPacketView {
    return .{
        .from = packet.from,
        .packet_number = packet.packet.packet_number,
        .frames = packet.frames,
        .peer_initiated_key_update = packet.peer_initiated_key_update,
    };
}

test "HTTP/3 connection cursor deadline validation preserves retained batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x5a} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cursor-local",
        .peer_connection_id = "cursor-peer",
    });
    defer connection.deinit();

    const frames = try allocator.alloc(quic.Frame, 1);
    frames[0] = .{ .ping = {} };
    const packets = try allocator.alloc(quic.one_rtt.ReceivedPacket, 1);
    packets[0] = .{
        .from = endpoint.address(),
        .packet = .{
            .destination_connection_id = try allocator.dupe(
                u8,
                "cursor-local",
            ),
            .packet_number = 7,
            .fixed_bit = true,
            .spin_bit = false,
            .key_phase = false,
            .payload = try allocator.alloc(u8, 0),
        },
        .frames = frames,
    };
    var cursor = Connection{
        .batch = .{ .allocator = allocator, .packets = packets },
        .ack_pending = true,
    };
    defer cursor.deinit();

    const Visitor = struct {
        fn visit(count: *usize, packet: quic.one_rtt.ReceivedPacketView) Error!void {
            if (packet.packet_number != 7) return error.InvalidPacketNumber;
            count.* += 1;
        }
    };
    var visits: usize = 0;
    try std.testing.expectError(
        error.Timeout,
        cursor.visitWithDeadline(
            &connection,
            .{ .clock = .real, .raw = .zero },
            &visits,
            Visitor.visit,
        ),
    );
    try std.testing.expect(cursor.ack_pending);
    try std.testing.expectEqual(@as(usize, 0), visits);
    try std.testing.expectEqual(@as(usize, 0), cursor.batch.?.next_index);

    try std.testing.expectError(
        error.Timeout,
        cursor.visitWithDeadline(
            &connection,
            .{ .clock = .awake, .raw = .zero },
            &visits,
            Visitor.visit,
        ),
    );
    try std.testing.expect(cursor.ack_pending);
    try std.testing.expectEqual(@as(usize, 0), visits);
    try std.testing.expectEqual(@as(usize, 0), cursor.batch.?.next_index);

    cursor.ack_pending = false;
    try cursor.visitWithDeadline(
        &connection,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        &visits,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 1), visits);
    try std.testing.expectEqual(@as(usize, 1), cursor.batch.?.next_index);
}

/// Stateless-key counterpart used by the preconfigured protected runtime.
pub const Protected = struct {
    const Batch = struct {
        allocator: std.mem.Allocator,
        packets: []quic.one_rtt.ReceivedPacket,
        next_index: usize = 0,

        fn deinit(self: *Batch) void {
            for (self.packets[self.next_index..]) |*packet| {
                packet.deinit(self.allocator);
            }
            self.allocator.free(self.packets);
            self.* = undefined;
        }

        fn takeNext(self: *Batch) ?quic.one_rtt.ReceivedPacket {
            if (self.next_index == self.packets.len) return null;
            const packet = self.packets[self.next_index];
            self.next_index += 1;
            return packet;
        }
    };

    batch: ?Batch = null,

    pub fn deinit(self: *Protected) void {
        if (self.batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    pub fn take(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
    ) Error!quic.one_rtt.ReceivedPacket {
        return self.takeUntil(
            endpoint,
            keys,
            destination_connection_id_len,
            expected_packet_number,
            max_frames,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn takeWithDeadline(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.ReceivedPacket {
        _ = try deadline_policy.usableAwake(endpoint.io, deadline);
        return self.takeUntil(
            endpoint,
            keys,
            destination_connection_id_len,
            expected_packet_number,
            max_frames,
            .{ .deadline = deadline },
        );
    }

    fn takeUntil(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
        timeout: ?std.Io.Timeout,
    ) ReceiveTimeoutError!quic.one_rtt.ReceivedPacket {
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet| {
                expected_packet_number.* = packet.packet.packet_number + 1;
                return packet;
            }
            batch.deinit();
            self.batch = null;
        }

        if (!endpoint.groReceiveEnabled()) {
            var datagram = if (timeout) |bounded|
                try endpoint.receiveBytesTimeout(bounded)
            else
                try endpoint.receiveBytes();
            defer datagram.deinit(endpoint.allocator);
            const packet = try quic.one_rtt.openReceivedBytes(
                endpoint,
                datagram.from,
                datagram.bytes,
                keys,
                destination_connection_id_len,
                expected_packet_number.*,
                max_frames,
            );
            expected_packet_number.* = packet.packet.packet_number + 1;
            return packet;
        }
        var datagrams = if (timeout) |bounded|
            try endpoint.receiveBytesBatchTimeout(bounded)
        else
            try endpoint.receiveBytesBatch();
        defer datagrams.deinit(endpoint.allocator);
        const packets = try endpoint.allocator.alloc(
            quic.one_rtt.ReceivedPacket,
            datagrams.segment_count,
        );
        var completed: usize = 0;
        errdefer {
            for (packets[0..completed]) |*packet| {
                packet.deinit(endpoint.allocator);
            }
            endpoint.allocator.free(packets);
        }
        var next_expected = expected_packet_number.*;
        for (packets, 0..) |*packet, index| {
            const bytes = datagrams.datagramAt(index) orelse
                return error.InvalidPacket;
            packet.* = try quic.one_rtt.openReceivedBytes(
                endpoint,
                datagrams.from,
                bytes,
                keys,
                destination_connection_id_len,
                next_expected,
                max_frames,
            );
            next_expected = packet.packet.packet_number + 1;
            completed += 1;
        }
        var batch = Batch{
            .allocator = endpoint.allocator,
            .packets = packets,
        };
        const packet = batch.takeNext() orelse return error.MissingStreamFrame;
        expected_packet_number.* = packet.packet.packet_number + 1;
        self.batch = batch;
        return packet;
    }
};
