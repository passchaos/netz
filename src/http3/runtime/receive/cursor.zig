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
        if (deadline.durationFromNow(connection.endpoint.io)
            .raw.nanoseconds <= 0) return error.Timeout;
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
