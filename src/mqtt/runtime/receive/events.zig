//! Shared event input policies and retained terminal-diagnostic ownership.
const std = @import("std");
const Pending = @import("../acknowledgement/pending.zig").State;
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Options = struct {
    deadline: ?std.Io.Clock.Timestamp = null,
    inactivity_timeout: ?std.Io.Clock.Duration = null,
    storage: ?[]u8 = null,
    prefix_len: usize = 0,
};

pub fn Reader(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;
        pub const Result = union(enum) {
            packet: Packet,
            disconnect: Context.DisconnectType,
        };

        pub fn read(connection: *Connection, options: Options) Error!Result {
            if (!Context.canReadBuffered(connection)) return error.ConnectionClosed;
            if (options.deadline) |deadline| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            if (connection.retained_disconnect.bytes != null) return .{ .disconnect = try retainedDisconnect(connection) };
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching({}, anyPacket)) |ready| {
                    if (ready.packet.fixed.packet_type == .disconnect) return .{ .disconnect = try disconnect(connection, ready) };
                    return .{ .packet = pending.takeMatch(ready.index) };
                }
            }
            if (!connection.isUsable()) return error.ConnectionClosed;
            var packet = try readTransport(connection, options);
            var owned = true;
            errdefer if (owned) packet.deinit(connection.allocator);
            Context.recordReceived(connection, packet.bytes.len);
            try Context.validate(connection, &packet);
            if (packet.fixed.packet_type != .disconnect) return .{ .packet = packet };
            // Terminal packets own their bytes. Retain them without allocating
            // queue state, preserving ordinary caller-buffer reads' zero-
            // allocation behavior while diagnostic decoding can be retried.
            connection.retained_disconnect.retain(packet);
            owned = false;
            return .{ .disconnect = try retainedDisconnect(connection) };
        }

        pub fn retainedDisconnect(connection: *Connection) Error!Context.DisconnectType {
            const packet = connection.retained_disconnect.packet().?;
            const value = Context.decodeDisconnect(connection, packet.bytes) catch |err| {
                if (err != error.OutOfMemory) {
                    var invalid = connection.retained_disconnect.take();
                    invalid.deinit(connection.allocator);
                }
                return err;
            };
            _ = connection.retained_disconnect.take();
            Context.finishDisconnect(connection);
            return .{ .packet = packet, .disconnect = value };
        }

        pub fn disconnect(connection: *Connection, ready: Pending.Match) Error!Context.DisconnectType {
            const value = Context.decodeDisconnect(connection, ready.packet.bytes) catch |err| {
                if (err != error.OutOfMemory) {
                    var packet = connection.pending_packets.?.takeMatch(ready.index);
                    packet.deinit(connection.allocator);
                }
                return err;
            };
            const packet = connection.pending_packets.?.takeMatch(ready.index);
            Context.finishDisconnect(connection);
            return .{ .packet = packet, .disconnect = value };
        }

        fn readTransport(connection: *Connection, options: Options) Error!Packet {
            const transport = &connection.transport;
            if (options.storage) |storage| {
                return if (options.inactivity_timeout) |timeout|
                    transport.readPacketWithInactivityTimeoutIntoWithPrefix(connection.allocator, connection.limits.max_packet_size, timeout, storage, options.prefix_len)
                else
                    transport.readPacketIntoWithPrefix(connection.allocator, connection.limits.max_packet_size, storage, options.prefix_len);
            }
            if (options.deadline) |deadline| return transport.readPacketWithDeadline(connection.allocator, connection.limits.max_packet_size, deadline);
            if (options.inactivity_timeout) |timeout| return transport.readPacketWithInactivityTimeout(connection.allocator, connection.limits.max_packet_size, timeout);
            return transport.readPacket(connection.allocator, connection.limits.max_packet_size);
        }

        fn anyPacket(_: void, _: Packet) bool {
            return true;
        }
    };
}
