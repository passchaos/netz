//! Shared event input policies and retained terminal-diagnostic ownership.
const std = @import("std");
const Pending = @import("../acknowledgement/pending.zig").State;
const deadline_policy = @import("../../../internal/deadline.zig");
const packet_transport = @import("../packet_transport.zig");

pub const Options = struct {
    deadline: ?std.Io.Clock.Timestamp = null,
    inactivity_timeout: ?std.Io.Clock.Duration = null,
    inactivity_observer: ?packet_transport.InactivityObserver = null,
    storage: ?[]u8 = null,
    prefix_len: usize = 0,
};

pub fn Reader(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Packet = Context.PacketType;
        const Error = Context.ErrorType;
        pub const Input = struct {
            packet: Packet,
            source: union(enum) { retained, queued: usize, caller },

            pub fn commit(self: Input, connection: *Connection) void {
                switch (self.source) {
                    .retained => _ = connection.retained_receive.take(),
                    .queued => |index| _ = connection.pending_packets.?.takeMatch(index),
                    .caller => {},
                }
            }

            pub fn reject(self: Input, connection: *Connection, err: anyerror) void {
                if (err == error.OutOfMemory) {
                    if (self.source == .caller) connection.transport.restoreBorrowedPacket(self.packet);
                    return;
                }
                self.commit(connection);
                var packet = self.packet;
                packet.deinit(connection.allocator);
            }
        };
        pub const Result = union(enum) {
            packet: Input,
            disconnect: Context.DisconnectType,
        };

        pub fn read(connection: *Connection, options: Options) Error!Result {
            if (!Context.canReadBuffered(connection)) return error.ConnectionClosed;
            if (options.deadline) |deadline| _ = try deadline_policy.usableAwake(connection.transport.ioHandle(), deadline);
            if (connection.retained_receive.packet()) |packet| {
                if (packet.fixed.packet_type == .disconnect) return .{ .disconnect = try retainedDisconnect(connection) };
                return .{ .packet = .{ .packet = packet, .source = .retained } };
            }
            if (connection.pending_packets) |pending| {
                if (pending.findFirstMatching({}, anyPacket)) |ready| {
                    if (ready.packet.fixed.packet_type == .disconnect) return .{ .disconnect = try disconnect(connection, ready) };
                    return .{ .packet = .{ .packet = ready.packet, .source = .{ .queued = ready.index } } };
                }
            }
            if (!connection.isUsable()) return error.ConnectionClosed;
            var packet = try readTransport(connection, options);
            var owned = true;
            errdefer if (owned) packet.deinit(connection.allocator);
            if (!packet.traffic_recorded) Context.recordReceived(connection, packet.bytes.len);
            packet.traffic_recorded = true;
            try Context.validate(connection, &packet, options.deadline);
            if (!packet.owns_bytes) {
                owned = false;
                return .{ .packet = .{ .packet = packet, .source = .caller } };
            }
            // Inline ownership avoids an event-path queue allocation. Both
            // ordinary and terminal decoders can retry before transfer.
            connection.retained_receive.retain(packet);
            owned = false;
            if (packet.fixed.packet_type != .disconnect) return .{ .packet = .{ .packet = packet, .source = .retained } };
            return .{ .disconnect = try retainedDisconnect(connection) };
        }

        pub fn retainedDisconnect(connection: *Connection) Error!Context.DisconnectType {
            const packet = connection.retained_receive.packet().?;
            const value = Context.decodeDisconnect(connection, packet.bytes) catch |err| {
                if (err != error.OutOfMemory) {
                    var invalid = connection.retained_receive.take();
                    invalid.deinit(connection.allocator);
                }
                return err;
            };
            _ = connection.retained_receive.take();
            Context.finishDisconnect(connection, value);
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
            Context.finishDisconnect(connection, value);
            return .{ .packet = packet, .disconnect = value };
        }

        fn readTransport(connection: *Connection, options: Options) Error!Packet {
            const transport = &connection.transport;
            if (options.storage) |storage| {
                return if (options.inactivity_observer) |observer|
                    transport.readPacketWithInactivityObserverIntoWithPrefix(connection.allocator, connection.limits.max_packet_size, observer, storage, options.prefix_len)
                else if (options.inactivity_timeout) |timeout|
                    transport.readPacketWithInactivityTimeoutIntoWithPrefix(connection.allocator, connection.limits.max_packet_size, timeout, storage, options.prefix_len)
                else
                    transport.readPacketIntoWithPrefix(connection.allocator, connection.limits.max_packet_size, storage, options.prefix_len);
            }
            std.debug.assert(options.inactivity_observer == null);
            if (options.deadline) |deadline| return transport.readPacketWithDeadline(connection.allocator, connection.limits.max_packet_size, deadline);
            if (options.inactivity_timeout) |timeout| return transport.readPacketWithInactivityTimeout(connection.allocator, connection.limits.max_packet_size, timeout);
            return transport.readPacket(connection.allocator, connection.limits.max_packet_size);
        }

        fn anyPacket(_: void, _: Packet) bool {
            return true;
        }
    };
}
