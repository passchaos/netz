//! Incremental MQTT framing above established TLS stream readers.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const progress_threshold = @import("../keep_alive_reader.zig").progress_threshold;

pub fn Reader(comptime Context: type) type {
    return struct {
        const Error = Context.ErrorType;

        pub fn read(allocator: std.mem.Allocator, transport: anytype, max_packet_size: usize, inactivity_timeout: ?std.Io.Clock.Duration, absolute_deadline: ?std.Io.Clock.Timestamp, owned_prefix_len: usize) Error!Context.PacketType {
            const connection = transport.connection;
            var deadline = if (inactivity_timeout) |timeout| Context.fromInactivity(connection.io, timeout) else absolute_deadline;
            const state = &transport.packet_state;
            while (state.packet == null) {
                // A complete header may survive a local allocation failure.
                // Retry that allocation before consuming any payload bytes.
                if (state.header_len < 2 or (state.header[state.header_len - 1] & 0x80) != 0) {
                    if (state.header_len >= state.header.len) return error.MalformedRemainingLength;
                    state.header_len += try readSome(connection, state.header[state.header_len .. state.header_len + 1], deadline);
                    if (state.header_len == 1) _ = try mqtt.packetTypeFromFirstByte(state.header[0]);
                    continue;
                }
                const decoded = try mqtt.decodeRemainingLength(state.header[1..state.header_len]);
                const packet_len = std.math.add(usize, 1 + decoded.len, decoded.value) catch return error.PacketTooLarge;
                if (packet_len > max_packet_size) return error.PacketTooLarge;
                const allocated = try Context.allocate(allocator, packet_len, owned_prefix_len);
                @memcpy(allocated.bytes[0..state.header_len], state.header[0..state.header_len]);
                state.packet = allocated.bytes;
                state.packet_prefix_len = allocated.prefix_len;
                state.packet_read = state.header_len;
            }
            const packet = state.packet.?;
            while (state.packet_read < packet.len) {
                if (inactivity_timeout) |timeout| {
                    if (packet.len - state.packet_read > progress_threshold) deadline = Context.fromInactivity(connection.io, timeout);
                }
                // Commit each returned plaintext prefix before another read
                // can fail. Propagate interruption with this cursor intact.
                state.packet_read += try readSome(connection, packet[state.packet_read..], deadline);
            }
            state.packet = null;
            const prefix_len = state.packet_prefix_len;
            state.packet_prefix_len = 0;
            state.packet_read = 0;
            state.header_len = 0;
            errdefer Context.free(allocator, packet, prefix_len);
            return .{ .bytes = packet, .fixed = try mqtt.FixedHeader.parse(packet), .prefix_len = prefix_len };
        }

        pub fn readSome(connection: anytype, buffer: []u8, deadline: ?std.Io.Clock.Timestamp) Error!usize {
            const count = (if (deadline) |absolute| connection.readWithDeadline(buffer, absolute) else connection.read(buffer)) catch |err| {
                // MQTT maps bare TLS EOF consistently with cleartext EOF.
                if (err == error.UnexpectedEof) return error.ConnectionClosed;
                return err;
            };
            if (count == 0) return error.ConnectionClosed;
            return count;
        }
    };
}
