//! MQTT byte-stream framing retains complete WebSocket message ownership.
const std = @import("std");
const progress_threshold = @import("../keep_alive_reader.zig").progress_threshold;

pub fn Reader(comptime Context: type) type {
    return struct {
        const Error = Context.ErrorType;

        pub fn read(allocator: std.mem.Allocator, ws: anytype, max_packet_size: usize, inactivity_timeout: ?std.Io.Clock.Duration, absolute_deadline: ?std.Io.Clock.Timestamp, owned_prefix_len: usize) Error!Context.PacketType {
            var deadline = if (inactivity_timeout) |timeout| Context.fromInactivity(ws.connection.io, timeout) else absolute_deadline;
            var large_progress_bytes: usize = 0;
            var frame = try Context.parse(ws.input.items);
            while (true) {
                if (frame) |parsed| {
                    if (parsed.packet_len > max_packet_size) return error.PacketTooLarge;
                    if (parsed.packet_len <= ws.input.items.len) {
                        const allocated = try Context.allocate(allocator, parsed.packet_len, owned_prefix_len);
                        errdefer Context.free(allocator, allocated.bytes, allocated.prefix_len);
                        @memcpy(allocated.bytes, ws.input.items[0..parsed.packet_len]);
                        Context.discard(&ws.input, parsed.packet_len);
                        return .{ .bytes = allocated.bytes, .fixed = parsed.fixed, .prefix_len = allocated.prefix_len };
                    }
                }
                if (ws.input.items.len >= max_packet_size) return error.PacketTooLarge;
                const added = try appendMessage(allocator, ws, max_packet_size, deadline);
                frame = try Context.parse(ws.input.items);
                if (added != 0) {
                    if (frame) |parsed| {
                        if (parsed.packet_len > max_packet_size) return error.PacketTooLarge;
                        if (inactivity_timeout) |timeout| {
                            if (ws.input.items.len > large_progress_bytes and parsed.packet_len > ws.input.items.len and parsed.packet_len - ws.input.items.len > progress_threshold) {
                                deadline = Context.fromInactivity(ws.connection.io, timeout);
                                large_progress_bytes = ws.input.items.len;
                            }
                        }
                    }
                }
            }
        }

        fn appendMessage(allocator: std.mem.Allocator, ws: anytype, max_packet_size: usize, deadline: ?std.Io.Clock.Timestamp) Error!usize {
            if (ws.pending_payload == null) {
                var message = if (deadline) |absolute| try ws.connection.receiveMessageWithDeadline(absolute) else try ws.connection.receiveMessage();
                if (message.opcode != .binary) {
                    message.deinit(ws.connection.allocator);
                    return error.InvalidWebSocketMessage;
                }
                // Compression has already committed at this ownership boundary.
                // Retain the decoded bytes instead of reading another message
                // if the MQTT append allocation fails.
                ws.pending_payload = message.payload;
            }
            errdefer |err| if (err != error.OutOfMemory) discardPending(ws);
            const payload = ws.pending_payload.?;
            const next_len = std.math.add(usize, ws.input.items.len, payload.len) catch return error.PacketTooLarge;
            const max_buffered = std.math.mul(usize, max_packet_size, 2) catch std.math.maxInt(usize);
            if (next_len > max_buffered) return error.PacketTooLarge;
            try ws.input.appendSlice(allocator, payload);
            const added = payload.len;
            discardPending(ws);
            return added;
        }

        pub fn discardPending(ws: anytype) void {
            if (ws.pending_payload) |payload| ws.connection.allocator.free(payload);
            ws.pending_payload = null;
        }
    };
}
