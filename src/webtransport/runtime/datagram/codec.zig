const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");

pub const stack_capacity: usize = 4096;

pub const Encoded = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *Encoded, allocator: std.mem.Allocator) void {
        if (self.owned) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
};

/// Encode into caller storage when possible and otherwise allocate the exact
/// wire length once. The returned payload owns no geometric spare capacity.
pub fn encodeStackFirst(
    allocator: std.mem.Allocator,
    stack: []u8,
    session_id: webtransport.SessionId,
    payload: []const u8,
) webtransport.Error!Encoded {
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    const total_len = std.math.add(usize, prefix_len, payload.len) catch
        return error.IntegerOverflow;
    if (total_len <= stack.len) {
        const bytes = try encodeInto(
            stack[0..total_len],
            session_id,
            payload,
        );
        return .{ .bytes = bytes };
    }

    const owned = try allocator.alloc(u8, total_len);
    errdefer allocator.free(owned);
    const bytes = try encodeInto(owned, session_id, payload);
    return .{ .bytes = bytes, .owned = owned };
}

pub fn encodeInto(
    output: []u8,
    session_id: webtransport.SessionId,
    payload: []const u8,
) webtransport.Error![]const u8 {
    if (!session_id.isClientInitiatedBidirectional()) {
        return error.InvalidSessionId;
    }
    const prefix_len = try quic.varint.length(session_id.quarterStreamId());
    const total_len = std.math.add(usize, prefix_len, payload.len) catch
        return error.IntegerOverflow;
    if (output.len < total_len) return error.BufferTooShort;
    const prefix = try quic.varint.encodeInto(
        output[0..prefix_len],
        session_id.quarterStreamId(),
    );
    std.debug.assert(prefix.len == prefix_len);
    @memcpy(output[prefix_len..total_len], payload);
    return output[0..total_len];
}
