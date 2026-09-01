//! Associated WebTransport streams for the cleartext development runtime.
//!
//! HTTP/3 remains the sole UDP packet pump and owns reassembly/send offsets.
//! This adapter owns only WebTransport association prefixes and per-session
//! registry accounting.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

pub const Error = webtransport.Error || http3.runtime.Error;

pub const Owned = struct {
    allocator: std.mem.Allocator,
    from: std.Io.net.IpAddress,
    stream_id: u62,
    direction: webtransport.StreamDirection,
    locally_initiated: bool,
    payload: []u8,
    fin: bool = true,

    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn initRegistry(
    allocator: std.mem.Allocator,
    session_id: webtransport.SessionId,
    role: webtransport.EndpointRole,
    max_session_streams: usize,
) Error!webtransport.StreamRegistry {
    const limit = std.math.cast(u64, max_session_streams) orelse
        std.math.maxInt(u64);
    return webtransport.StreamRegistry.init(allocator, session_id, role, .{
        .max_local_bidi = limit,
        .max_local_uni = limit,
        .max_peer_bidi = limit,
        .max_peer_uni = limit,
    });
}

/// Reserve the registry allocations/count budget needed for one external H3
/// stream ID without consuming either allocator's ID cursor.
pub fn preflightLocal(
    registry: *webtransport.StreamRegistry,
    role: webtransport.EndpointRole,
    direction: webtransport.StreamDirection,
) Error!void {
    var candidate: u62 = switch (role) {
        .client => switch (direction) {
            .bidirectional => 4,
            .unidirectional => 14,
        },
        .server => switch (direction) {
            .bidirectional => 1,
            .unidirectional => 15,
        },
    };
    while (registry.get(candidate) != null) {
        candidate = std.math.add(u62, candidate, 4) catch
            return error.StreamLimitExceeded;
    }
    try registry.prepareLocalId(candidate, direction);
}

pub fn prefix(
    storage: []u8,
    direction: webtransport.StreamDirection,
    session_id: webtransport.SessionId,
) Error![]const u8 {
    return switch (direction) {
        .bidirectional => webtransport.BidirectionalStreamHeader.writeInto(
            storage,
            session_id,
        ),
        .unidirectional => blk: {
            const stream_type = try quic.varint.encodeInto(
                storage,
                @intFromEnum(http3.StreamType.webtransport_unidirectional),
            );
            const session = try quic.varint.encodeInto(
                storage[stream_type.len..],
                session_id.value,
            );
            break :blk storage[0 .. stream_type.len + session.len];
        },
    };
}

pub fn match(
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    role: webtransport.EndpointRole,
) http3.runtime.DevelopmentStreamMatch {
    return .{
        .session_id = session_id.value,
        .local_role = switch (role) {
            .client => .client,
            .server => .server,
        },
        .context = registry,
        .is_local_bidirectional = isLocalBidirectional,
    };
}

fn isLocalBidirectional(context: *const anyopaque, stream_id: u62) bool {
    const registry: *webtransport.StreamRegistry =
        @ptrCast(@alignCast(@constCast(context)));
    const stream = registry.get(stream_id) orelse return false;
    return stream.locally_initiated and stream.direction == .bidirectional;
}

pub fn take(
    registry: *webtransport.StreamRegistry,
    raw_value: http3.runtime.DevelopmentStream,
) Error!Owned {
    var raw = raw_value;
    errdefer raw.deinit();
    const direction: webtransport.StreamDirection = switch (raw.direction) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
    var stream = registry.get(raw.stream_id);
    if (stream == null) {
        stream = try registry.registerPeer(raw.stream_id, direction);
    } else if (stream.?.direction != direction) {
        return error.InvalidStreamType;
    }
    try registry.recordReceived(raw.stream_id, raw.bytes.len, true);
    return .{
        .allocator = raw.allocator,
        .from = raw.from,
        .stream_id = raw.stream_id,
        .direction = direction,
        .locally_initiated = stream.?.locally_initiated,
        .payload = raw.bytes,
    };
}
