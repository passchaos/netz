const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

pub const Error = webtransport.Error || http3.runtime.Error;

pub const OwnedHandshakeStream = struct {
    allocator: std.mem.Allocator,
    stream_id: u62,
    direction: webtransport.StreamDirection,
    locally_initiated: bool,
    payload: []u8,
    fin: bool,

    pub fn deinit(self: *OwnedHandshakeStream) void {
        self.allocator.free(self.payload);
        self.* = undefined;
    }
};

pub fn initRegistry(
    allocator: std.mem.Allocator,
    session_id: webtransport.SessionId,
    role: webtransport.EndpointRole,
    local: http3.Settings,
    peer: http3.Settings,
    max_session_streams: usize,
    first_local_bidi: ?u62,
    first_local_uni: ?u62,
) Error!webtransport.StreamRegistry {
    try webtransport.ensureNegotiated(local, peer);
    const max_streams = std.math.cast(u64, max_session_streams) orelse
        std.math.maxInt(u64);
    return webtransport.StreamRegistry.init(
        allocator,
        session_id,
        role,
        .{
            .max_local_bidi = @min(
                peer.webtransport_initial_max_streams_bidi,
                max_streams,
            ),
            .max_local_uni = @min(
                peer.webtransport_initial_max_streams_uni,
                max_streams,
            ),
            .max_peer_bidi = @min(
                local.webtransport_initial_max_streams_bidi,
                max_streams,
            ),
            .max_peer_uni = @min(
                local.webtransport_initial_max_streams_uni,
                max_streams,
            ),
            .first_local_bidi = first_local_bidi,
            .first_local_uni = first_local_uni,
        },
    );
}

pub fn send(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    if (stream.reset or stream.local_fin) return error.InvalidStreamState;

    var fin_sent = false;
    if (!stream.prefix_sent) {
        var prefix_storage: [16]u8 = undefined;
        const prefix = switch (stream.direction) {
            .bidirectional => try webtransport
                .BidirectionalStreamHeader.writeInto(
                &prefix_storage,
                session_id,
            ),
            .unidirectional => try writeUnidirectionalHeaderInto(
                &prefix_storage,
                session_id,
            ),
        };
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = prefix,
            .fin = fin and payload.len == 0,
        } }};
        try sendHandshakeStreamFramesPaced(connection, &frames);
        fin_sent = fin and payload.len == 0;
        stream.send_offset = std.math.add(
            u64,
            stream.send_offset,
            prefix.len,
        ) catch return error.IntegerOverflow;
        stream.prefix_sent = true;
        if (fin_sent) try registry.recordSent(stream_id, 0, true);
    }

    const max_frame_data = @max(
        @as(usize, 1),
        connection.currentSendDatagramSize() -|
            128,
    );
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(payload.len, offset + max_frame_data);
        const is_final = fin and end == payload.len;
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = payload[offset..end],
            .fin = is_final,
        } }};
        try sendHandshakeStreamFramesPaced(connection, &frames);
        stream.send_offset = std.math.add(
            u64,
            stream.send_offset,
            end - offset,
        ) catch return error.IntegerOverflow;
        // Commit application accounting per socket-visible chunk. If a later
        // transport error aborts this call, already-sent progress remains
        // observable instead of being reported as zero.
        try registry.recordSent(stream_id, end - offset, is_final);
        offset = end;
    }
    if (payload.len == 0 and fin and !fin_sent) {
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = &.{},
            .fin = true,
        } }};
        try sendHandshakeStreamFramesPaced(connection, &frames);
        try registry.recordSent(stream_id, 0, true);
    } else if (payload.len == 0 and !fin) {
        try registry.recordSent(stream_id, 0, false);
    }
}

fn sendHandshakeStreamFramesPaced(
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
) Error!void {
    while (true) {
        connection.send(frames) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                var packet = try connection.receivePacketServicingTimers();
                defer packet.deinit(connection.endpoint.allocator);
                _ = connection.sendAckForPacketsIfNeeded(
                    @as(*const [1]quic.one_rtt.ReceivedPacket, &packet),
                ) catch {};
                _ = try connection.retransmitPacketThresholdLosses(
                    quic.one_rtt.max_batch_packets,
                );
                continue;
            },
            else => return err,
        };
        return;
    }
}

pub fn receive(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
) Error!OwnedHandshakeStream {
    while (true) {
        var stream_ids: [256]u62 = undefined;
        var start: usize = 0;
        while (true) {
            const ids = connection.receivedStreamIdsFromInto(
                start,
                &stream_ids,
            );
            for (ids) |stream_id| {
                if (stream_id == session_id.value or
                    isHttp3CriticalOrPushStream(stream_id))
                {
                    continue;
                }
                if (try takeHandshakeSessionStream(
                    connection,
                    registry,
                    session_id,
                    stream_id,
                    max_stream_bytes,
                )) |stream| return stream;
            }
            start += ids.len;
            if (ids.len < stream_ids.len) break;
        }

        var packet = try connection.receivePacketServicingTimers();
        defer packet.deinit(connection.endpoint.allocator);
        _ = connection.sendAckForPacketsIfNeeded(
            @as(*const [1]quic.one_rtt.ReceivedPacket, &packet),
        ) catch {};
    }
}

fn takeHandshakeSessionStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    max_stream_bytes: usize,
) Error!?OwnedHandshakeStream {
    const available = connection.availableReceivedStream(stream_id) orelse
        return null;
    const direction: webtransport.StreamDirection =
        if (quic.StreamId.init(stream_id).direction() == .bidirectional)
            .bidirectional
        else
            .unidirectional;

    var stream = registry.get(stream_id);
    if (stream == null) {
        const prefix_len = switch (direction) {
            .bidirectional => blk: {
                const parsed =
                    webtransport.BidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return null,
                            error.InvalidStreamType => return null,
                            else => return err,
                        };
                if (parsed.session_id.value != session_id.value) {
                    return error.InvalidSessionId;
                }
                break :blk parsed.consumed;
            },
            .unidirectional => blk: {
                const parsed =
                    webtransport.UnidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return null,
                            else => return err,
                        };
                if (parsed.stream_type != .webtransport_unidirectional) {
                    return null;
                }
                if (parsed.session_id == null or
                    parsed.session_id.?.value != session_id.value)
                {
                    return error.InvalidSessionId;
                }
                break :blk parsed.consumed;
            },
        };
        stream = try registry.registerPeer(stream_id, direction);
        stream.?.prefix_received = true;
        stream.?.receive_prefix_len = prefix_len;
    } else if (stream.?.locally_initiated and
        stream.?.direction == .bidirectional and
        stream.?.bytes_received == 0 and
        !stream.?.prefix_received)
    {
        // A locally-opened bidi stream has no association prefix in the peer's
        // reverse direction.
        stream.?.prefix_received = true;
    }
    const prefix_len = stream.?.receive_prefix_len;

    const stats = connection.recvStreamStats(stream_id) orelse return null;
    const final_size = stats.final_size orelse return null;
    if (final_size < prefix_len) return error.InvalidStreamState;
    const payload_len_u64 = final_size - prefix_len;
    const payload_len = std.math.cast(usize, payload_len_u64) orelse
        return error.IntegerOverflow;
    if (payload_len > max_stream_bytes) return error.StreamLimitExceeded;
    if (!stream.?.prefix_received or available.len < prefix_len + payload_len) {
        return null;
    }
    const payload = try connection.endpoint.allocator.dupe(
        u8,
        available[prefix_len .. prefix_len + payload_len],
    );
    errdefer connection.endpoint.allocator.free(payload);
    try connection.releaseReceivedCapacity(
        stream_id,
        prefix_len + payload_len,
    );
    try registry.recordReceived(stream_id, payload_len, true);
    return .{
        .allocator = connection.endpoint.allocator,
        .stream_id = stream_id,
        .direction = direction,
        .locally_initiated = stream.?.locally_initiated,
        .payload = payload,
        .fin = true,
    };
}

fn writeUnidirectionalHeaderInto(
    storage: []u8,
    session_id: webtransport.SessionId,
) Error![]const u8 {
    const stream_type = try quic.varint.encodeInto(
        storage,
        @intFromEnum(http3.StreamType.webtransport_unidirectional),
    );
    const session = try quic.varint.encodeInto(
        storage[stream_type.len..],
        session_id.value,
    );
    return storage[0 .. stream_type.len + session.len];
}

fn isHttp3CriticalOrPushStream(stream_id: u62) bool {
    return switch (stream_id) {
        2, 3, 6, 7, 10, 11 => true,
        else => false,
    };
}
