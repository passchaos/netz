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

const association = @import("stream_association.zig");
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
    var offset: usize = 0;
    while (offset < payload.len) {
        offset += try write(
            connection,
            registry,
            session_id,
            stream_id,
            payload[offset..],
        );
    }
    if (fin) try finish(
        connection,
        registry,
        session_id,
        stream_id,
    );
}

/// Submit at most one packet-sized application prefix and return its length.
///
/// This call processes peer packets until at least one byte is writable, but
/// returns after one STREAM submission so the caller can fairly schedule other
/// streams. Empty input is a no-op; use `finish` for FIN.
pub fn write(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
) Error!usize {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    if (stream.send_reset != null or
        stream.stopped != null or
        stream.local_fin)
    {
        return error.InvalidStreamState;
    }
    if (payload.len == 0) return 0;

    while (true) {
        try sendPrefixIfNeeded(
            connection,
            stream,
            session_id,
            stream_id,
        );
        const credit = connection.streamSendCredit(stream_id);
        const max_frame_data = @max(
            @as(usize, 1),
            credit.max_datagram_size -| 128,
        );
        const count = @min(
            payload.len,
            @min(max_frame_data, credit.available()),
        );
        if (count == 0) {
            try receiveSendProgress(connection);
            continue;
        }
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = payload[0..count],
            .fin = false,
        } }};
        connection.send(&frames) catch |err| switch (err) {
            error.FlowControlBlocked,
            error.CongestionLimited,
            error.PacingLimited,
            => {
                try receiveSendProgress(connection);
                continue;
            },
            else => return err,
        };
        stream.send_offset = std.math.add(
            u64,
            stream.send_offset,
            count,
        ) catch return error.IntegerOverflow;
        try registry.recordSent(stream_id, count, false);
        return count;
    }
}

pub fn finish(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    if (stream.send_reset != null or
        stream.stopped != null or
        stream.local_fin)
    {
        return error.InvalidStreamState;
    }
    try sendPrefixIfNeeded(
        connection,
        stream,
        session_id,
        stream_id,
    );
    while (true) {
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = &.{},
            .fin = true,
        } }};
        connection.send(&frames) catch |err| switch (err) {
            error.FlowControlBlocked,
            error.CongestionLimited,
            error.PacingLimited,
            => {
                try receiveSendProgress(connection);
                continue;
            },
            else => return err,
        };
        try registry.recordSent(stream_id, 0, true);
        return;
    }
}

fn sendPrefixIfNeeded(
    connection: *quic.one_rtt.Connection,
    stream: *webtransport.StreamState,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    if (stream.prefix_sent) return;
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
    while (true) {
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = prefix,
            .fin = false,
        } }};
        connection.send(&frames) catch |err| switch (err) {
            error.FlowControlBlocked,
            error.CongestionLimited,
            error.PacingLimited,
            => {
                try receiveSendProgress(connection);
                continue;
            },
            else => return err,
        };
        stream.send_offset = std.math.add(
            u64,
            stream.send_offset,
            prefix.len,
        ) catch return error.IntegerOverflow;
        stream.prefix_sent = true;
        return;
    }
}

fn receiveSendProgress(
    connection: *quic.one_rtt.Connection,
) Error!void {
    var packet = try connection.receivePacketServicingTimers();
    defer packet.deinit(connection.endpoint.allocator);
    _ = connection.sendAckForPacketsIfNeeded(
        @as(*const [1]quic.one_rtt.ReceivedPacket, &packet),
    ) catch {};
    _ = try connection.retransmitPacketThresholdLosses(
        quic.one_rtt.max_batch_packets,
    );
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
    const stream = try association.identify(
        connection,
        registry,
        session_id,
        stream_id,
        .whole,
    ) orelse return null;
    if (stream.receive_reset != null) return error.InvalidStreamState;
    const prefix_len = stream.receive_prefix_len;

    const stats = connection.recvStreamStats(stream_id) orelse return null;
    const final_size = stats.final_size orelse return null;
    if (final_size < prefix_len) return error.InvalidStreamState;
    const payload_len_u64 = final_size - prefix_len;
    const payload_len = std.math.cast(usize, payload_len_u64) orelse
        return error.IntegerOverflow;
    if (payload_len > max_stream_bytes) return error.StreamLimitExceeded;
    if (!stream.prefix_received or available.len < prefix_len + payload_len) {
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
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
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
