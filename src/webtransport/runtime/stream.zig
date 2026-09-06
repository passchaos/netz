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
                webTransportStreamLimit(
                    peer.webtransport_initial_max_streams_bidi,
                    max_streams,
                ),
                max_streams,
            ),
            .max_local_uni = @min(
                webTransportStreamLimit(
                    peer.webtransport_initial_max_streams_uni,
                    max_streams,
                ),
                max_streams,
            ),
            .max_peer_bidi = @min(
                webTransportStreamLimit(
                    local.webtransport_initial_max_streams_bidi,
                    max_streams,
                ),
                max_streams,
            ),
            .max_peer_uni = @min(
                webTransportStreamLimit(
                    local.webtransport_initial_max_streams_uni,
                    max_streams,
                ),
                max_streams,
            ),
            .first_local_bidi = first_local_bidi,
            .first_local_uni = first_local_uni,
        },
    );
}

fn webTransportStreamLimit(advertised: u64, fallback: u64) u64 {
    // Current wtransport/browser peers rely on QUIC MAX_STREAMS and omit the
    // older WebTransport-specific 0x2b64/0x2b65 settings. Zero therefore means
    // "no extra protocol-layer limit" here; the negotiated QUIC limits and
    // `max_session_streams` remain hard bounds.
    return if (advertised == 0) fallback else advertised;
}

test "WebTransport registry accepts peers without legacy stream settings" {
    var registry = try initRegistry(
        std.testing.allocator,
        .init(0),
        .server,
        .{ .enable_connect_protocol = true, .enable_webtransport = true },
        .{ .enable_connect_protocol = true, .enable_webtransport = true },
        8,
        null,
        null,
    );
    defer registry.deinit();
    try std.testing.expectEqual(@as(u62, 1), (try registry.openLocal(.bidirectional)).stream_id);
    try std.testing.expectEqual(@as(u62, 15), (try registry.openLocal(.unidirectional)).stream_id);
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
    const stream = try writableStream(registry, stream_id);
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
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgress(connection);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
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
    const stream = try writableStream(registry, stream_id);
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
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgress(connection);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
        try association.requestAfterSendTerminal(connection, stream);
        try registry.recordSent(stream_id, 0, true);
        return;
    }
}

/// Validate a local send direction and transmit its association prefix.
/// Batch writers call this before staging application DATA transactionally.
pub fn prepare(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!*webtransport.StreamState {
    const stream = try writableStream(registry, stream_id);
    try sendPrefixIfNeeded(connection, stream, session_id, stream_id);
    return stream;
}

fn writableStream(
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
) Error!*webtransport.StreamState {
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
    return stream;
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
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgress(connection);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
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

pub fn receiveSendProgress(
    connection: *quic.one_rtt.Connection,
) Error!void {
    // Send progress depends only on ACK/credit/recovery state. Avoid creating
    // owned packet diagnostics that this pump would immediately discard.
    try connection.servicePacketServicingTimers();
}

pub fn receive(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
) Error!OwnedHandshakeStream {
    return receiveUntil(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn receiveWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!OwnedHandshakeStream {
    return receiveUntil(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        deadline,
    );
}

fn receiveUntil(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!OwnedHandshakeStream {
    while (true) {
        if (try poll(
            connection,
            registry,
            session_id,
            max_stream_bytes,
        )) |stream| return stream;

        if (deadline) |absolute| {
            try connection.servicePacketServicingTimersDeadline(absolute);
        } else {
            try connection.servicePacketServicingTimers();
        }
    }
}

/// Take the next FIN-complete associated stream already present in QUIC
/// receive state without reading the endpoint socket. This is the whole-stream
/// counterpart to the incremental poller used by shared-endpoint dispatchers.
pub fn poll(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
) Error!?OwnedHandshakeStream {
    var stream_ids: [256]u62 = undefined;
    var after: ?u62 = null;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(
            after,
            &stream_ids,
        );
        for (ids) |stream_id| {
            // Critical/push streams are not prefiltered by numeric ID. The
            // HTTP/3 layer has already consumed them into connection stream
            // state, and association parsing rejects every prefix except the
            // WebTransport 0x41/0x54 forms. This also permits a valid
            // WebTransport stream to use an ID once guessed to be reserved.
            if (stream_id == session_id.value) continue;
            if (try takeHandshakeSessionStream(
                connection,
                registry,
                session_id,
                stream_id,
                max_stream_bytes,
            )) |stream| return stream;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) return null;
    }
}

fn takeHandshakeSessionStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    max_stream_bytes: usize,
) Error!?OwnedHandshakeStream {
    // Receive mode is selected per stream, not per session. A caller may use
    // the compatibility whole-stream API for one stream and incremental reads
    // for another. Ignore streams already claimed by the incremental reader
    // rather than making them poison every later whole-stream scan.
    if (registry.get(stream_id)) |registered| {
        if (registered.receive_mode == .incremental) return null;
    }
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
    _ = try association.requestTransportRetirement(connection, stream);
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

test "WebTransport whole-stream receive requests transport retirement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd5} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-retire-server",
        .peer_connection_id = "wt-retire-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &encoded,
        allocator,
        session_id,
    );
    try encoded.appendSlice(allocator, "payload");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 2,
            .data = encoded.items,
            .fin = true,
        } }},
        null,
        .not_ect,
    );

    var stream = (try poll(
        &connection,
        &registry,
        session_id,
        64,
    )) orelse return error.TestUnexpectedResult;
    defer stream.deinit();
    try std.testing.expectEqualStrings("payload", stream.payload);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(registry.get(2) != null);
}

test "WebTransport local unidirectional FIN requests transport retirement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd6} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-local-client",
        .peer_connection_id = "wt-local-server",
        .initial_send_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_uni = 1, .first_local_uni = 2 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.unidirectional);
    try std.testing.expectEqual(@as(u62, 2), stream.stream_id);

    try finish(&connection, &registry, session_id, stream.stream_id);
    try std.testing.expect(!connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(stream.local_fin);
    try std.testing.expect(connection.markPacketAcknowledged(1));
    try std.testing.expect(!connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(connection.markPacketAcknowledged(0));
    try std.testing.expect(connection.localStreamClosed(stream.stream_id));
    try std.testing.expect(registry.get(stream.stream_id) != null);
}
