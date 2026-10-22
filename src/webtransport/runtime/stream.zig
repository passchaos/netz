const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub const Error = webtransport.Error || http3.runtime.Error;
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

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
const association_prefix = @import("stream/prefix.zig");
const connection_lifecycle = @import("connection_lifecycle.zig");
const flow_send = @import("flow/send.zig");
const flow_progress = @import("flow/progress.zig");
const flow_receive = @import("flow/receive.zig");
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
    var registry = try webtransport.StreamRegistry.init(
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
    errdefer registry.deinit();
    // Once negotiated, these fields bound retained registry entries while
    // protocol opening credit comes from the dynamic flow-control state.
    if (webtransport.flow_control.negotiated(local, peer)) {
        registry.max_local_bidi = max_streams;
        registry.max_local_uni = max_streams;
        registry.max_peer_bidi = max_streams;
        registry.max_peer_uni = max_streams;
        try registry.configureFlow(local, peer);
    }
    return registry;
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

const max_slice_frames_per_packet: usize = 16;

const SliceCursor = struct {
    parts: []const []const u8,
    part_index: usize = 0,
    part_offset: usize = 0,
    committed: usize = 0,

    fn skipEmpty(self: *SliceCursor) void {
        while (self.part_index < self.parts.len and
            self.part_offset == self.parts[self.part_index].len)
        {
            self.part_index += 1;
            self.part_offset = 0;
        }
    }

    fn done(self: *SliceCursor) bool {
        self.skipEmpty();
        return self.part_index == self.parts.len;
    }

    fn remaining(self: *SliceCursor) []const u8 {
        self.skipEmpty();
        return self.parts[self.part_index][self.part_offset..];
    }

    fn advance(self: *SliceCursor, count: usize) void {
        std.debug.assert(count != 0);
        std.debug.assert(count <= self.remaining().len);
        self.part_offset += count;
        self.committed += count;
        self.skipEmpty();
    }
};

fn slicesLength(parts: []const []const u8) Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.IntegerOverflow;
    }
    return total;
}

const WholeStreamLengths = struct {
    wire: usize,
    payload: usize,
};

fn wholeStreamLengths(
    final_size: u64,
    prefix_len: usize,
) Error!WholeStreamLengths {
    // `final_size` covers both the WebTransport association prefix and the
    // application payload. Convert that authoritative total before
    // subtracting the prefix: on narrow targets the payload alone can fit
    // `usize` even though adding the prefix back would overflow.
    const wire_len = std.math.cast(usize, final_size) orelse
        return error.IntegerOverflow;
    if (wire_len < prefix_len) return error.InvalidStreamState;
    return .{
        .wire = wire_len,
        .payload = wire_len - prefix_len,
    };
}

test "WebTransport whole-stream lengths preserve checked final size" {
    const lengths = try wholeStreamLengths(13, 5);
    try std.testing.expectEqual(@as(usize, 13), lengths.wire);
    try std.testing.expectEqual(@as(usize, 8), lengths.payload);
    try std.testing.expectError(
        error.InvalidStreamState,
        wholeStreamLengths(4, 5),
    );

    if (comptime @bitSizeOf(usize) < 64) {
        try std.testing.expectError(
            error.IntegerOverflow,
            wholeStreamLengths(@as(u64, std.math.maxInt(usize)) + 1, 8),
        );
    }
}

/// Send the complete payload with bounded consecutive same-stream packet
/// batches, waiting for flow-control, congestion, or pacing progress between
/// batches. `write` retains its one-packet fairness contract.
pub fn send(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
) Error!void {
    var committed_out: usize = 0;
    return sendWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        fin,
        &committed_out,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Send the complete payload and optional FIN under one absolute awake-clock
/// deadline. `committed` reports the exact application prefix submitted even
/// when the operation returns an error, so a caller can resume without
/// duplicating bytes. FIN is committed only on success.
pub fn sendWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
    committed_out: *usize,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    committed_out.* = 0;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return sendWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        fin,
        committed_out,
        deadline,
        null,
    );
}

/// Send a logical associated-stream payload from borrowed slices without
/// joining them. Empty slices are ignored and FIN follows the final byte.
pub fn sendSlices(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
) Error!void {
    var committed: usize = 0;
    return sendSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        fin,
        &committed,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Deadline-bounded scatter/gather send. `committed_out` counts only
/// application bytes from the logical concatenation, never association-prefix
/// bytes, and always describes the exact socket-visible prefix on error.
pub fn sendSlicesWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
    committed_out: *usize,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    committed_out.* = 0;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return sendSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        fin,
        committed_out,
        deadline,
        null,
    );
}

/// Submit one complete scatter/gather payload as a single QUIC packet without
/// waiting. This is the endpoint-dispatcher counterpart to `sendSlices`; an
/// error leaves application offsets unchanged.
pub fn sendSlicesOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
) Error!void {
    const stream = try writableStream(registry, stream_id);
    const total_len = try slicesLength(parts);
    try flow_send.check(registry, total_len);
    if (total_len == 0 and !fin) return;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try pendingPrefix(stream, session_id, &prefix_storage);
    var frames: [max_slice_frames_per_packet]quic.Frame = undefined;
    var frame_count: usize = 0;
    const frame_limit = @max(
        @as(usize, 1),
        @min(
            max_slice_frames_per_packet,
            connection.config.max_frames_per_packet,
        ),
    );
    var offset = stream.send_offset;
    if (prefix.len != 0) {
        frames[frame_count] = .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = prefix,
            .fin = fin and total_len == 0,
        } };
        frame_count += 1;
        offset = std.math.add(u64, offset, prefix.len) catch
            return error.IntegerOverflow;
    }
    var non_empty_left: usize = 0;
    for (parts) |part| non_empty_left += @intFromBool(part.len != 0);
    for (parts) |part| {
        if (part.len == 0) continue;
        if (frame_count == frame_limit) return error.DatagramTooLarge;
        non_empty_left -= 1;
        frames[frame_count] = .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = part,
            .fin = fin and non_empty_left == 0,
        } };
        frame_count += 1;
        offset = std.math.add(u64, offset, part.len) catch
            return error.IntegerOverflow;
    }
    if (non_empty_left != 0) return error.DatagramTooLarge;
    if (frame_count == 0) {
        frames[0] = .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .data = &.{},
            .fin = true,
        } };
        frame_count = 1;
    }
    const next_bytes_sent = std.math.add(
        u64,
        stream.bytes_sent,
        total_len,
    ) catch return error.IntegerOverflow;
    try connection.trySend(frames[0..frame_count]);
    stream.send_offset = offset;
    stream.bytes_sent = next_bytes_sent;
    flow_send.commit(registry, total_len);
    stream.prefix_sent = true;
    if (fin) {
        stream.local_fin = true;
        association.requestAfterSendTerminal(connection, stream) catch
            unreachable;
    }
}

pub fn sendSlicesWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
    committed_out: *usize,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!void {
    committed_out.* = 0;
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    const total_len = try slicesLength(parts);
    var cursor = SliceCursor{ .parts = parts };
    while (!cursor.done()) {
        var stream = try writableStream(registry, stream_id);
        try sendPrefixIfNeededUntil(
            connection,
            stream,
            session_id,
            stream_id,
            deadline,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        // Maintenance can swap-remove a retired sibling from this registry.
        stream = try writableStream(registry, stream_id);
        const packet_payload = @max(
            @as(usize, 1),
            connection.currentSendDatagramSize() -| 128,
        );
        const connection_available = std.math.cast(
            usize,
            connection.connectionSendAvailable(),
        ) orelse std.math.maxInt(usize);
        const stream_available = std.math.cast(
            usize,
            connection.streamSendAvailable(stream_id),
        ) orelse std.math.maxInt(usize);
        const available = @min(
            total_len - cursor.committed,
            connection_available,
            stream_available,
            connection.congestionAvailable(),
            flow_send.available(registry),
        );
        if (available == 0) {
            try receiveSendProgressUntil(connection, deadline);
            continue;
        }
        // Preflight the largest state transition before constructing frame
        // offsets or making any socket-visible submission.
        _ = std.math.add(u64, stream.send_offset, available) catch
            return error.IntegerOverflow;
        _ = std.math.add(u64, stream.bytes_sent, available) catch
            return error.IntegerOverflow;

        var frames: [quic.one_rtt.max_batch_packets][max_slice_frames_per_packet]quic.Frame = undefined;
        var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
            undefined;
        var packet_cursors: [quic.one_rtt.max_batch_packets]SliceCursor =
            undefined;
        var staged = cursor;
        var staged_bytes: usize = 0;
        var packet_count: usize = 0;
        const frame_limit = @max(
            @as(usize, 1),
            @min(
                max_slice_frames_per_packet,
                connection.config.max_frames_per_packet,
            ),
        );
        while (packet_count < quic.one_rtt.max_batch_packets and
            staged_bytes < available and !staged.done())
        {
            var frame_count: usize = 0;
            var wire_bytes: usize = 0;
            var packet_data: usize = 0;
            while (frame_count < frame_limit and
                staged_bytes < available and !staged.done())
            {
                const part = staged.remaining();
                var count = @min(
                    part.len,
                    @min(
                        available - staged_bytes,
                        packet_payload -| wire_bytes,
                    ),
                );
                while (count != 0) {
                    const candidate = quic.Frame{ .stream = .{
                        .stream_id = stream_id,
                        .offset = stream.send_offset + staged_bytes,
                        .data = part[0..count],
                        .fin = false,
                    } };
                    const candidate_len = try candidate.wireLen();
                    if (candidate_len <= packet_payload -| wire_bytes) {
                        frames[packet_count][frame_count] = candidate;
                        wire_bytes += candidate_len;
                        packet_data += count;
                        staged_bytes += count;
                        staged.advance(count);
                        frame_count += 1;
                        break;
                    }
                    count -|= @max(
                        @as(usize, 1),
                        candidate_len -| (packet_payload -| wire_bytes),
                    );
                }
                if (count == 0) break;
            }
            if (frame_count == 0) return error.DatagramTooLarge;
            std.debug.assert(packet_data != 0);
            packets[packet_count] = frames[packet_count][0..frame_count];
            packet_cursors[packet_count] = staged;
            packet_count += 1;
        }
        std.debug.assert(packet_count != 0);
        const sent_time_ns = monotonicNowNs(connection);
        const result = connection.sendManyProgressAt(
            packets[0..packet_count],
            sent_time_ns,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => |other| return other,
        };
        if (result.sent_count > packet_count or
            result.sent_count > result.protected_count)
        {
            return error.Unexpected;
        }
        if (result.sent_count == 0) {
            if (result.send_error) |err| return err;
            return error.Unexpected;
        }
        const committed_cursor = packet_cursors[result.sent_count - 1];
        const committed = committed_cursor.committed - cursor.committed;
        const next_send_offset = std.math.add(
            u64,
            stream.send_offset,
            committed,
        ) catch return error.IntegerOverflow;
        const next_bytes_sent = std.math.add(
            u64,
            stream.bytes_sent,
            committed,
        ) catch return error.IntegerOverflow;
        stream.send_offset = next_send_offset;
        stream.bytes_sent = next_bytes_sent;
        flow_send.commit(registry, committed);
        cursor = committed_cursor;
        committed_out.* = cursor.committed;
        if (result.send_error) |err| return err;
    }
    if (fin) try finishUntil(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
    );
}

pub fn sendWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
    committed_out: *usize,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!void {
    committed_out.* = 0;
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    var offset: usize = 0;
    while (offset < payload.len) {
        var stream = try writableStream(registry, stream_id);
        try sendPrefixIfNeededUntil(
            connection,
            stream,
            session_id,
            stream_id,
            deadline,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        // Maintenance can swap-remove a retired sibling from this registry.
        stream = try writableStream(registry, stream_id);
        const packet_payload = @max(
            @as(usize, 1),
            connection.currentSendDatagramSize() -| 128,
        );
        // `SendCredit.available()` is deliberately capped to one datagram for
        // the single-packet writer. A multi-packet batch instead snapshots the
        // aggregate flow/congestion limits and applies the datagram limit to
        // each staged packet below.
        const connection_available = std.math.cast(
            usize,
            connection.connectionSendAvailable(),
        ) orelse std.math.maxInt(usize);
        const stream_available = std.math.cast(
            usize,
            connection.streamSendAvailable(stream_id),
        ) orelse std.math.maxInt(usize);
        const available = @min(
            payload.len - offset,
            connection_available,
            stream_available,
            connection.congestionAvailable(),
            flow_send.available(registry),
        );
        if (available == 0) {
            try receiveSendProgressUntil(connection, deadline);
            continue;
        }
        const packet_count = @min(
            quic.one_rtt.max_batch_packets,
            std.math.divCeil(usize, available, packet_payload) catch
                return error.IntegerOverflow,
        );
        var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
        var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
            undefined;
        var staged_bytes: usize = 0;
        for (0..packet_count) |index| {
            const count = @min(
                packet_payload,
                available - staged_bytes,
            );
            frames[index][0] = .{ .stream = .{
                .stream_id = stream_id,
                .offset = stream.send_offset + staged_bytes,
                .data = payload[offset + staged_bytes ..][0..count],
                .fin = false,
            } };
            packets[index] = &frames[index];
            staged_bytes += count;
        }
        _ = std.math.add(u64, stream.send_offset, staged_bytes) catch
            return error.IntegerOverflow;
        _ = std.math.add(u64, stream.bytes_sent, staged_bytes) catch
            return error.IntegerOverflow;
        _ = std.math.add(usize, offset, staged_bytes) catch
            return error.IntegerOverflow;
        const sent_time_ns = monotonicNowNs(connection);
        const result = connection.sendManyProgressAt(
            packets[0..packet_count],
            sent_time_ns,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => |other| return other,
        };
        if (result.sent_count > packet_count or
            result.sent_count > result.protected_count)
        {
            return error.Unexpected;
        }
        var committed: usize = 0;
        for (0..result.sent_count) |index| {
            committed += frames[index][0].stream.data.len;
        }
        if (committed == 0) {
            if (result.send_error) |err| return err;
            return error.Unexpected;
        }
        // Preflight every fallible state update before the socket-visible
        // commit. After sendManyProgressAt succeeds, only infallible assigns
        // remain and `committed_out` can describe any following socket error.
        stream.send_offset += committed;
        stream.bytes_sent += committed;
        flow_send.commit(registry, committed);
        offset += committed;
        committed_out.* = offset;
        if (result.send_error) |err| return err;
    }
    if (fin) try finishUntil(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
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
    return writeWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Submit at most one packet-sized application prefix under one absolute
/// awake-clock deadline. The returned count is the exact committed prefix; a
/// timeout never commits unreported application bytes.
pub fn writeWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!usize {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return writeWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        deadline,
        null,
    );
}

/// Submit at most one packet-sized prefix from borrowed application slices.
/// The returned byte count spans slice boundaries and excludes association
/// bytes, matching `write`'s fairness and retry contract.
pub fn writeSlices(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
) Error!usize {
    return writeSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn writeSlicesWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!usize {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return writeSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        deadline,
        null,
    );
}

pub fn writeSlicesWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!usize {
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    var stream = try writableStream(registry, stream_id);
    const total_len = try slicesLength(parts);
    if (total_len == 0) return 0;
    const cursor = SliceCursor{ .parts = parts };

    while (true) {
        try sendPrefixIfNeededUntil(
            connection,
            stream,
            session_id,
            stream_id,
            deadline,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        // Maintenance can swap-remove a retired sibling from this registry.
        stream = try writableStream(registry, stream_id);
        const credit = connection.streamSendCredit(stream_id);
        const packet_payload = @max(
            @as(usize, 1),
            credit.max_datagram_size -| 128,
        );
        const available = @min(
            total_len,
            @min(packet_payload, credit.available(), flow_send.available(registry)),
        );
        if (available == 0) {
            try receiveSendProgressUntil(connection, deadline);
            continue;
        }
        _ = std.math.add(u64, stream.send_offset, available) catch
            return error.IntegerOverflow;
        _ = std.math.add(u64, stream.bytes_sent, available) catch
            return error.IntegerOverflow;

        var frames: [max_slice_frames_per_packet]quic.Frame = undefined;
        var frame_count: usize = 0;
        var wire_bytes: usize = 0;
        var staged = cursor;
        const frame_limit = @max(
            @as(usize, 1),
            @min(
                max_slice_frames_per_packet,
                connection.config.max_frames_per_packet,
            ),
        );
        while (frame_count < frame_limit and
            staged.committed < available and !staged.done())
        {
            const part = staged.remaining();
            var count = @min(
                part.len,
                @min(
                    available - staged.committed,
                    packet_payload -| wire_bytes,
                ),
            );
            while (count != 0) {
                const candidate = quic.Frame{ .stream = .{
                    .stream_id = stream_id,
                    .offset = stream.send_offset + staged.committed,
                    .data = part[0..count],
                    .fin = false,
                } };
                const candidate_len = try candidate.wireLen();
                if (candidate_len <= packet_payload -| wire_bytes) {
                    frames[frame_count] = candidate;
                    frame_count += 1;
                    wire_bytes += candidate_len;
                    staged.advance(count);
                    break;
                }
                count -|= @max(
                    @as(usize, 1),
                    candidate_len -| (packet_payload -| wire_bytes),
                );
            }
            if (count == 0) break;
        }
        if (frame_count == 0) return error.DatagramTooLarge;
        connection.trySend(frames[0..frame_count]) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => |other| return other,
        };
        stream.send_offset += staged.committed;
        stream.bytes_sent += staged.committed;
        flow_send.commit(registry, staged.committed);
        return staged.committed;
    }
}

pub fn writeWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!usize {
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    var stream = try writableStream(registry, stream_id);
    if (payload.len == 0) return 0;

    while (true) {
        try sendPrefixIfNeededUntil(
            connection,
            stream,
            session_id,
            stream_id,
            deadline,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        // Maintenance can swap-remove a retired sibling from this registry.
        stream = try writableStream(registry, stream_id);
        const credit = connection.streamSendCredit(stream_id);
        const max_frame_data = @max(
            @as(usize, 1),
            credit.max_datagram_size -| 128,
        );
        const count = @min(
            payload.len,
            @min(max_frame_data, credit.available(), flow_send.available(registry)),
        );
        if (count == 0) {
            try receiveSendProgressUntil(connection, deadline);
            continue;
        }
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = payload[0..count],
            .fin = false,
        } }};
        const next_send_offset = std.math.add(
            u64,
            stream.send_offset,
            count,
        ) catch return error.IntegerOverflow;
        const next_bytes_sent = std.math.add(
            u64,
            stream.bytes_sent,
            count,
        ) catch return error.IntegerOverflow;
        connection.trySend(&frames) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => |other| return other,
        };
        stream.send_offset = next_send_offset;
        stream.bytes_sent = next_bytes_sent;
        flow_send.commit(registry, count);
        return count;
    }
}

/// Submit at most one packet-sized application prefix without sleeping or
/// reading the endpoint socket. Association-prefix progress is retained, but
/// an error never commits application bytes, so retrying the same input is
/// unambiguous for a shared-endpoint owner.
pub fn writeOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
) Error!usize {
    const stream = try writableStream(registry, stream_id);
    if (payload.len == 0) return 0;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try pendingPrefix(stream, session_id, &prefix_storage);
    const credit = connection.streamSendCredit(stream_id);
    const max_frame_data = @max(
        @as(usize, 1),
        credit.max_datagram_size -| 128,
    );
    const available = @min(credit.available() -| prefix.len, flow_send.available(registry));
    const count = @min(
        payload.len,
        @min(max_frame_data -| prefix.len, available),
    );
    if (count == 0 and prefix.len == 0) {
        if (flow_send.available(registry) == 0) return error.FlowControlBlocked;
        // Let QUIC emit DATA_BLOCKED/STREAM_DATA_BLOCKED when appropriate, or
        // report congestion/pacing, without entering its receive loop.
        const probe = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = payload[0..1],
            .fin = false,
        } }};
        try connection.trySend(&probe);
        return error.Unexpected;
    }
    try submitOnce(
        connection,
        registry,
        stream,
        stream_id,
        prefix,
        payload[0..count],
        false,
    );
    return count;
}

/// Submit at most one packet-sized prefix from borrowed slices without
/// waiting or reading the endpoint socket. The association prefix shares the
/// packet when possible and is excluded from the returned application count.
pub fn writeSlicesOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
) Error!usize {
    const stream = try writableStream(registry, stream_id);
    if (try slicesLength(parts) == 0) return 0;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try pendingPrefix(stream, session_id, &prefix_storage);
    const application_offset = std.math.add(
        u64,
        stream.send_offset,
        prefix.len,
    ) catch return error.IntegerOverflow;
    const credit = connection.streamSendCredit(stream_id);
    const packet_payload = @max(
        @as(usize, 1),
        credit.max_datagram_size -| 128,
    );
    const available = @min(
        packet_payload -| prefix.len,
        credit.available() -| prefix.len,
        flow_send.available(registry),
    );
    var frames: [max_slice_frames_per_packet]quic.Frame = undefined;
    var frame_count: usize = 0;
    var wire_bytes: usize = 0;
    if (prefix.len != 0) {
        const frame = quic.Frame{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = prefix,
            .fin = false,
        } };
        frames[frame_count] = frame;
        frame_count += 1;
        wire_bytes = try frame.wireLen();
    }
    const frame_limit = @max(
        @as(usize, 1),
        @min(
            max_slice_frames_per_packet,
            connection.config.max_frames_per_packet,
        ),
    );
    var cursor = SliceCursor{ .parts = parts };
    while (frame_count < frame_limit and
        cursor.committed < available and !cursor.done())
    {
        const part = cursor.remaining();
        var count = @min(
            part.len,
            @min(
                available - cursor.committed,
                packet_payload -| wire_bytes,
            ),
        );
        while (count != 0) {
            const candidate = quic.Frame{ .stream = .{
                .stream_id = stream_id,
                .offset = application_offset + cursor.committed,
                .data = part[0..count],
                .fin = false,
            } };
            const candidate_len = try candidate.wireLen();
            if (candidate_len <= packet_payload -| wire_bytes) {
                frames[frame_count] = candidate;
                frame_count += 1;
                wire_bytes += candidate_len;
                cursor.advance(count);
                break;
            }
            count -|= @max(
                @as(usize, 1),
                candidate_len -| (packet_payload -| wire_bytes),
            );
        }
        if (count == 0) break;
    }
    if (frame_count == 0) {
        if (flow_send.available(registry) == 0) return error.FlowControlBlocked;
        const first = cursor.remaining();
        const probe = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = first[0..1],
            .fin = false,
        } }};
        try connection.trySend(&probe);
        return error.Unexpected;
    }
    const next_send_offset = std.math.add(
        u64,
        stream.send_offset,
        prefix.len + cursor.committed,
    ) catch return error.IntegerOverflow;
    const next_bytes_sent = std.math.add(
        u64,
        stream.bytes_sent,
        cursor.committed,
    ) catch return error.IntegerOverflow;
    try connection.trySend(frames[0..frame_count]);
    stream.send_offset = next_send_offset;
    stream.bytes_sent = next_bytes_sent;
    flow_send.commit(registry, cursor.committed);
    stream.prefix_sent = true;
    return cursor.committed;
}

/// Submit one complete payload and optional FIN as a single QUIC packet. This
/// is the all-or-nothing counterpart used by endpoint-owned convenience APIs.
pub fn sendOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
) Error!void {
    const stream = try writableStream(registry, stream_id);
    if (payload.len == 0 and !fin) return;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try pendingPrefix(stream, session_id, &prefix_storage);
    try submitOnce(connection, registry, stream, stream_id, prefix, payload, fin);
}

pub fn finish(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    return finishUntil(
        connection,
        registry,
        session_id,
        stream_id,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Submit an empty FIN under one absolute awake-clock deadline. A timeout
/// leaves `local_fin` clear, so the same operation can be retried safely.
pub fn finishWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return finishUntil(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
    );
}

fn finishUntil(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    const stream = try writableStream(registry, stream_id);
    try sendPrefixIfNeededUntil(
        connection,
        stream,
        session_id,
        stream_id,
        deadline,
    );
    while (true) {
        try ensureDeadline(connection, deadline);
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = &.{},
            .fin = true,
        } }};
        connection.trySend(&frames) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => |other| return other,
        };
        // Mark the socket-visible FIN before fallible retirement bookkeeping.
        // Any later error therefore cannot cause a retry to submit a duplicate
        // terminal offset.
        stream.local_fin = true;
        association.requestAfterSendTerminal(connection, stream) catch unreachable;
        return;
    }
}

/// Submit an empty FIN without waiting for socket or transport progress.
pub fn finishOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    try sendOnce(connection, registry, session_id, stream_id, &.{}, true);
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

/// Validate a stream and submit its association prefix once, without waiting
/// for pacing, congestion, flow control, or peer packets.
pub fn prepareOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!*webtransport.StreamState {
    const stream = try writableStream(registry, stream_id);
    try sendPrefixIfNeededOnce(connection, stream, session_id, stream_id);
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
    return sendPrefixIfNeededUntil(
        connection,
        stream,
        session_id,
        stream_id,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn sendPrefixIfNeededUntil(
    connection: *quic.one_rtt.Connection,
    stream: *webtransport.StreamState,
    session_id: webtransport.SessionId,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    if (stream.prefix_sent) return;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try association_prefix.header(session_id, stream.direction, &prefix_storage);
    while (true) {
        try ensureDeadline(connection, deadline);
        sendPrefixOnce(connection, stream, stream_id, prefix) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receiveSendProgressUntil(connection, deadline);
                continue;
            },
            error.PacingLimited => {
                try waitForPacingUntil(connection, deadline);
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn sendPrefixIfNeededOnce(
    connection: *quic.one_rtt.Connection,
    stream: *webtransport.StreamState,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    if (stream.prefix_sent) return;
    var prefix_storage: [16]u8 = undefined;
    const prefix = try pendingPrefix(stream, session_id, &prefix_storage);
    try sendPrefixOnce(connection, stream, stream_id, prefix);
}

fn pendingPrefix(
    stream: *const webtransport.StreamState,
    session_id: webtransport.SessionId,
    storage: *[16]u8,
) Error![]const u8 {
    if (stream.prefix_sent) return storage[0..0];
    return association_prefix.header(session_id, stream.direction, storage);
}

fn submitOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream: *webtransport.StreamState,
    stream_id: u62,
    prefix: []const u8,
    payload: []const u8,
    fin: bool,
) Error!void {
    try flow_send.check(registry, payload.len);
    const total = std.math.add(usize, prefix.len, payload.len) catch
        return error.IntegerOverflow;
    const next_offset = std.math.add(
        u64,
        stream.send_offset,
        total,
    ) catch return error.IntegerOverflow;
    const next_bytes_sent = std.math.add(
        u64,
        stream.bytes_sent,
        payload.len,
    ) catch return error.IntegerOverflow;
    var frames: [2]quic.Frame = undefined;
    var frame_count: usize = 0;
    if (prefix.len != 0) {
        frames[frame_count] = .{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = prefix,
            .fin = fin and payload.len == 0,
        } };
        frame_count += 1;
    }
    if (payload.len != 0 or (fin and prefix.len == 0)) {
        frames[frame_count] = .{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset + prefix.len,
            .data = payload,
            .fin = fin,
        } };
        frame_count += 1;
    }
    std.debug.assert(frame_count != 0);
    try connection.trySend(frames[0..frame_count]);
    stream.send_offset = next_offset;
    stream.bytes_sent = next_bytes_sent;
    flow_send.commit(registry, payload.len);
    stream.prefix_sent = true;
    if (fin) {
        stream.local_fin = true;
        association.requestAfterSendTerminal(connection, stream) catch unreachable;
    }
}

fn sendPrefixOnce(
    connection: *quic.one_rtt.Connection,
    stream: *webtransport.StreamState,
    stream_id: u62,
    prefix: []const u8,
) Error!void {
    const next_offset = std.math.add(
        u64,
        stream.send_offset,
        prefix.len,
    ) catch return error.IntegerOverflow;
    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = stream_id,
        .offset = stream.send_offset,
        .data = prefix,
        .fin = false,
    } }};
    try connection.trySend(&frames);
    stream.send_offset = next_offset;
    stream.prefix_sent = true;
}

pub fn receiveSendProgress(
    connection: *quic.one_rtt.Connection,
) Error!void {
    // Send progress depends only on ACK/credit/recovery state. Avoid creating
    // owned packet diagnostics that this pump would immediately discard.
    try connection.servicePacketServicingTimers();
}

fn ensureDeadline(
    connection: *quic.one_rtt.Connection,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    }
}

fn monotonicNowNs(connection: *const quic.one_rtt.Connection) u64 {
    const timestamp = std.Io.Clock.awake.now(connection.endpoint.io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

fn receiveSendProgressUntil(
    connection: *quic.one_rtt.Connection,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    if (deadline) |absolute| {
        return connection.servicePacketServicingTimersDeadline(absolute);
    }
    return connection.servicePacketServicingTimers();
}

fn waitForPacingUntil(
    connection: *quic.one_rtt.Connection,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    if (deadline) |absolute| {
        return connection.waitForPacingAvailabilityWithDeadline(absolute);
    }
    return connection.waitForPacingAvailability();
}

pub fn receive(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
) Error!OwnedHandshakeStream {
    return receiveWithProgress(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        null,
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
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return receiveWithProgress(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        deadline,
        null,
    );
}

pub fn receiveWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) (Error || quic.runtime.ReceiveTimeoutError)!OwnedHandshakeStream {
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        if (progress) |owner| try owner.maintain(deadline);
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
    return pollInternal(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        false,
    );
}

/// Take one FIN-complete associated stream without waiting for receive-credit
/// pacing. Transport bytes and the allocated payload remain uncommitted on
/// backpressure so a dispatcher can retry the same stream later.
pub fn pollOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
) Error!?OwnedHandshakeStream {
    return pollInternal(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        true,
    );
}

fn pollInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
    single_attempt: bool,
) Error!?OwnedHandshakeStream {
    if (connection_lifecycle.terminating(connection)) return error.ConnectionClosed;
    const drained = try association.drainAbandonedReceives(
        connection,
        registry,
        single_attempt,
    );
    if (single_attempt and drained) return null;
    for (registry.registered()) |*stream| {
        if (stream.receive_mode == .incremental or stream.reset_reported or
            stream.receive_reset == null or
            stream.receive_reset_final_size == null)
        {
            continue;
        }
        if (stream.receive_mode == .unset) stream.receive_mode = .whole;
        stream.reset_reported = true;
        return error.InvalidStreamState;
    }
    var stream_ids: [256]u62 = undefined;
    var after: ?u62 = null;
    var saw_stream_limit = false;
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
            var transport_progressed = false;
            if (try takeHandshakeSessionStream(
                connection,
                registry,
                session_id,
                stream_id,
                max_stream_bytes,
                single_attempt,
                &transport_progressed,
                &saw_stream_limit,
            )) |stream| return stream;
            if (single_attempt and transport_progressed) return null;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) {
            if (saw_stream_limit) return error.StreamLimitExceeded;
            return null;
        }
    }
}

fn takeHandshakeSessionStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    max_stream_bytes: usize,
    single_attempt: bool,
    transport_progressed: *bool,
    saw_stream_limit: *bool,
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
    const identification = (if (single_attempt)
        association.identifyClassifiedOnce(
            connection,
            registry,
            session_id,
            stream_id,
            .whole,
        )
    else
        association.identifyClassified(
            connection,
            registry,
            session_id,
            stream_id,
            .whole,
        )) catch |err| switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        => return null,
        else => return err,
    };
    const stream = switch (identification) {
        .associated => |value| value,
        .rejected => |progressed| {
            transport_progressed.* = progressed;
            return null;
        },
        .unclaimed => return null,
    };
    const stats = connection.recvStreamStats(stream_id) orelse return null;
    if (stats.reset) |reset| {
        if (reset.reliable_size != 0 and
            stats.bytes_read + available.len < reset.reliable_size)
        {
            return null;
        }
        if (stream.receive_reset == null) {
            stream.receive_reset = .fromHttp3(
                reset.application_error_code,
            );
            stream.receive_reset_final_size = reset.final_size;
        }
        _ = try connection.discardResetReceived(stream_id);
        flow_receive.consumeAbandoned(registry, stream);
        _ = try association.requestTransportRetirement(connection, stream);
        stream.reset_reported = true;
        return error.InvalidStreamState;
    }
    if (stream.receive_reset != null) return error.InvalidStreamState;
    if (stream.stop_sent != null) return null;
    const prefix_len = stream.receive_prefix_len;

    const lengths = try wholeStreamLengths(
        stats.final_size orelse return null,
        prefix_len,
    );
    if (lengths.payload > max_stream_bytes) {
        // The aggregate limit belongs to this API, not to the protocol or the
        // peer. Leave every byte unconsumed and release only the whole-stream
        // claim so the application can drain the stream incrementally. Keep
        // scanning as a smaller ready sibling may still satisfy this poll.
        stream.receive_mode = .unset;
        saw_stream_limit.* = true;
        return null;
    }
    if (!stream.prefix_received or available.len < lengths.wire) {
        return null;
    }
    const payload = try connection.endpoint.allocator.dupe(
        u8,
        available[prefix_len..lengths.wire],
    );
    var payload_owned = true;
    defer if (payload_owned) connection.endpoint.allocator.free(payload);
    const release_result = if (single_attempt)
        connection.tryReleaseReceivedCapacity(
            stream_id,
            lengths.wire,
        )
    else
        connection.releaseReceivedCapacity(
            stream_id,
            lengths.wire,
        );
    release_result catch |err| switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        => return null,
        else => return err,
    };
    _ = try association.requestTransportRetirement(connection, stream);
    try registry.recordReceived(stream_id, lengths.payload, true);
    flow_receive.consume(registry, stream, lengths.payload);
    payload_owned = false;
    return .{
        .allocator = connection.endpoint.allocator,
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .payload = payload,
        .fin = true,
    };
}

test "WebTransport whole-stream oversize advances sibling and permits incremental drain" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8d} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-limit-server",
        .peer_connection_id = "wt-limit-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var header_storage: [16]u8 = undefined;
    const header = try webtransport.BidirectionalStreamHeader.writeInto(
        &header_storage,
        session_id,
    );
    const oversized_payload = "0123456789abcdefg";
    var oversized_storage: [64]u8 = undefined;
    const oversized = oversized_storage[0 .. header.len + oversized_payload.len];
    @memcpy(oversized[0..header.len], header);
    @memcpy(oversized[header.len..], oversized_payload);
    var sibling_storage: [32]u8 = undefined;
    const sibling_payload = "sibling";
    const sibling_bytes = sibling_storage[0 .. header.len + sibling_payload.len];
    @memcpy(sibling_bytes[0..header.len], header);
    @memcpy(sibling_bytes[header.len..], sibling_payload);
    // First observe the oversized stream before FIN. This commits its parsed
    // association and `.whole` claim in an earlier poll turn.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = oversized,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) == null);
    try std.testing.expectEqual(
        webtransport.ReceiveMode.whole,
        registry.get(4).?.receive_mode,
    );

    // A later FIN reveals the aggregate mismatch. The scanner must release
    // the old whole-stream claim and continue to the ready sibling.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .offset = oversized.len,
                .data = &.{},
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = sibling_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var sibling = (try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) orelse return error.TestUnexpectedResult;
    defer sibling.deinit();
    try std.testing.expectEqual(@as(u62, 8), sibling.stream_id);
    try std.testing.expectEqualStrings(sibling_payload, sibling.payload);

    // With no smaller sibling left, surface the aggregate API mismatch while
    // preserving the stream for a caller-buffer read.
    try std.testing.expectError(
        error.StreamLimitExceeded,
        poll(&connection, &registry, session_id, 16),
    );
    try std.testing.expectEqual(
        webtransport.ReceiveMode.unset,
        registry.get(4).?.receive_mode,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(4).?.bytes_read,
    );

    var out: [32]u8 = undefined;
    const event = (try @import("stream_incremental.zig").poll(
        &connection,
        &registry,
        session_id,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(@as(u62, 4), event.data.stream_id);
    try std.testing.expectEqualStrings(
        oversized_payload,
        out[0..event.data.bytes],
    );
    try std.testing.expect(event.data.fin);
}

test "WebTransport whole-stream poll rejects wrong-session uni and advances sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8e} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-wrong-uni-server",
        .peer_connection_id = "wt-wrong-uni-client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 1, .max_peer_uni = 1 },
    );
    defer registry.deinit();

    var wrong: std.ArrayList(u8) = .empty;
    defer wrong.deinit(allocator);
    try webtransport.UnidirectionalStreamHeader.writeWebTransport(
        &wrong,
        allocator,
        .init(4),
    );
    try wrong.appendSlice(allocator, "bad");
    var valid_header_storage: [16]u8 = undefined;
    const valid_header = try webtransport.BidirectionalStreamHeader.writeInto(
        &valid_header_storage,
        session_id,
    );
    var valid_bytes_storage: [32]u8 = undefined;
    const valid_bytes = valid_bytes_storage[0 .. valid_header.len + "ok".len];
    @memcpy(valid_bytes[0..valid_header.len], valid_header);
    @memcpy(valid_bytes[valid_header.len..], "ok");
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .stream = .{ .stream_id = 2, .data = wrong.items } },
            .{ .stream = .{
                .stream_id = 4,
                .data = valid_bytes,
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var sibling = (try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) orelse return error.TestUnexpectedResult;
    defer sibling.deinit();
    try std.testing.expectEqual(@as(u62, 4), sibling.stream_id);
    try std.testing.expectEqualStrings("ok", sibling.payload);
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expect(connection.sendStreamStats(2) == null);
    try std.testing.expectEqual(
        webtransport.ApplicationErrorCode.buffered_stream_rejected,
        connection.recvStreamStats(2).?.stop_sending_sent.?
            .application_error_code,
    );
    var rejection_datagram = try sender.receiveBytes();
    defer rejection_datagram.deinit(allocator);
    var rejection = try quic.one_rtt.openReceivedBytes(
        &sender,
        rejection_datagram.from,
        rejection_datagram.bytes,
        keys,
        "wt-wrong-uni-client".len,
        0,
        4,
    );
    defer rejection.deinit(allocator);
    var saw_stop = false;
    for (rejection.frames) |frame| switch (frame) {
        .stop_sending => |stop_info| {
            try std.testing.expectEqual(@as(u64, 2), stop_info.stream_id);
            try std.testing.expectEqual(
                webtransport.ApplicationErrorCode.buffered_stream_rejected,
                stop_info.application_error_code,
            );
            saw_stop = true;
        },
        .reset_stream => return error.TestUnexpectedResult,
        else => {},
    };
    try std.testing.expect(saw_stop);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 2).?,
    );

    // Late bytes on the rejected stream are discarded, and FIN lets QUIC
    // return its stream slot without ever admitting it to this session.
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .stream = .{
            .stream_id = 2,
            .offset = wrong.items.len,
            .data = "late",
            .fin = true,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expect((try poll(
        &connection,
        &registry,
        session_id,
        16,
    )) == null);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(connection.recvStreamStats(2) == null);
    try std.testing.expect(registry.get(2) == null);
}

test "WebTransport whole-stream deadline preserves ready stream before retirement" {
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

    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(2).?.bytes_read,
    );
    try std.testing.expect(registry.get(2) == null);
    try std.testing.expectError(
        error.Timeout,
        receiveWithDeadline(
            &connection,
            &registry,
            session_id,
            64,
            .fromNow(threaded.io(), .{
                .clock = .real,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.recvStreamStats(2).?.bytes_read,
    );
    try std.testing.expect(registry.get(2) == null);

    var stream = try receiveWithDeadline(
        &connection,
        &registry,
        session_id,
        64,
        .fromNow(threaded.io(), .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        }),
    );
    defer stream.deinit();
    try std.testing.expectEqualStrings("payload", stream.payload);
    try std.testing.expect(connection.peerStreamClosed(2));
    try std.testing.expect(registry.get(2) != null);
}

test "WebTransport whole-stream poll drains stopped sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-whole-server",
        .peer_connection_id = "wt-whole-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 16,
        .receive_window = 16,
        .max_receive_window = 16,
        .initial_receive_max_stream_data = 16,
        .stream_receive_window = 16,
        .max_stream_receive_window = 16,
        .initial_receive_max_streams_bidi = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 3 },
    );
    defer registry.deinit();

    var prefix_storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &prefix_storage,
        session_id,
    );
    var cancelled_start: [17]u8 = undefined;
    @memcpy(cancelled_start[0..prefix.len], prefix);
    cancelled_start[prefix.len] = 'a';
    const cancelled_start_len = prefix.len + 1;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = cancelled_start[0..cancelled_start_len],
        } }},
        null,
        .not_ect,
    );
    const cancelled = (try association.identify(
        &connection,
        &registry,
        session_id,
        4,
        .whole,
    )) orelse return error.TestUnexpectedResult;
    const stop_code = webtransport.applicationErrorCodeToHttp3(22);
    try connection.sendStopSending(4, stop_code);
    cancelled.stop_sent = .fromHttp3(stop_code);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);

    var target_bytes: [18]u8 = undefined;
    @memcpy(target_bytes[0..prefix.len], prefix);
    @memcpy(target_bytes[prefix.len..][0..2], "ok");
    const target_len = prefix.len + 2;
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{
            .{ .stream = .{
                .stream_id = 4,
                .offset = cancelled_start_len,
                .data = "late",
                .fin = true,
            } },
            .{ .stream = .{
                .stream_id = 8,
                .data = target_bytes[0..target_len],
                .fin = true,
            } },
        },
        null,
        .not_ect,
    );

    var target = (try poll(
        &connection,
        &registry,
        session_id,
        64,
    )) orelse return error.TestUnexpectedResult;
    defer target.deinit();
    try std.testing.expectEqual(@as(u62, 8), target.stream_id);
    try std.testing.expectEqualStrings("ok", target.payload);
    try std.testing.expectEqual(
        @as(usize, 0),
        quic.one_rtt.testing.receiveStreamAvailableLen(&connection, 4).?,
    );
    try std.testing.expectEqual(
        @as(u64, 16),
        connection.recvStreamStats(4).?.receive_limit,
    );
    try std.testing.expect(registry.get(4).?.peer_fin);
}

test "WebTransport whole-stream stopped reset remains observable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-server",
        .peer_connection_id = "wt-reset-client",
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .max_receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .max_stream_receive_window = 8,
        .initial_receive_max_streams_bidi = 2,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_peer_bidi = 2 },
    );
    defer registry.deinit();

    var storage: [16]u8 = undefined;
    const prefix = try webtransport.BidirectionalStreamHeader.writeInto(
        &storage,
        session_id,
    );
    var initial: [17]u8 = undefined;
    @memcpy(initial[0..prefix.len], prefix);
    initial[prefix.len] = 'x';
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{.{ .stream = .{
            .stream_id = 4,
            .data = initial[0 .. prefix.len + 1],
        } }},
        null,
        .not_ect,
    );
    const stream = (try association.identify(
        &connection,
        &registry,
        session_id,
        4,
        .whole,
    )) orelse return error.TestUnexpectedResult;
    const stop_code = webtransport.applicationErrorCodeToHttp3(23);
    try connection.sendStopSending(4, stop_code);
    stream.stop_sent = .fromHttp3(stop_code);
    var stop_datagram = try sender.receiveBytes();
    defer stop_datagram.deinit(allocator);
    var stop_credit_datagram = try sender.receiveBytes();
    defer stop_credit_datagram.deinit(allocator);
    var stop_credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        stop_credit_datagram.from,
        stop_credit_datagram.bytes,
        keys,
        "wt-reset-client".len,
        1,
        8,
    );
    defer stop_credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), stop_credit.frames.len);
    try std.testing.expect(stop_credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 12),
        stop_credit.frames[0].max_data.maximum_data,
    );

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        1,
        &.{.{ .reset_stream = .{
            .stream_id = 4,
            .application_error_code = stop_code,
            .final_size = 8,
        } }},
        null,
        .not_ect,
    );
    try std.testing.expectError(
        error.InvalidStreamState,
        poll(&connection, &registry, session_id, 64),
    );
    try std.testing.expect(registry.get(4).?.receive_reset != null);
    try std.testing.expectEqual(
        @as(u64, 8),
        connection.recvStreamStats(4).?.receive_limit,
    );
    var credit_datagram = try sender.receiveBytes();
    defer credit_datagram.deinit(allocator);
    var credit = try quic.one_rtt.openReceivedBytes(
        &sender,
        credit_datagram.from,
        credit_datagram.bytes,
        keys,
        "wt-reset-client".len,
        stop_credit.packet.packet_number + 1,
        8,
    );
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), credit.frames.len);
    try std.testing.expect(credit.frames[0] == .max_data);
    try std.testing.expectEqual(
        @as(u64, 16),
        credit.frames[0].max_data.maximum_data,
    );
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

test "WebTransport complete stream send batches consecutive packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-batch-client",
        .peer_connection_id = "wt-batch-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    const ObservedBatchSend =
        @import("../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{ .delegate = sender_endpoint.io };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0xa5} ** 10_000;
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &payload,
        false,
    );

    // One association-prefix send is followed by one three-datagram
    // application batch: 3968 + 3968 + 2064 bytes.
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expectEqual(@as(usize, 3), observed.last_message_count);
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 4), connection.stats().packets_sent);
}

test "WebTransport complete stream batch commits only socket prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd9} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-prefix-client",
        .peer_connection_id = "wt-prefix-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    _ = try prepare(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
    );
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);

    const ObservedBatchSend =
        @import("../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{
        .delegate = sender_endpoint.io,
        .fail_after_prefix = 0,
    };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0x5a} ** 10_000;
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &payload,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);

    observed.fail_after_prefix = 1;
    try std.testing.expectError(
        error.NetworkDown,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &payload,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    const first_packet_bytes: usize = 4096 - 128;
    try std.testing.expectEqual(first_packet_bytes, committed);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expectEqual(@as(usize, 3), observed.last_message_count);
    try std.testing.expectEqual(
        @as(u64, first_packet_bytes),
        stream.bytes_sent,
    );
    try std.testing.expectEqual(
        @as(u64, first_packet_bytes + 3),
        stream.send_offset,
    );

    sender_endpoint.io = observed.delegate;
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        payload[first_packet_bytes..],
        false,
    );
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
}

test "WebTransport stream slice batch commits only socket prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-vect-client",
        .peer_connection_id = "wt-vect-server",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    _ = try prepare(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
    );

    const ObservedBatchSend =
        @import("../../quic/one_rtt/tests/observed_batch_send.zig")
            .ObservedBatchSend;
    var observed = ObservedBatchSend{
        .delegate = sender_endpoint.io,
        .fail_after_prefix = 1,
    };
    var observed_vtable = sender_endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    sender_endpoint.io = .{
        .userdata = &observed,
        .vtable = &observed_vtable,
    };
    defer sender_endpoint.io = observed.delegate;

    const payload = [_]u8{0x5b} ** 10_000;
    const parts = [_][]const u8{ "ab", &.{}, payload[0..4000], payload[4000..] };
    var committed: usize = 99;
    try std.testing.expectError(
        error.NetworkDown,
        sendSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &parts,
            false,
            &committed,
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(committed > 2);
    try std.testing.expect(committed < 2 + payload.len);
    try std.testing.expectEqual(@as(usize, 1), observed.calls);
    try std.testing.expect(observed.last_message_count > 1);
    try std.testing.expectEqual(@as(u64, committed), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, committed + 3), stream.send_offset);

    sender_endpoint.io = observed.delegate;
    try sendSlices(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{payload[committed - 2 ..]},
        false,
    );
    try std.testing.expectEqual(@as(u64, 2 + payload.len), stream.bytes_sent);
    try std.testing.expectEqual(
        @as(u64, 2 + payload.len + 3),
        stream.send_offset,
    );
}

test "WebTransport deadline send reports committed prefix and resumes after credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xda} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline-client",
        .peer_connection_id = "wt-deadline-server",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data_bidi_remote = 8,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const payload = "abcdefghijkl";

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            payload,
            true,
            &committed,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqual(@as(u64, 5), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8), stream.send_offset);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try sendWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        payload[committed..],
        true,
        &committed,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(@as(usize, 7), committed);
    try std.testing.expectEqual(@as(u64, payload.len), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, payload.len + 3), stream.send_offset);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream slices report cross-slice committed prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdd} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-slices-client",
        .peer_connection_id = "wt-slices-server",
        .initial_send_max_data = 8,
        .initial_send_max_stream_data_bidi_remote = 8,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const parts = [_][]const u8{ "ab", &.{}, "cdef", "ghijkl" };

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &parts,
            true,
            &committed,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    // Three association bytes consume the first eight bytes of stream credit.
    // The five committed application bytes cross the "ab"/"cdef" slice
    // boundary and are reported as one logical prefix.
    try std.testing.expectEqual(@as(usize, 5), committed);
    try std.testing.expectEqual(@as(u64, 5), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 8), stream.send_offset);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try sendSlicesWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "f", &.{}, "ghijkl" },
        true,
        &committed,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(@as(usize, 7), committed);
    try std.testing.expectEqual(@as(u64, 12), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 15), stream.send_offset);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream slice write fills one packet across boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdf} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-write-server",
        .peer_connection_id = "wt-write-client",
        .max_datagram_size = 512,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const long = [_]u8{0xa5} ** 600;

    const first = try writeSlices(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "ab", &.{}, "cdef", &long },
    );
    try std.testing.expect(first > 6);
    try std.testing.expect(first < 6 + long.len);
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, first), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, first + 3), stream.send_offset);

    var committed = first;
    while (committed < 6 + long.len) {
        const remaining = committed - 6;
        const count = try writeSlicesWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &.{long[remaining..]},
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        );
        try std.testing.expect(count != 0);
        committed += count;
    }
    try std.testing.expectEqual(@as(usize, 606), committed);
    try std.testing.expectEqual(@as(u64, 606), stream.bytes_sent);
    try finish(&connection, &registry, session_id, stream.stream_id);
    try std.testing.expect(stream.local_fin);
}

test "WebTransport stream deadline rejects wrong clock without mutation" {
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
        [_]u8{0xdb} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-clock-client",
        .peer_connection_id = "wt-clock-server",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const wrong_clock: std.Io.Clock.Timestamp = .{
        .clock = .real,
        .raw = .fromNanoseconds(std.time.ns_per_s),
    };

    var committed: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        sendWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            false,
            &committed,
            wrong_clock,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expectError(
        error.Timeout,
        writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            wrong_clock,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        finishWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            wrong_clock,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        @import("stream_incremental.zig").resetWithDeadline(
            &connection,
            &registry,
            stream.stream_id,
            42,
            wrong_clock,
        ),
    );
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(?webtransport.StreamError, null), stream.send_reset);
}

test "WebTransport bounded write and finish preserve retryable stream state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdc} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-write-client",
        .peer_connection_id = "wt-write-server",
        .initial_send_max_data = 3,
        .initial_send_max_stream_data_bidi_remote = 3,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try std.testing.expectError(
        error.Timeout,
        writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 3), stream.send_offset);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expect(!stream.local_fin);

    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            .{ .max_data = .{ .maximum_data = 64 } },
            .{ .max_stream_data = .{
                .stream_id = stream.stream_id,
                .maximum_stream_data = 64,
            } },
        },
        null,
        .not_ect,
    );
    try std.testing.expectEqual(
        @as(usize, 7),
        try writeWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            "payload",
            .fromNow(io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(u64, 7), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(&connection);
    try std.testing.expectError(
        error.Timeout,
        finishWithDeadline(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
    quic.one_rtt.testing.acknowledgeAllInFlight(&connection);
    try finishWithDeadline(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 10), stream.send_offset);
}

test "WebTransport bounded reset preserves retryable stream state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var silent_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer silent_peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xdd} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = silent_peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-reset-client",
        .peer_connection_id = "wt-reset-server",
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .client,
        .{ .max_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    try send(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        "payload",
        false,
    );

    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(&connection);
    try std.testing.expectError(
        error.Timeout,
        @import("stream_incremental.zig").resetWithDeadline(
            &connection,
            &registry,
            stream.stream_id,
            42,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(
        @as(?webtransport.StreamError, null),
        stream.send_reset,
    );

    quic.one_rtt.testing.acknowledgeAllInFlight(&connection);
    try @import("stream_incremental.zig").resetWithDeadline(
        &connection,
        &registry,
        stream.stream_id,
        42,
        .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    );
    try std.testing.expectEqual(
        @as(u32, 42),
        stream.send_reset.?.application_code,
    );
}

test "WebTransport single-attempt send atomically includes prefix payload and FIN" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-once-server",
        .peer_connection_id = "wt-once-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_local_bidi = 1, .first_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try sendOnce(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        "atomic",
        true,
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 6), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 9), stream.send_offset);

    var packet = try quic.one_rtt.receive(
        &receiver_endpoint,
        keys,
        "wt-once-client".len,
        0,
        4,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), packet.frames.len);
    try std.testing.expect(packet.frames[0] == .stream);
    try std.testing.expectEqual(@as(u64, 0), packet.frames[0].stream.offset);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x41, 0x00 },
        packet.frames[0].stream.data,
    );
    try std.testing.expect(!packet.frames[0].stream.fin);
    try std.testing.expect(packet.frames[1] == .stream);
    try std.testing.expectEqual(@as(u64, 3), packet.frames[1].stream.offset);
    try std.testing.expectEqualStrings("atomic", packet.frames[1].stream.data);
    try std.testing.expect(packet.frames[1].stream.fin);
}

test "WebTransport single-attempt slices are atomic and preserve boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xde} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&sender_endpoint, .{
        .peer = receiver_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-slice-server",
        .peer_connection_id = "wt-slice-client",
        .local_endpoint = .server,
        .max_frames_per_packet = 4,
        .enable_pacing = false,
    });
    defer connection.deinit();
    const session_id: webtransport.SessionId = .init(0);
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        session_id,
        .server,
        .{ .max_local_bidi = 1, .first_local_bidi = 1 },
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);

    try std.testing.expectError(
        error.DatagramTooLarge,
        sendSlicesOnce(
            &connection,
            &registry,
            session_id,
            stream.stream_id,
            &.{ "a", "b", "c", "d" },
            true,
        ),
    );
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
    try std.testing.expect(!stream.local_fin);
    try std.testing.expectEqual(@as(u64, 0), connection.stats().packets_sent);

    try sendSlicesOnce(
        &connection,
        &registry,
        session_id,
        stream.stream_id,
        &.{ "at", &.{}, "om", "ic" },
        true,
    );
    try std.testing.expect(stream.prefix_sent);
    try std.testing.expect(stream.local_fin);
    try std.testing.expectEqual(@as(u64, 6), stream.bytes_sent);
    try std.testing.expectEqual(@as(u64, 9), stream.send_offset);

    var packet = try quic.one_rtt.receive(
        &receiver_endpoint,
        keys,
        "wt-slice-client".len,
        0,
        8,
    );
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), packet.frames.len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x41, 0x00 },
        packet.frames[0].stream.data,
    );
    try std.testing.expectEqualStrings(
        "at",
        packet.frames[1].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 3), packet.frames[1].stream.offset);
    try std.testing.expectEqualStrings(
        "om",
        packet.frames[2].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 5), packet.frames[2].stream.offset);
    try std.testing.expectEqualStrings(
        "ic",
        packet.frames[3].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 7), packet.frames[3].stream.offset);
    try std.testing.expect(!packet.frames[0].stream.fin);
    try std.testing.expect(!packet.frames[1].stream.fin);
    try std.testing.expect(!packet.frames[2].stream.fin);
    try std.testing.expect(packet.frames[3].stream.fin);
}
