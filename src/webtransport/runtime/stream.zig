const std = @import("std");
const bounded_packets = @import("../../quic/one_rtt/send_deadline.zig");
const association_send = @import("stream/association_send.zig");
const receive_credit = @import("stream/receive_credit.zig");
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
const send_wait = @import("stream/wait.zig");
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

pub fn wholeStreamLengths(
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

/// Relative-timeout counterpart to `send`. A non-positive duration returns
/// `Timeout` with `committed_out` cleared before any transport work.
pub fn sendWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    fin: bool,
    committed_out: *usize,
    timeout: std.Io.Duration,
) TimeoutError!void {
    committed_out.* = 0;
    return sendWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        fin,
        committed_out,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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

/// Relative-timeout counterpart to `sendSlices`. A non-positive duration
/// returns `Timeout` with `committed_out` cleared before any transport work.
pub fn sendSlicesWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
    committed_out: *usize,
    timeout: std.Io.Duration,
) TimeoutError!void {
    committed_out.* = 0;
    return sendSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        fin,
        committed_out,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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
            registry,
            session_id,
            stream_id,
            deadline,
            progress,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        try ensureDeadline(connection, deadline);
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
            try send_wait.receive(connection, deadline, progress);
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
        var result: quic.one_rtt.ConnectionBatchSendResult = .{ .sent_count = 0, .protected_count = 0 };
        var send_failure: ?TimeoutError = null;
        bounded_packets.manyOptional(connection, packets[0..packet_count], &result, sent_time_ns, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
                continue;
            },
            else => |other| send_failure = other,
        };
        if (result.sent_count > packet_count or
            result.sent_count > result.protected_count)
        {
            return error.Unexpected;
        }
        if (result.sent_count == 0) {
            if (send_failure) |err| return err;
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
        if (send_failure) |err| return err;
        if (result.send_error) |err| return err;
    }
    if (fin) try finishWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
        progress,
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
            registry,
            session_id,
            stream_id,
            deadline,
            progress,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        try ensureDeadline(connection, deadline);
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
            try send_wait.receive(connection, deadline, progress);
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
        var result: quic.one_rtt.ConnectionBatchSendResult = .{ .sent_count = 0, .protected_count = 0 };
        var send_failure: ?TimeoutError = null;
        bounded_packets.manyOptional(connection, packets[0..packet_count], &result, sent_time_ns, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
                continue;
            },
            else => |other| send_failure = other,
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
            if (send_failure) |err| return err;
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
        if (send_failure) |err| return err;
        if (result.send_error) |err| return err;
    }
    if (fin) try finishWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
        progress,
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

/// Relative-timeout counterpart to `write`. A non-positive duration returns
/// `Timeout` before any packet is committed.
pub fn writeWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    payload: []const u8,
    timeout: std.Io.Duration,
) TimeoutError!usize {
    return writeWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        payload,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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

/// Relative-timeout counterpart to `writeSlices`. A non-positive duration
/// returns `Timeout` before any packet is committed.
pub fn writeSlicesWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    parts: []const []const u8,
    timeout: std.Io.Duration,
) TimeoutError!usize {
    return writeSlicesWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        parts,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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
            registry,
            session_id,
            stream_id,
            deadline,
            progress,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        try ensureDeadline(connection, deadline);
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
            try send_wait.receive(connection, deadline, progress);
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
        bounded_packets.oneOptional(connection, frames[0..frame_count], deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
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
            registry,
            session_id,
            stream_id,
            deadline,
            progress,
        );
        try ensureDeadline(connection, deadline);
        try flow_send.wait(registry, progress, deadline);
        try ensureDeadline(connection, deadline);
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
            try send_wait.receive(connection, deadline, progress);
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
        bounded_packets.oneOptional(connection, &frames, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
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
    return finishWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Relative-timeout counterpart to `finish`. A non-positive duration returns
/// `Timeout` while leaving `local_fin` clear.
pub fn finishWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    timeout: std.Io.Duration,
) TimeoutError!void {
    return finishWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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
    return finishWithProgress(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
        null,
    );
}

pub fn finishWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!void {
    _ = try writableStream(registry, stream_id);
    try sendPrefixIfNeededUntil(
        connection,
        registry,
        session_id,
        stream_id,
        deadline,
        progress,
    );
    while (true) {
        try ensureDeadline(connection, deadline);
        if (progress) |owner| try owner.maintain(deadline);
        try ensureDeadline(connection, deadline);
        const stream = try writableStream(registry, stream_id);
        const frames = [_]quic.Frame{.{ .stream = .{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .data = &.{},
            .fin = true,
        } }};
        bounded_packets.oneOptional(connection, &frames, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
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
    try sendPrefixIfNeeded(connection, registry, session_id, stream_id);
    return writableStream(registry, stream_id);
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
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
) Error!void {
    return sendPrefixIfNeededUntil(
        connection,
        registry,
        session_id,
        stream_id,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn sendPrefixIfNeededUntil(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!void {
    while (true) {
        try ensureDeadline(connection, deadline);
        if (progress) |owner| try owner.maintain(deadline);
        try ensureDeadline(connection, deadline);
        const stream = try writableStream(registry, stream_id);
        if (stream.prefix_sent) return;
        var prefix_storage: [16]u8 = undefined;
        const prefix = try association_prefix.header(session_id, stream.direction, &prefix_storage);
        association_send.prefix(connection, stream, stream_id, prefix, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
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

fn sendPrefixOnce(connection: *quic.one_rtt.Connection, stream: *webtransport.StreamState, stream_id: u62, prefix: []const u8) Error!void {
    return association_send.prefix(connection, stream, stream_id, prefix, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
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

/// Relative-timeout counterpart to `receive`. A non-positive duration returns
/// `Timeout` before any socket wait.
pub fn receiveWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    max_stream_bytes: usize,
    timeout: std.Io.Duration,
) (Error || quic.runtime.ReceiveTimeoutError)!OwnedHandshakeStream {
    return receiveWithProgress(
        connection,
        registry,
        session_id,
        max_stream_bytes,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
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

        if (progress) |owner| {
            if (try owner.receive(deadline)) continue;
        }
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
/// pacing. QUIC retains any pending flow advertisement for its connection
/// timer after the allocated payload's receive cursor is committed.
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
    const previous_stream = stream.*;
    try registry.recordReceived(stream_id, lengths.payload, true);
    receive_credit.commit(connection, stream_id, lengths.wire) catch |err| {
        stream.* = previous_stream;
        return err;
    };
    flow_receive.consume(registry, stream, lengths.payload);
    _ = try association.requestTransportRetirement(connection, stream);
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

test {
    _ = @import("stream/tests/handshake_stream.zig");
    _ = @import("stream/tests/socket_deadline.zig");
}
