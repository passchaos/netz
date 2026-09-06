//! Incremental caller-buffer WebTransport stream reads and cancellation.

const std = @import("std");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const association = @import("stream_association.zig");

pub const Error = association.Error;

pub const Read = union(enum) {
    data: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        bytes: usize,
        /// True when these are the final application bytes, or when FIN was
        /// already consumed and this is the stream's zero-byte EOF event.
        fin: bool,
    },
    reset: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        error_info: webtransport.StreamError,
        final_size: u64,
    },
    stopped: struct {
        stream_id: u62,
        direction: webtransport.StreamDirection,
        locally_initiated: bool,
        error_info: webtransport.StreamError,
    },
};

/// Read the next stream event into caller storage without waiting for FIN.
///
/// Each returned data prefix is immediately released to QUIC flow control, so
/// a long-lived stream can exceed its receive window without whole-body
/// retention. The supplied buffer must be non-empty.
pub fn read(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!Read {
    if (out.len == 0) return error.BufferTooShort;
    while (true) {
        if (try poll(connection, registry, session_id, out)) |event| {
            return event;
        }

        // `poll` reads assembled QUIC stream state, so packet plaintext and
        // frame arrays do not need ownership beyond transport processing.
        try connection.servicePacketServicingTimers();
    }
}

/// Deadline-bounded counterpart to `read`. One absolute deadline spans all
/// unrelated/control packets and any earlier QUIC transport timers.
pub fn readWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!Read {
    if (out.len == 0) return error.BufferTooShort;
    while (true) {
        if (try poll(connection, registry, session_id, out)) |event| {
            return event;
        }
        try connection.servicePacketServicingTimersDeadline(deadline);
    }
}

/// Abort the local send direction with a mapped WebTransport error code.
pub fn reset(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStream(stream_id, http3_code);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction once without sleeping for QUIC pacing.
/// Registry state changes only after the RESET_STREAM packet is submitted.
pub fn resetOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.tryResetStream(stream_id, http3_code);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Cancel the peer send direction with a mapped WebTransport error code.
pub fn stop(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.sendStopSending(stream_id, http3_code);
    stream.stop_sent = .fromHttp3(http3_code);
}

/// Cancel the peer send direction once without sleeping for QUIC pacing.
/// Registry state changes only after STOP_SENDING reaches the socket.
pub fn stopOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.trySendStopSending(stream_id, http3_code);
    stream.stop_sent = .fromHttp3(http3_code);
}

pub fn poll(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!?Read {
    return pollInternal(connection, registry, session_id, out, false);
}

/// Poll one buffered stream event without waiting for receive-credit pacing.
/// Application bytes are returned only after the matching QUIC receive cursor
/// has committed, so retrying never duplicates a delivered payload.
pub fn pollOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
) Error!?Read {
    return pollInternal(connection, registry, session_id, out, true);
}

fn pollInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    out: []u8,
    single_attempt: bool,
) Error!?Read {
    if (try pollKnownStopped(connection, registry)) |event| return event;

    var stream_ids: [256]u62 = undefined;
    const previous = registry.incremental_poll_cursor;
    var after = previous;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |stream_id| {
            if (try pollStreamId(
                connection,
                registry,
                session_id,
                stream_id,
                out,
                single_attempt,
            )) |event| return event;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) break;
    }
    if (previous == null) return null;

    // Wrap to the lowest active ID. The cursor is an ID rather than a physical
    // table slot, so reclaiming its stream between calls cannot skip a moved
    // entry.
    after = null;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |stream_id| {
            if (stream_id > previous.?) return null;
            if (try pollStreamId(
                connection,
                registry,
                session_id,
                stream_id,
                out,
                single_attempt,
            )) |event| return event;
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) return null;
    }
}

fn pollStreamId(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    single_attempt: bool,
) Error!?Read {
    // Association-prefix parsing, rather than numeric guesses, distinguishes
    // HTTP/3 critical/push streams from WebTransport.
    if (stream_id == session_id.value) return null;
    const event = try pollStream(
        connection,
        registry,
        session_id,
        stream_id,
        out,
        single_attempt,
    ) orelse return null;
    registry.incremental_poll_cursor = switch (event) {
        inline else => |value| value.stream_id,
    };
    return event;
}

fn pollStream(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    out: []u8,
    single_attempt: bool,
) Error!?Read {
    // A session can mix whole-stream and incremental consumption as long as a
    // single receive direction never changes mode. Skip streams claimed by
    // the whole-stream reader so an already-consumed stream cannot prevent
    // incremental events from other associated streams being observed.
    if (registry.get(stream_id)) |registered| {
        if (registered.receive_mode == .whole) return null;
    }
    const stream = (if (single_attempt)
        association.identifyOnce(
            connection,
            registry,
            session_id,
            stream_id,
            .incremental,
        )
    else
        association.identify(
            connection,
            registry,
            session_id,
            stream_id,
            .incremental,
        )) catch |err| switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        => return null,
        else => return err,
    } orelse return null;

    if (connection.sendStreamStats(stream_id)) |stats| {
        if (stats.reset) |reset_info| {
            stream.send_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        if (stats.stopped) |stopped| {
            if (stream.stopped == null) {
                stream.stopped =
                    .fromHttp3(stopped.application_error_code);
            }
            if (!stream.stopped_reported) {
                stream.stopped_reported = true;
                return stoppedEvent(stream, stream_id);
            }
        }
    }

    const recv_stats = connection.recvStreamStats(stream_id) orelse
        return null;
    if (recv_stats.reset) |reset_info| {
        if (stream.receive_reset == null) {
            stream.receive_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        if (!stream.reset_reported) {
            // RESET_STREAM terminates the receive direction at packet
            // application time. It can overtake earlier STREAM packets, so
            // retained or later-arriving bytes are never exposed after reset.
            _ = try association.requestTransportRetirement(connection, stream);
            stream.reset_reported = true;
            return resetEvent(stream, stream_id, reset_info.final_size);
        }
        return null;
    }
    if (stream.stop_sent != null) {
        // Bytes already in flight remain bounded in QUIC but are not delivered
        // after the application has cancelled this receive direction.
        return null;
    }

    const available = connection.availableReceivedStream(stream_id) orelse
        return null;
    if (available.len != 0) {
        const count = @min(out.len, available.len);
        @memcpy(out[0..count], available[0..count]);
        const fin = recv_stats.reset == null and
            recv_stats.final_size != null and
            recv_stats.bytes_read + count == recv_stats.final_size.?;
        const previous_stream = stream.*;
        try registry.recordReceived(stream_id, count, fin);
        const release_result = if (single_attempt)
            connection.tryReleaseReceivedCapacity(stream_id, count)
        else
            connection.releaseReceivedCapacity(stream_id, count);
        release_result catch |err| switch (err) {
            error.PacingLimited,
            error.CongestionLimited,
            error.FlowControlBlocked,
            => {
                stream.* = previous_stream;
                return null;
            },
            else => {
                stream.* = previous_stream;
                return err;
            },
        };
        if (fin) {
            _ = association.requestTransportRetirement(
                connection,
                stream,
            ) catch unreachable;
        }
        return dataEvent(stream, stream_id, count, fin);
    }
    if (recv_stats.final_size != null and
        recv_stats.bytes_read == recv_stats.final_size.? and
        !stream.peer_fin)
    {
        _ = try association.requestTransportRetirement(connection, stream);
        try registry.recordReceived(stream_id, 0, true);
        return dataEvent(stream, stream_id, 0, true);
    }
    return null;
}

fn pollKnownStopped(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!?Read {
    for (registry.registered()) |*stream| {
        const stats = connection.sendStreamStats(stream.stream_id) orelse
            continue;
        if (stats.reset) |reset_info| {
            stream.send_reset =
                .fromHttp3(reset_info.application_error_code);
        }
        const stopped = stats.stopped orelse continue;
        if (stream.stopped == null) {
            stream.stopped = .fromHttp3(stopped.application_error_code);
        }
        if (stream.stopped_reported) continue;
        try association.requestAfterSendTerminal(connection, stream);
        stream.stopped_reported = true;
        return stoppedEvent(stream, stream.stream_id);
    }
    return null;
}

fn dataEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
    bytes: usize,
    fin: bool,
) Read {
    return .{ .data = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .bytes = bytes,
        .fin = fin,
    } };
}

fn resetEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
    final_size: u64,
) Read {
    return .{ .reset = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .error_info = stream.receive_reset.?,
        .final_size = final_size,
    } };
}

fn stoppedEvent(
    stream: *const webtransport.StreamState,
    stream_id: u62,
) Read {
    return .{ .stopped = .{
        .stream_id = stream_id,
        .direction = stream.direction,
        .locally_initiated = stream.locally_initiated,
        .error_info = stream.stopped.?,
    } };
}

test "WebTransport incremental polling rotates across busy streams" {
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
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-fair-server",
        .peer_connection_id = "wt-fair-client",
        .local_endpoint = .server,
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

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &encoded,
        allocator,
        session_id,
    );
    try encoded.appendSlice(allocator, "busy");
    var idle: std.ArrayList(u8) = .empty;
    defer idle.deinit(allocator);
    try webtransport.BidirectionalStreamHeader.write(
        &idle,
        allocator,
        session_id,
    );
    try quic.one_rtt.testing.applyReceivedFrames(
        &connection,
        0,
        &.{
            // An unrelated HTTP/3 unidirectional stream and an associated but
            // idle stream must not interfere with the ready-stream rotation.
            .{ .stream = .{ .stream_id = 2, .data = &.{0} } },
            .{ .stream = .{ .stream_id = 4, .data = encoded.items } },
            .{ .stream = .{ .stream_id = 12, .data = idle.items } },
            .{ .stream = .{ .stream_id = 8, .data = encoded.items } },
        },
        null,
        .not_ect,
    );

    var byte: [1]u8 = undefined;
    const first = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 4), first.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    // Stream four still has immediately readable bytes, but the stable cursor
    // gives its equally busy sibling the next application scheduling turn.
    const second = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 8), second.data.stream_id);
    try std.testing.expectEqualStrings("b", &byte);

    const wrapped = (try poll(
        &connection,
        &registry,
        session_id,
        &byte,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(wrapped == .data);
    try std.testing.expectEqual(@as(u62, 4), wrapped.data.stream_id);
    try std.testing.expectEqualStrings("u", &byte);
}
