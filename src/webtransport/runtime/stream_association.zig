//! WebTransport stream association over QUIC stream prefixes.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");

pub const Error = webtransport.Error || quic.one_rtt.Error;

pub const Identification = union(enum) {
    associated: *webtransport.StreamState,
    rejected: bool,
    unclaimed,
};

/// Request transport-state reclamation while retaining WebTransport's
/// session-lifetime registry entry and counters.
pub fn requestTransportRetirement(
    connection: *quic.one_rtt.Connection,
    stream: *const webtransport.StreamState,
) Error!bool {
    return if (stream.locally_initiated)
        connection.requestCompletedLocalStreamRelease(stream.stream_id)
    else
        connection.requestCompletedPeerStreamRelease(stream.stream_id);
}

/// A send terminal is sufficient immediately for a local unidirectional
/// stream. Bidirectional streams wait until the application has also observed
/// peer FIN/RESET, preventing transport reclamation from hiding that event.
pub fn requestAfterSendTerminal(
    connection: *quic.one_rtt.Connection,
    stream: *const webtransport.StreamState,
) Error!void {
    if (stream.direction == .bidirectional and
        !stream.peer_fin and stream.receive_reset == null)
    {
        return;
    }
    _ = try requestTransportRetirement(connection, stream);
}

/// Discard bytes for every receive direction abandoned by local STOP_SENDING
/// or peer RESET_STREAM. This is shared by targeted, whichever-ready, and
/// whole-stream pollers so an application that waits only on a sibling cannot
/// leave connection flow-control credit trapped behind a terminal stream.
/// RESET metadata remains in the session registry for one later application
/// event even if QUIC can reclaim the stream immediately.
pub fn drainAbandonedReceives(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    single_attempt: bool,
) Error!bool {
    var progressed = false;
    for (registry.registered()) |*stream| {
        if (stream.peer_fin) continue;
        const before = connection.recvStreamStats(stream.stream_id) orelse
            continue;
        var fresh_reset = false;
        if (before.reset) |reset| {
            // RESET_STREAM_AT keeps its prefix reliable. Do not let the
            // automatic abandoned-stream sweep consume or retire that prefix
            // before the application has received it through the normal
            // stream polling path.
            if (reset.reliable_size != 0 and
                before.bytes_read < reset.reliable_size)
            {
                continue;
            }
            // RESET_STREAM is application-visible. Preserve its metadata in
            // the session registry before releasing transport storage.
            if (stream.receive_reset == null) {
                stream.receive_reset = .fromHttp3(
                    reset.application_error_code,
                );
                fresh_reset = true;
            }
            if (stream.receive_reset_final_size == null) {
                stream.receive_reset_final_size = reset.final_size;
                fresh_reset = true;
            }
            _ = try connection.discardResetReceived(stream.stream_id);
            try requestAfterSendTerminal(connection, stream);
        } else {
            if (stream.stop_sent == null) continue;
            _ = try connection.discardStoppedReceived(stream.stream_id);
        }
        progressed = progressed or before.available_bytes != 0 or fresh_reset;
        const after = connection.recvStreamStats(stream.stream_id) orelse {
            if (single_attempt and progressed) return true;
            continue;
        };
        if (after.reset == null and after.final_size != null and
            after.bytes_read == after.final_size.?)
        {
            stream.peer_fin = true;
            try requestAfterSendTerminal(connection, stream);
            progressed = true;
        } else {
            std.debug.assert(after.bytes_read >= before.bytes_read);
        }
        // Endpoint pollers promise bounded nonblocking work. After one
        // cancelled receive direction advances, let the dispatcher service
        // timers and other connections before another sweep.
        if (single_attempt and progressed) return true;
    }
    return progressed;
}

/// Identify/register a WebTransport stream after its association prefix is
/// contiguous. Locally-opened bidirectional reverse directions carry no
/// second prefix and are recognized from the existing registry entry.
pub fn identify(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
) Error!?*webtransport.StreamState {
    return switch (try identifyClassified(
        connection,
        registry,
        session_id,
        stream_id,
        receive_mode,
    )) {
        .associated => |stream| stream,
        .rejected, .unclaimed => null,
    };
}

pub fn identifyClassified(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
) Error!Identification {
    return identifyInternal(
        connection,
        registry,
        session_id,
        stream_id,
        receive_mode,
        false,
    );
}

/// Identify an associated stream without waiting while returning prefix
/// receive credit. A backpressure failure removes a newly registered stream,
/// leaving the prefix available for an identical endpoint retry.
pub fn identifyOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
) Error!?*webtransport.StreamState {
    return switch (try identifyClassifiedOnce(
        connection,
        registry,
        session_id,
        stream_id,
        receive_mode,
    )) {
        .associated => |stream| stream,
        .rejected, .unclaimed => null,
    };
}

pub fn identifyClassifiedOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
) Error!Identification {
    return identifyInternal(
        connection,
        registry,
        session_id,
        stream_id,
        receive_mode,
        true,
    );
}

fn isPeerInitiated(
    registry: *const webtransport.StreamRegistry,
    stream_id: u62,
) bool {
    return switch (registry.role) {
        .client => quic.StreamId.init(stream_id).initiator() == .server,
        .server => quic.StreamId.init(stream_id).initiator() == .client,
    };
}

fn rejectionAlreadyStarted(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    direction: webtransport.StreamDirection,
) bool {
    const rejection_code =
        webtransport.ApplicationErrorCode.buffered_stream_rejected;
    if (connection.recvStreamStats(stream_id)) |stats| {
        if (stats.stop_sending_sent) |stop| {
            if (stop.application_error_code == rejection_code) return true;
        }
    }
    if (direction == .bidirectional) {
        if (connection.sendStreamStats(stream_id)) |stats| {
            if (stats.reset) |reset| {
                if (reset.application_error_code == rejection_code) return true;
            }
        }
    }
    return false;
}

/// Reject a syntactically valid WebTransport stream associated with another
/// session. The transport STOP marker also remembers the decision after the
/// association prefix has been discarded, so later STREAM frames are drained
/// instead of being reparsed as a new prefix.
fn rejectWrongSession(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    direction: webtransport.StreamDirection,
    single_attempt: bool,
) Error!bool {
    const rejection_code =
        webtransport.ApplicationErrorCode.buffered_stream_rejected;
    const already_started =
        rejectionAlreadyStarted(connection, stream_id, direction);
    switch (direction) {
        .bidirectional => if (single_attempt)
            try connection.tryCancelStream(stream_id, rejection_code)
        else
            try connection.cancelStream(stream_id, rejection_code),
        .unidirectional => if (single_attempt)
            try connection.trySendStopSending(stream_id, rejection_code)
        else
            try connection.sendStopSending(stream_id, rejection_code),
    }
    // A one-attempt dispatcher call performs no second socket submission after
    // it first publishes the rejection. A later poll will drain and retire the
    // stream through the already-committed, idempotent terminal state.
    if (single_attempt and !already_started) return true;

    const discarded = try connection.discardStoppedReceived(stream_id);
    // A peer FIN/RESET makes retirement immediate (subject to RESET_STREAM ACK
    // for bidi). Before then the next scan repeats the idempotent drain so late
    // bytes cannot retain connection credit.
    if (single_attempt and discarded != 0) return true;
    _ = try connection.requestCompletedPeerStreamRelease(stream_id);
    return !already_started or discarded != 0 or
        connection.peerStreamClosed(stream_id);
}

fn identifyInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
    single_attempt: bool,
) Error!Identification {
    std.debug.assert(receive_mode != .unset);
    const direction: webtransport.StreamDirection =
        if (quic.StreamId.init(stream_id).direction() == .bidirectional)
            .bidirectional
        else
            .unidirectional;
    var stream = registry.get(stream_id);
    if (stream == null) {
        // Locally initiated bidi reverse directions are recognizable only from
        // their existing registry entry. An unregistered one belongs to a
        // different HTTP/3 consumer and must not be rejected as peer input.
        if (!isPeerInitiated(registry, stream_id)) return .unclaimed;
        if (rejectionAlreadyStarted(connection, stream_id, direction)) {
            const progressed = try rejectWrongSession(
                connection,
                stream_id,
                direction,
                single_attempt,
            );
            return .{ .rejected = progressed };
        }
        const available = connection.retainedReceivedStream(stream_id) orelse
            return .unclaimed;
        const prefix_len = switch (direction) {
            .bidirectional => blk: {
                const parsed =
                    webtransport.BidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return .unclaimed,
                            // Another HTTP/3 adapter owns ordinary request or
                            // extension streams on the same QUIC connection.
                            error.InvalidStreamType => return .unclaimed,
                            else => return err,
                        };
                if (parsed.session_id.value != session_id.value) {
                    const progressed = try rejectWrongSession(
                        connection,
                        stream_id,
                        direction,
                        single_attempt,
                    );
                    return .{ .rejected = progressed };
                }
                break :blk parsed.consumed;
            },
            .unidirectional => blk: {
                const parsed =
                    webtransport.UnidirectionalStreamHeader.parse(available) catch |err|
                        switch (err) {
                            error.BufferTooShort => return .unclaimed,
                            else => return err,
                        };
                if (parsed.stream_type !=
                    http3.StreamType.webtransport_unidirectional)
                {
                    return .unclaimed;
                }
                if (parsed.session_id == null or
                    parsed.session_id.?.value != session_id.value)
                {
                    const progressed = try rejectWrongSession(
                        connection,
                        stream_id,
                        direction,
                        single_attempt,
                    );
                    return .{ .rejected = progressed };
                }
                break :blk parsed.consumed;
            },
        };
        stream = try registry.registerPeer(stream_id, direction);
        stream.?.receive_mode = receive_mode;
        if (receive_mode == .incremental) {
            // Association bytes count toward QUIC credit but are never exposed
            // as WebTransport application bytes.
            var reset_consumed_prefix = false;
            if (connection.recvStreamStats(stream_id).?.reset) |reset| {
                if (reset.reliable_size <= prefix_len) {
                    stream.?.receive_reset = .fromHttp3(
                        reset.application_error_code,
                    );
                    stream.?.receive_reset_final_size = reset.final_size;
                    _ = try connection.discardResetReceived(stream_id);
                    reset_consumed_prefix = true;
                }
            }
            if (!reset_consumed_prefix) {
                const release_result = if (single_attempt)
                    connection.tryReleaseReceivedCapacity(
                        stream_id,
                        prefix_len,
                    )
                else
                    connection.releaseReceivedCapacity(
                        stream_id,
                        prefix_len,
                    );
                release_result catch |err| {
                    // Registry insertion must be transactional with prefix-
                    // credit consumption. Otherwise a failed MAX_* send leaves
                    // a peer stream registered while its prefix remains at the
                    // front of transport storage.
                    registry.removeLastPeer(stream_id);
                    return err;
                };
            }
        } else {
            // The compatibility whole-stream API consumes prefix + payload in
            // one transaction after FIN.
            stream.?.receive_prefix_len = prefix_len;
        }
        stream.?.prefix_received = true;
    } else if (stream.?.locally_initiated and
        stream.?.direction == .bidirectional and
        !stream.?.prefix_received)
    {
        // The peer's reverse direction begins directly with application data.
        stream.?.prefix_received = true;
    }
    if (stream.?.receive_mode == .unset) {
        // A whole-stream poll may have parsed this peer association before FIN
        // and later released its claim after discovering that the final body
        // exceeds the aggregate limit. Incremental takeover must consume that
        // already-identified prefix exactly once before exposing payload.
        if (receive_mode == .incremental and
            stream.?.receive_prefix_len != 0)
        {
            const prefix_len = stream.?.receive_prefix_len;
            const release_result = if (single_attempt)
                connection.tryReleaseReceivedCapacity(stream_id, prefix_len)
            else
                connection.releaseReceivedCapacity(stream_id, prefix_len);
            try release_result;
            stream.?.receive_prefix_len = 0;
        }
        stream.?.receive_mode = receive_mode;
    } else if (stream.?.receive_mode != receive_mode) {
        return error.InvalidStreamState;
    }
    return .{ .associated = stream.? };
}
