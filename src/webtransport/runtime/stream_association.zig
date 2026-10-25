//! WebTransport stream association over QUIC stream prefixes.

const std = @import("std");
const receive_credit = @import("stream/receive_credit.zig");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const flow_receive = @import("flow/receive.zig");
const association_prefix = @import("stream/prefix.zig");
const buffered_rejection = @import("association/rejection.zig");
const abandoned_receive = @import("association/abandoned.zig");
const association_header = @import("association/header.zig");

pub const Error = webtransport.Error || quic.one_rtt.Error;

pub const Identification = union(enum) {
    associated: *webtransport.StreamState,
    rejected: bool,
    unclaimed,
};

/// Type-erased lookup used by a shared HTTP/3 endpoint to distinguish a
/// stream for another accepted or pending WebTransport Session from an unknown Session.
/// The former must remain untouched for its owner; the latter is rejected with
/// WT_BUFFERED_STREAM_REJECTED as before.
pub const SessionLookup = struct {
    context: *const anyopaque,
    scope: u64,
    containsFn: *const fn (*const anyopaque, u64, u62) bool,

    pub fn contains(self: SessionLookup, session_id: u62) bool {
        return self.containsFn(self.context, self.scope, session_id);
    }
};

/// Draft-16 section 4 makes a malformed peer Session ID a connection
/// error, even when no accepted Session owns the stream yet. Keep the wire
/// close code shared by ordinary association and early-stream discovery.
pub fn rejectInvalidSessionId(connection: *quic.one_rtt.Connection) error{InvalidSessionId} {
    // The canonical close installs local termination before its best-effort
    // socket write, preserving the peer error if that write fails.
    http3.runtime.closeConnectionForProtocolError(connection, error.IdError) catch {};
    return error.InvalidSessionId;
}

/// Associate complete prefixes without claiming either application reader or
/// consuming data. Flow maintenance can then enforce session limits before a
/// DATAGRAM-only application ever polls a stream.
pub fn discoverBuffered(connection: *quic.one_rtt.Connection, registry: *webtransport.StreamRegistry) Error!void {
    var stream_ids: [256]u62 = undefined;
    var after: ?u62 = null;
    const other_sessions = SessionLookup{ .context = registry, .scope = 0, .containsFn = leaveOtherSessions };
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(after, &stream_ids);
        for (ids) |id| {
            if (id == registry.session_id.value or registry.get(id) != null) continue;
            _ = try identifyInternal(connection, registry, registry.session_id, id, .unset, true, other_sessions);
        }
        if (ids.len < stream_ids.len) return;
        after = ids[ids.len - 1];
    }
}

fn leaveOtherSessions(_: *const anyopaque, _: u64, _: u62) bool {
    return true;
}

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

pub const drainAbandonedReceives = abandoned_receive.drain;

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
        null,
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
        null,
    );
}

/// Shared-endpoint form that leaves streams for another accepted Session
/// unclaimed so its own registry can classify them later in the same poll
/// cycle.
pub fn identifyClassifiedOnceShared(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
    sessions: SessionLookup,
) Error!Identification {
    return identifyInternal(
        connection,
        registry,
        session_id,
        stream_id,
        receive_mode,
        true,
        sessions,
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

fn rejectWrongSession(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    direction: webtransport.StreamDirection,
    single_attempt: bool,
) Error!bool {
    return buffered_rejection.advance(connection, stream_id, direction, buffered_rejection.code(connection, stream_id, direction) orelse
        webtransport.ApplicationErrorCode.buffered_stream_rejected, single_attempt);
}

fn identifyInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    stream_id: u62,
    receive_mode: webtransport.ReceiveMode,
    single_attempt: bool,
    sessions: ?SessionLookup,
) Error!Identification {
    if (registry.get(stream_id) == null and connection.streamLifecycle(stream_id) == .closed) return .unclaimed;
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
        if (buffered_rejection.code(connection, stream_id, direction) != null) {
            const progressed = try rejectWrongSession(
                connection,
                stream_id,
                direction,
                single_attempt,
            );
            return .{ .rejected = progressed };
        }
        const header = (try association_header.peek(connection, stream_id)) orelse return .unclaimed;
        const associated_session = header.session_id orelse return .unclaimed;
        if (associated_session != session_id.value) {
            if (sessions) |known| {
                if (known.contains(associated_session)) return .unclaimed;
            }
            const progressed = try rejectWrongSession(connection, stream_id, direction, single_attempt);
            return .{ .rejected = progressed };
        }
        const prefix_len = header.consumed;
        stream = try registry.registerPeer(stream_id, direction);
        stream.?.receive_header_len = prefix_len;
        try flow_receive.observe(connection, registry, stream.?);
        if (direction == .bidirectional) {
            association_prefix.bind(connection, registry, stream.?) catch |err| {
                registry.removeLastPeer(stream_id);
                return err;
            };
        }
        stream.?.receive_mode = receive_mode;
        const receive_stats = connection.recvStreamStats(stream_id).?;
        if (receive_stats.stop_sending_sent) |stop| stream.?.stop_sent = .fromHttp3(stop.application_error_code);
        if (receive_mode == .incremental) {
            // Association bytes count toward QUIC credit but are never exposed
            // as WebTransport application bytes.
            var reset_consumed_prefix = receive_stats.bytes_read >= prefix_len;
            if (connection.recvStreamStats(stream_id).?.reset) |reset| {
                if (reset.reliable_size <= prefix_len) {
                    stream.?.receive_reset = .fromHttp3(
                        reset.application_error_code,
                    );
                    stream.?.receive_reset_final_size = reset.final_size;
                    _ = try connection.discardResetReceived(stream_id);
                    flow_receive.consumeAbandoned(registry, stream.?);
                    reset_consumed_prefix = true;
                }
            }
            if (!reset_consumed_prefix) {
                receive_credit.commit(connection, stream_id, prefix_len) catch |err| {
                    // Failed local consumption cannot leave a registry entry
                    // interpreting the association bytes as application data.
                    // QUIC retains outbound MAX_* failures independently.
                    registry.removeLastPeer(stream_id);
                    return err;
                };
            }
        } else {
            // Whole-stream readers consume prefix + payload after FIN. Idle
            // discovery leaves the same prefix pending for either reader.
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
        // Idle discovery and a released whole-stream claim both leave the
        // association prefix pending. Incremental takeover consumes it exactly
        // once, including after RESET/STOP has already abandoned receive data.
        if (receive_mode == .incremental and
            stream.?.receive_prefix_len != 0)
        {
            const prefix_len = stream.?.receive_prefix_len;
            const already_consumed = if (connection.recvStreamStats(stream_id)) |stats| stats.bytes_read >= prefix_len else true;
            if (!already_consumed) {
                try receive_credit.commit(connection, stream_id, prefix_len);
            }
            stream.?.receive_prefix_len = 0;
        }
        stream.?.receive_mode = receive_mode;
    } else if (stream.?.receive_mode != receive_mode) {
        return error.InvalidStreamState;
    }
    try flow_receive.observe(connection, registry, stream.?);
    return .{ .associated = stream.? };
}
