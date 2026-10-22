//! WT_SESSION_GONE cleanup for registered and still-buffered streams.
//! Each terminal direction retains socket-visible progress across retries.

const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const association = @import("../stream_association.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");
const stream_reset = @import("../stream/reset.zig");

pub const Error = webtransport.Error || http3.runtime.Error;

pub fn terminateStreams(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!void {
    if (connection_lifecycle.terminating(connection)) return;
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try stream_reset.resetWithCode(
                connection,
                registry,
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
            );
            stream.send_reset = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
        }
        const has_receive_side = stream.direction == .bidirectional or
            !stream.locally_initiated;
        if (has_receive_side and
            !stream.peer_fin and
            stream.receive_reset == null and
            stream.stop_sent == null)
        {
            try connection.sendStopSending(
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
            );
            stream.stop_sent = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
        }
        try requestAfterSessionTerminal(connection, stream);
    }
    try terminateBufferedStreams(connection, registry);
}

/// Terminate every associated stream under one caller-owned absolute
/// awake-clock deadline. Per-stream terminal state is committed only after
/// the corresponding transport frame reaches the socket, so a timeout can be
/// resumed without submitting an already completed RESET_STREAM or
/// STOP_SENDING again.
pub fn terminateStreamsWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    if (connection_lifecycle.terminating(connection)) return;
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try stream_reset.resetWithCodeAndDeadline(
                connection,
                registry,
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
                deadline,
            );
            stream.send_reset = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
        }
        const has_receive_side = stream.direction == .bidirectional or
            !stream.locally_initiated;
        if (has_receive_side and
            !stream.peer_fin and
            stream.receive_reset == null and
            stream.stop_sent == null)
        {
            try connection.sendStopSendingWithDeadline(
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
                deadline,
            );
            stream.stop_sent = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
        }
        try requestAfterSessionTerminal(connection, stream);
    }
    try terminateBufferedStreamsWithDeadline(
        connection,
        registry,
        deadline,
    );
}

pub const TerminateProgress = enum { complete, submitted };

/// Submit at most one RESET_STREAM or STOP_SENDING needed to terminate this
/// session's associated streams. Successful per-stream state is retained, so
/// an endpoint loop can call this repeatedly after pacing or ACK progress.
pub fn terminateStreamsOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!TerminateProgress {
    if (connection_lifecycle.terminating(connection)) return .complete;
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try stream_reset.resetOnceWithCode(
                connection,
                registry,
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
            );
            stream.send_reset = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
            return .submitted;
        }
        const has_receive_side = stream.direction == .bidirectional or
            !stream.locally_initiated;
        if (has_receive_side and
            !stream.peer_fin and
            stream.receive_reset == null and
            stream.stop_sent == null)
        {
            try connection.trySendStopSending(
                stream.stream_id,
                webtransport.ApplicationErrorCode.session_gone,
            );
            stream.stop_sent = .fromHttp3(
                webtransport.ApplicationErrorCode.session_gone,
            );
            try requestAfterSessionTerminal(connection, stream);
            return .submitted;
        }
        try requestAfterSessionTerminal(connection, stream);
    }
    return terminateBufferedStreamsOnce(connection, registry);
}

fn requestAfterSessionTerminal(
    connection: *quic.one_rtt.Connection,
    stream: *const webtransport.StreamState,
) Error!void {
    const send_terminal = stream.direction == .unidirectional and
        !stream.locally_initiated or
        stream.local_fin or stream.send_reset != null or
        stream.stopped != null;
    const receive_terminal = stream.direction == .unidirectional and
        stream.locally_initiated or
        stream.peer_fin or stream.receive_reset != null or
        stream.stop_sent != null;
    if (send_terminal and receive_terminal) {
        _ = try association.requestTransportRetirement(connection, stream);
    }
}

/// Terminate peer streams whose complete association prefix reached QUIC before
/// the session became terminal but which no WebTransport read had observed.
/// Prefix and payload bytes remain unconsumed, and registry capacity is not
/// required merely to apply terminal transport state.
fn terminateBufferedStreams(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!void {
    while ((terminateBufferedStreamsInternal(
        connection,
        registry,
        false,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    }) == .submitted) {}
}

fn terminateBufferedStreamsWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    deadline: std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!void {
    while (try terminateBufferedStreamsInternal(
        connection,
        registry,
        false,
        deadline,
    ) == .submitted) {}
}

fn terminateBufferedStreamsOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!TerminateProgress {
    return terminateBufferedStreamsInternal(
        connection,
        registry,
        true,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn terminateBufferedStreamsInternal(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    single_attempt: bool,
    deadline: ?std.Io.Clock.Timestamp,
) (Error || quic.runtime.ReceiveTimeoutError)!TerminateProgress {
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(
            connection.endpoint.io,
            absolute,
        );
    }
    var stream_ids: [256]u62 = undefined;
    var after: ?u62 = null;
    while (true) {
        const ids = connection.receivedStreamIdsAfterInto(
            after,
            &stream_ids,
        );
        for (ids) |stream_id| {
            if (stream_id == registry.session_id.value or
                registry.get(stream_id) != null)
            {
                continue;
            }
            const direction = bufferedPeerWebTransportDirection(
                connection,
                registry,
                stream_id,
            ) orelse continue;
            if (direction == .bidirectional and
                bufferedSendNeedsReset(connection, stream_id))
            {
                if (connection.config.reliable_reset.peer) try connection.setStreamResetPrefix(stream_id, &.{});
                if (deadline) |absolute| {
                    try connection.resetStreamWithDeadline(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                        absolute,
                    );
                } else if (single_attempt) {
                    try connection.tryResetStream(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                } else {
                    try connection.resetStream(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return .submitted;
            }
            if (bufferedReceiveNeedsStop(connection, stream_id)) {
                if (deadline) |absolute| {
                    try connection.sendStopSendingWithDeadline(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                        absolute,
                    );
                } else if (single_attempt) {
                    try connection.trySendStopSending(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                } else {
                    try connection.sendStopSending(
                        stream_id,
                        webtransport.ApplicationErrorCode.session_gone,
                    );
                }
                return .submitted;
            }
        }
        if (ids.len != 0) after = ids[ids.len - 1];
        if (ids.len < stream_ids.len) return .complete;
    }
}

fn bufferedPeerWebTransportDirection(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
) ?webtransport.StreamDirection {
    const id = quic.StreamId.init(stream_id);
    const peer_initiated = switch (registry.role) {
        .client => id.initiator() == .server,
        .server => id.initiator() == .client,
    };
    if (!peer_initiated) return null;
    const available = connection.availableReceivedStream(stream_id) orelse
        return null;
    return switch (id.direction()) {
        .bidirectional => blk: {
            const header = webtransport.BidirectionalStreamHeader.parse(
                available,
            ) catch return null;
            if (header.session_id.value != registry.session_id.value) {
                return null;
            }
            break :blk .bidirectional;
        },
        .unidirectional => blk: {
            const header = webtransport.UnidirectionalStreamHeader.parse(
                available,
            ) catch return null;
            if (header.stream_type !=
                http3.StreamType.webtransport_unidirectional or
                header.session_id == null or
                header.session_id.?.value != registry.session_id.value)
            {
                return null;
            }
            break :blk .unidirectional;
        },
    };
}

fn bufferedSendNeedsReset(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
) bool {
    const stats = connection.sendStreamStats(stream_id) orelse return true;
    return stats.final_size == null and
        stats.reset == null and
        stats.stopped == null;
}

fn bufferedReceiveNeedsStop(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
) bool {
    const stats = connection.recvStreamStats(stream_id) orelse return false;
    return stats.final_size == null and
        stats.reset == null and
        stats.stop_sending_sent == null;
}
