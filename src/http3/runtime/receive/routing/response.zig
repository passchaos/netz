const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const runtime_error = @import("../../error.zig");
const connect_datagram = @import("../../datagram.zig");
const control_receive = @import("../../control/receive.zig");
const qpack_state = @import("../../qpack/state.zig");
const buffered_response = @import("../../stream/buffered/response.zig");
const stream_lifecycle = @import("../../stream/lifecycle.zig");
const streaming_set = @import("../../stream/set.zig");
const push_state = @import("../../stream/push/state.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const ResponseStreamSet = buffered_response.Set;
const ClientRequestLifecycle = stream_lifecycle.Client;
const StreamingResponseSet = streaming_set.Set;
const PushStreamSet = push_state.Set;

const rejectCriticalStreamClosureFrame =
    control_receive.rejectCriticalStreamClosureFrame;
const messageStreamDisposition = control_receive.messageStreamDisposition;
const applyControlStreamFrameForRole =
    control_receive.applyControlStreamFrameForRole;
const configureQpackEncoderFromPeerSettings =
    control_receive.configureQpackEncoderFromPeerSettings;

/// Mutable response-side state shared by handshake-backed and
/// preconfigured-key clients. `connection` is needed only when preserving a
/// detached extension stream whose type prefix was reassembled by QUIC.
pub const State = struct {
    allocator: std.mem.Allocator,
    connection: ?*quic.one_rtt.Connection = null,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
    detached_stream_id: ?u62 = null,
    detached_streams: ?*connect_datagram.Registry = null,
};

pub fn validateBlockedStreamBudget(
    state: *State,
) Error!void {
    const limit = state.max_blocked_streams;
    var count = try state.response_streams.blockedStreamCount(
        state.qpack_decode.table,
    );
    if (state.streaming_responses) |streaming| {
        count = std.math.add(
            u64,
            count,
            try streaming.blockedStreamCount(state.qpack_decode.table),
        ) catch return error.QpackDecompressionFailed;
    }
    if (state.push_streams) |pushes| {
        count = std.math.add(
            u64,
            count,
            try pushes.blockedStreamCount(state.qpack_decode.table),
        ) catch return error.QpackDecompressionFailed;
    }
    if (count > limit) return error.QpackDecompressionFailed;
}

/// Route authenticated frames into response, push, control, and QPACK state.
/// The return value tells the caller whether reset processing queued decoder
/// feedback that should be flushed after the complete packet is accepted.
pub fn routePacket(
    state: *State,
    from: net.IpAddress,
    frames: []const quic.Frame,
) Error!bool {
    var flush_qpack_feedback = false;
    for (frames) |frame| {
        try rejectCriticalStreamClosureFrame(
            state.control.*,
            frame,
            .client,
        );
        if (state.connection) |connection| {
            const maybe_stream_id: ?u62 = switch (frame) {
                .stream => |stream| @intCast(stream.stream_id),
                .reset_stream => |reset| @intCast(reset.stream_id),
                else => null,
            };
            if (maybe_stream_id) |stream_id| {
                if (connection.peerStreamClosed(stream_id)) continue;
            }
        }
        if (frame == .reset_stream and
            (frame.reset_stream.stream_id & 0x02) != 0)
        {
            const preserve_for_detached = hasDetachedAssociation(state.*) and
                shouldPreserveDetachedUniReset(
                    state.connection,
                    state.qpack_decode,
                    frame.reset_stream.stream_id,
                );
            state.qpack_decode.discardPeerUniStream(
                frame.reset_stream.stream_id,
            );
            var tracked_push = false;
            if ((frame.reset_stream.stream_id & 0x03) == 0x03) {
                if (state.push_streams) |pushes| {
                    const stream_id: u62 = @intCast(
                        frame.reset_stream.stream_id,
                    );
                    tracked_push = pushes.containsStream(stream_id);
                    if (try pushes.hasUnacknowledgedDynamicSection(
                        stream_id,
                        state.qpack_decode.table,
                    )) {
                        try state.qpack_decode.recordStreamCancellation(stream_id);
                        flush_qpack_feedback = true;
                    }
                    if (tracked_push) {
                        if (state.connection) |connection| {
                            _ = try connection
                                .requestCompletedPeerStreamRelease(stream_id);
                        }
                    }
                    pushes.removeByStreamId(stream_id);
                }
            }
            if (!tracked_push and !preserve_for_detached) {
                if (state.connection) |connection| {
                    _ = try connection.requestCompletedPeerStreamRelease(
                        frame.reset_stream.stream_id,
                    );
                }
            }
            continue;
        }
        if (frame == .reset_stream and
            (try messageStreamDisposition(
                frame.reset_stream.stream_id,
            )) == .request_response)
        {
            const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
            if (state.detached_streams) |detached| {
                if (detached.contains(stream_id)) {
                    // Detached associations report their own terminal state.
                    // Their caller routes DATAGRAMs before exposing the reset.
                    continue;
                }
            }
            if (state.request_lifecycle) |lifecycle| {
                if (lifecycle.isFinished(stream_id)) continue;
                if (!lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
            }
            flush_qpack_feedback =
                try recordClientResponseReset(
                    state.response_streams,
                    state.streaming_responses,
                    state.qpack_decode,
                    stream_id,
                    frame.reset_stream.application_error_code,
                ) or flush_qpack_feedback;
            continue;
        }
        if (frame != .stream) continue;
        if (state.detached_stream_id != null and
            frame.stream.stream_id == state.detached_stream_id.?)
        {
            state.qpack_decode.discardPeerUniStream(
                frame.stream.stream_id,
            );
            continue;
        }
        if (state.detached_streams) |detached| {
            if (detached.contains(
                std.math.cast(u62, frame.stream.stream_id) orelse
                    return error.UnexpectedStream,
            )) {
                state.qpack_decode.discardPeerUniStream(
                    frame.stream.stream_id,
                );
                continue;
            }
        }
        if (hasDetachedAssociation(state.*) and state.connection != null and
            shouldPreserveDetachedStream(
                state.connection.?,
                frame.stream,
                state.request_lifecycle,
            ))
        {
            // QUIC has already retained these bytes. Classify WebTransport
            // before HTTP/3 stream-type routing so extension streams may use
            // any legal peer-initiated unidirectional stream number.
            state.qpack_decode.discardPeerUniStream(
                frame.stream.stream_id,
            );
            continue;
        }
        if ((frame.stream.stream_id & 0x02) != 0) {
            if (state.push_streams) |pushes| {
                if (pushes.isCancelledStream(frame.stream.stream_id)) {
                    state.qpack_decode.discardPeerUniStream(
                        frame.stream.stream_id,
                    );
                    if (state.connection) |connection| {
                        const available = connection.retainedReceivedStream(
                            frame.stream.stream_id,
                        ) orelse return error.UnexpectedStream;
                        const stats = connection.recvStreamStats(
                            frame.stream.stream_id,
                        ) orelse return error.UnexpectedStream;
                        const consumed_end = std.math.add(
                            u64,
                            stats.bytes_read,
                            std.math.cast(u64, available.len) orelse
                                return error.InvalidStreamRange,
                        ) catch return error.InvalidStreamRange;
                        try connection.commitReceivedThrough(
                            frame.stream.stream_id,
                            consumed_end,
                        );
                        if (stats.final_size != null and
                            stats.final_size.? == consumed_end)
                        {
                            _ = try connection.requestCompletedPeerStreamRelease(
                                frame.stream.stream_id,
                            );
                        }
                    }
                    continue;
                }
            }
            const classified = try state.qpack_decode.classifyPeerUniFrame(
                frame.stream,
            ) orelse continue;
            var transport_consumed_end: ?u64 = null;
            var mark_push_prefix_credited = false;
            var discard_classified_stream = false;
            switch (classified.stream_type) {
                .control => {
                    if (!try applyControlStreamFrameForRole(
                        state.control,
                        state.allocator,
                        classified.frame,
                        .client,
                    )) return error.UnexpectedStream;
                    if (state.push_streams) |pushes| {
                        pushes.removeByStreamId(
                            @intCast(classified.frame.stream_id),
                        );
                    }
                    try configureQpackEncoderFromPeerSettings(
                        state.control.*,
                        state.qpack_encode,
                    );
                },
                .qpack_decoder => {
                    if (state.push_streams) |pushes| {
                        pushes.removeByStreamId(
                            @intCast(classified.frame.stream_id),
                        );
                    }
                    try state.qpack_encode.applyDecoderStreamFrame(
                        state.control,
                        classified.frame,
                    );
                },
                .qpack_encoder => {
                    if (state.push_streams) |pushes| {
                        pushes.removeByStreamId(
                            @intCast(classified.frame.stream_id),
                        );
                    }
                    try state.qpack_decode.applyEncoderStreamFrame(
                        state.control,
                        classified.frame,
                    );
                },
                .push => {
                    if (state.push_streams) |pushes| {
                        const had_reader = pushes.readerForStream(
                            @intCast(classified.frame.stream_id),
                        ) != null;
                        if (!try pushes.insert(
                            from,
                            classified.frame,
                            state.control.*,
                        )) return error.UnexpectedStream;
                        if (pushes.isCancelledStream(
                            classified.frame.stream_id,
                        )) {
                            transport_consumed_end = if (state.connection) |connection| blk: {
                                const available = connection.retainedReceivedStream(
                                    classified.frame.stream_id,
                                ) orelse return error.UnexpectedStream;
                                const stats = connection.recvStreamStats(
                                    classified.frame.stream_id,
                                ) orelse return error.UnexpectedStream;
                                break :blk std.math.add(
                                    u64,
                                    stats.bytes_read,
                                    std.math.cast(u64, available.len) orelse
                                        return error.InvalidStreamRange,
                                ) catch return error.InvalidStreamRange;
                            } else std.math.add(
                                u64,
                                classified.frame.offset,
                                std.math.cast(
                                    u64,
                                    classified.frame.data.len,
                                ) orelse return error.InvalidStreamRange,
                            ) catch return error.InvalidStreamRange;
                            discard_classified_stream = true;
                            break;
                        }
                        if (!had_reader) {
                            if (pushes.readerForStream(
                                @intCast(classified.frame.stream_id),
                            )) |reader| {
                                transport_consumed_end = reader.readOffset();
                                mark_push_prefix_credited = true;
                            }
                        }
                    }
                },
                .unknown => {},
            }
            if (classified.stream_type != .push or
                state.push_streams == null)
            {
                transport_consumed_end = std.math.add(
                    u64,
                    classified.frame.offset,
                    std.math.cast(
                        u64,
                        classified.frame.data.len,
                    ) orelse return error.InvalidStreamRange,
                ) catch return error.InvalidStreamRange;
            }
            if (transport_consumed_end) |consumed_end| {
                if (state.connection) |connection| {
                    try connection.commitReceivedThrough(
                        classified.frame.stream_id,
                        consumed_end,
                    );
                    if (mark_push_prefix_credited) {
                        const pushes = state.push_streams orelse unreachable;
                        const reader = pushes.readerForStream(
                            @intCast(classified.frame.stream_id),
                        ) orelse unreachable;
                        reader.markCredited(reader.uncreditedConsumed());
                    }
                    if (classified.stream_type == .unknown and
                        classified.frame.fin)
                    {
                        _ = try connection.requestCompletedPeerStreamRelease(
                            classified.frame.stream_id,
                        );
                    }
                }
            }
            if (discard_classified_stream) {
                state.qpack_decode.discardPeerUniStream(
                    classified.frame.stream_id,
                );
            } else {
                state.qpack_decode.commitPeerUniFrame(classified.frame);
            }
            continue;
        }
        if ((try messageStreamDisposition(
            frame.stream.stream_id,
        )) == .ignore) continue;
        const stream_id: u62 = @intCast(frame.stream.stream_id);
        if (state.request_lifecycle) |lifecycle| {
            if (lifecycle.isFinished(stream_id)) continue;
            if (!lifecycle.contains(stream_id)) return error.UnexpectedStream;
        }
        if (state.streaming_responses) |streaming| {
            if (try streaming.insert(from, frame.stream)) continue;
        }
        try state.response_streams.insert(from, frame.stream);
    }
    try validateBlockedStreamBudget(state);
    return flush_qpack_feedback or
        state.qpack_decode.pendingDecoderInstructions().len != 0;
}

/// Retire all receive-side state for a reset response stream atomically.
pub fn recordClientResponseReset(
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    qpack_decode: *QpackDecodeState,
    stream_id: u62,
    application_error_code: u64,
) Error!bool {
    if (!try response_streams.prepareReset(
        stream_id,
        application_error_code,
    )) return false;

    var cancel_qpack = try response_streams.requiresQpackCancellation(
        stream_id,
        qpack_decode.table,
    );
    if (streaming_responses) |streaming| {
        cancel_qpack = cancel_qpack or
            try streaming.hasUnacknowledgedDynamicSection(
                stream_id,
                qpack_decode.table,
            );
    }
    if (cancel_qpack) {
        try qpack_decode.recordStreamCancellation(stream_id);
    }

    response_streams.remove(stream_id);
    if (streaming_responses) |streaming| streaming.removeEntry(stream_id);
    response_streams.commitPreparedResetAssumeCapacity(
        stream_id,
        application_error_code,
    );
    return cancel_qpack;
}

fn hasDetachedAssociation(state: State) bool {
    return state.detached_stream_id != null or
        if (state.detached_streams) |detached|
            detached.associationCount() != 0
        else
            false;
}

fn shouldPreserveDetachedUniReset(
    maybe_connection: ?*quic.one_rtt.Connection,
    qpack_decode: *QpackDecodeState,
    stream_id: u64,
) bool {
    if (qpack_decode.classifiedPeerUniStreamType(stream_id) != null)
        return false;
    const connection = maybe_connection orelse return true;
    const stats = connection.recvStreamStats(stream_id) orelse return false;
    if (stats.bytes_read != 0) return true;
    const available = connection.retainedReceivedStream(stream_id) orelse
        return false;
    const prefix = quic.varint.decodeSlice(available) catch return false;
    return @as(http3.StreamType, @enumFromInt(prefix.value)) ==
        .webtransport_unidirectional;
}

fn shouldPreserveDetachedStream(
    connection: *quic.one_rtt.Connection,
    stream: quic.StreamFrame,
    request_lifecycle: ?*const ClientRequestLifecycle,
) bool {
    if ((stream.stream_id & 0x02) == 0) {
        const stream_id: u62 = @intCast(stream.stream_id);
        const lifecycle = request_lifecycle orelse return false;
        return !lifecycle.contains(stream_id) and
            !lifecycle.isFinished(stream_id);
    }
    const available = connection.availableReceivedStream(
        stream.stream_id,
    ) orelse return false;
    const prefix = quic.varint.decodeSlice(available) catch return false;
    return @as(http3.StreamType, @enumFromInt(prefix.value)) ==
        .webtransport_unidirectional;
}
