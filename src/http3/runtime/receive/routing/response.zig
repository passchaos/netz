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
            state.qpack_decode.discardPeerUniStream(
                frame.reset_stream.stream_id,
            );
        }
        if (frame == .reset_stream and
            (frame.reset_stream.stream_id & 0x03) == 0x03)
        {
            if (state.push_streams) |pushes| {
                const stream_id: u62 = @intCast(
                    frame.reset_stream.stream_id,
                );
                const tracked_push = pushes.containsStream(stream_id);
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
        if (state.detached_stream_id != null and
            state.connection != null and
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
            const classified = try state.qpack_decode.classifyPeerUniFrame(
                frame.stream,
            ) orelse continue;
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
                        if (state.control.peer_cancelled_push_id) |push_id| {
                            try pushes.observePeerCancellation(push_id);
                        }
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
                        if (!try pushes.insert(
                            from,
                            classified.frame,
                            state.control.*,
                        )) return error.UnexpectedStream;
                    }
                },
                .unknown => {},
            }
            state.qpack_decode.commitPeerUniFrame(classified.frame);
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
    if (stream.offset == 0) {
        return control_receive.peekUniStreamType(stream) ==
            .webtransport_unidirectional;
    }
    const available = connection.availableReceivedStream(
        stream.stream_id,
    ) orelse return false;
    const prefix = quic.varint.decodeSlice(available) catch return false;
    return @as(http3.StreamType, @enumFromInt(prefix.value)) ==
        .webtransport_unidirectional;
}
