//! Stateful streaming HEADERS submission and outbound-body publication.
//! Callers with explicit request ownership may retain an exact partial prefix.

const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const field_section = @import("field_section.zig");
const runtime_error = @import("../error.zig");
const control_sender = @import("../control/send.zig");
const body_sender = @import("body.zig");
const send_scratch = @import("scratch.zig");
const qpack_state = @import("../qpack/state.zig");
const outbound_body = @import("../stream/outbound_body.zig");
const Error = runtime_error.Error;
const StreamMessageSendScratch = send_scratch.Message;
const CriticalStreamSendScratch = send_scratch.Critical;
const QpackEncodeState = qpack_state.QpackEncodeState;
const OutboundBodySet = outbound_body.Set;
const sendConnectionFrames = body_sender.sendConnectionFrames;
const sendConnectionFramesWithDeadline = body_sender.sendConnectionFramesWithDeadline;
const sendConnectionQpackEncoderInstructions = control_sender.sendConnectionQpackEncoderInstructions;
const sendConnectionQpackEncoderInstructionsWithDeadline = control_sender.sendConnectionQpackEncoderInstructionsWithDeadline;

pub fn sendConnectionStreamingHead(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    trailers_pending: bool,
    options: anytype,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    bodies: *OutboundBodySet,
) Error!void {
    return sendConnectionStreamingHeadUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        expected_length,
        body_allowed,
        trailers_pending,
        options,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        bodies,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionStreamingHeadWithDeadline(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    trailers_pending: bool,
    options: anytype,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    bodies: *OutboundBodySet,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionStreamingHeadUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        expected_length,
        body_allowed,
        trailers_pending,
        options,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        bodies,
        deadline,
        null,
    );
}

fn sendConnectionStreamingHeadUntil(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    trailers_pending: bool,
    options: anytype,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    bodies: *OutboundBodySet,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?*usize,
) runtime_error.ReceiveTimeoutError!void {
    if (progress) |committed| if (committed.* > scratch.encoded.items.len) return error.InvalidStreamRange;
    const retain_body_state = body_allowed and
        (trailers_pending or expected_length == null or
            expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    if (deadline) |absolute| {
        try sendConnectionQpackEncoderInstructionsWithDeadline(
            connection,
            critical_scratch,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            options,
            absolute,
        );
    } else {
        try sendConnectionQpackEncoderInstructions(
            connection,
            critical_scratch,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            options,
        );
    }
    var send = quic.stream_state.SendState.init(stream_id);
    const fin = !body_allowed or (!trailers_pending and expected_length != null and expected_length.? == 0);
    if (progress) |committed| {
        try field_section.sendProgress(connection, stream_id, scratch.encoded.items, 0, fin, committed, options.max_stream_frame_data, options.max_frames_per_packet, deadline);
        send.next_offset = committed.*;
    } else {
        try send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.encoded.items,
            options.max_stream_frame_data,
            !body_allowed or
                (!trailers_pending and
                    expected_length != null and expected_length.? == 0),
        );
        if (deadline) |absolute| {
            try sendConnectionFramesWithDeadline(
                connection,
                scratch.frames.items,
                options.max_frames_per_packet,
                absolute,
            );
        } else {
            try sendConnectionFrames(
                connection,
                scratch.frames.items,
                options.max_frames_per_packet,
            );
        }
    }
    if (retain_body_state) {
        var body_send = quic.stream_state.SendState.init(stream_id);
        body_send.next_offset = send.next_offset;
        bodies.appendOpenAssumeCapacity(
            stream_id,
            body_send,
            expected_length,
        );
    }
}

/// Preserve the socket-visible HEADERS prefix across transport backpressure.
/// The request owner must cancel the stream if this operation is abandoned.
pub fn sendProgress(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    trailers_pending: bool,
    options: anytype,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    bodies: *OutboundBodySet,
    committed: *usize,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionStreamingHeadUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        expected_length,
        body_allowed,
        trailers_pending,
        options,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        bodies,
        deadline,
        committed,
    );
}
