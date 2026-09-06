const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const control_sender = @import("../control/send.zig");
const body_sender = @import("body.zig");
const protected_send_module = @import("protected.zig");
const send_scratch = @import("scratch.zig");
const qpack_state = @import("../qpack/state.zig");
const outbound_body = @import("../stream/outbound_body.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const StreamMessageSendScratch = send_scratch.Message;
const PushSendScratch = send_scratch.Push;
const CriticalStreamSendScratch = send_scratch.Critical;
const ProtectedSendState = protected_send_module.State;
const QpackEncodeState = qpack_state.QpackEncodeState;
const OutboundBodySet = outbound_body.Set;
const sendConnectionFrames = body_sender.sendConnectionFrames;
const sendConnectionQpackEncoderInstructions =
    control_sender.sendConnectionQpackEncoderInstructions;
const sendProtectedQpackEncoderInstructions =
    control_sender.sendProtectedQpackEncoderInstructions;

pub const ServerPush = struct {
    push_id: u64,
    request: http3.Request,
    informational: []const http3.InformationalResponse = &.{},
    response: http3.Response,
};

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    protected_send: *ProtectedSendState,
) Error!void {
    try protected_send.sendFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames,
        config.max_frames_per_packet,
    );
}
pub fn sendConnectionMessage(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    request: http3.Request,
    options: anytype,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    message_sent = true;
}

/// Encode a complete request without dynamic QPACK references and submit it
/// as one QUIC packet. Failure leaves the transport stream namespace and the
/// caller's HTTP request bookkeeping retryable.
pub fn trySendConnectionRequestLiteral(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    request: http3.Request,
    options: anytype,
    peer_settings: http3.Settings,
) Error!void {
    scratch.reset();
    try request.writeWithSettings(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    if (scratch.frames.items.len == 0 or
        scratch.frames.items.len >
            @max(@as(usize, 1), options.max_frames_per_packet) or
        try connection.packetLenForFramesAtOffset(
            0,
            scratch.frames.items,
        ) > connection.currentSendDatagramSize())
    {
        return error.DatagramTooLarge;
    }
    try connection.trySend(scratch.frames.items);
}

pub fn sendConnectionResponseSequence(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    options: anytype,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try http3.writeResponseSequenceDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        informational,
        response,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    message_sent = true;
}

/// Encode a HEADERS-only response without dynamic-table references and submit
/// it as exactly one QUIC packet. Event-loop adapters can safely retry pacing,
/// congestion, flow-control, and size failures because neither QPACK nor
/// stream-send state is committed before `Connection.trySend` succeeds.
pub fn trySendConnectionResponseHeadLiteral(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    response: http3.Response,
    peer_settings: http3.Settings,
    fin: bool,
    release_received: usize,
) Error!u64 {
    if (response.body.len != 0 or response.trailers.len != 0) {
        return error.InvalidContentLength;
    }
    scratch.reset();
    try response.writeWithSettings(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        @max(@as(usize, 1), scratch.encoded.items.len),
        fin,
    );
    std.debug.assert(scratch.frames.items.len == 1);
    if (try connection.packetLenForFramesAtOffset(
        0,
        scratch.frames.items,
    ) > connection.currentSendDatagramSize()) {
        return error.DatagramTooLarge;
    }
    if (release_received == 0) {
        try connection.trySend(scratch.frames.items);
    } else {
        try connection.trySendAndReleaseReceivedCapacity(
            stream_id,
            release_received,
            scratch.frames.items[0],
        );
    }
    return send.next_offset;
}

pub fn sendProtectedMessage(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    request: http3.Request,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &scratch.encoded,
        endpoint.allocator,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        scratch.frames.items,
        protected_send,
    );
    message_sent = true;
}

pub fn sendProtectedResponseSequence(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    scratch.reset();
    // A field section can acquire dynamic-table references before any network
    // I/O. Release those references when encoder- or response-stream sending
    // fails; unreferenced speculative inserts remain useful for later sends.
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try http3.writeResponseSequenceDynamic(
        &scratch.encoded,
        endpoint.allocator,
        informational,
        response,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        scratch.frames.items,
        protected_send,
    );
    message_sent = true;
}

pub fn encodePushMessages(
    allocator: std.mem.Allocator,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    parent: *std.ArrayList(u8),
    pushed: *std.ArrayList(u8),
) Error!void {
    try http3.writePushPromiseDynamic(
        parent,
        allocator,
        push.push_id,
        push.request,
        peer_settings,
        request_stream_id,
        qpack,
    );
    try response.writeDynamic(
        parent,
        allocator,
        peer_settings,
        request_stream_id,
        qpack,
    );
    const push_stream_type = @intFromEnum(http3.StreamType.push);
    const push_stream_type_len = try quic.varint.length(push_stream_type);
    const push_id_len = try quic.varint.length(push.push_id);
    try pushed.ensureUnusedCapacity(
        allocator,
        @as(usize, push_stream_type_len) + push_id_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(
        pushed,
        push_stream_type,
        push_stream_type_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(
        pushed,
        push.push_id,
        push_id_len,
    );
    try http3.writeResponseSequenceDynamic(
        pushed,
        allocator,
        push.informational,
        push.response,
        peer_settings,
        push_stream_id,
        qpack,
    );
}

fn appendMessageFrames(
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        frames,
        allocator,
        bytes,
        max_stream_frame_data,
        true,
    );
}

pub fn sendConnectionPush(
    connection: *quic.one_rtt.Connection,
    scratch: *PushSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    options: anytype,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try encodePushMessages(
        connection.endpoint.allocator,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        &scratch.parent,
        &scratch.pushed,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    // Promise bytes precede the pushed response in this frame list. QUIC may
    // reorder the streams, and the receive lifecycle deliberately tolerates
    // that, but same-call ordering minimizes unnecessary buffering.
    try appendMessageFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        request_stream_id,
        scratch.parent.items,
        options.max_stream_frame_data,
    );
    try appendMessageFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        push_stream_id,
        scratch.pushed.items,
        options.max_stream_frame_data,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
}

pub fn sendProtectedPush(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    scratch: *PushSendScratch,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try encodePushMessages(
        endpoint.allocator,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        &scratch.parent,
        &scratch.pushed,
    );
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    try appendMessageFrames(
        &scratch.frames,
        endpoint.allocator,
        request_stream_id,
        scratch.parent.items,
        config.max_stream_frame_data,
    );
    try appendMessageFrames(
        &scratch.frames,
        endpoint.allocator,
        push_stream_id,
        scratch.pushed.items,
        config.max_stream_frame_data,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        scratch.frames.items,
        protected_send,
    );
}

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
    const retain_body_state = body_allowed and
        (trailers_pending or expected_length == null or
            expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        !body_allowed or
            (!trailers_pending and
                expected_length != null and expected_length.? == 0),
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
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

pub fn sendProtectedStreamingHead(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
) Error!void {
    const retain_body_state = body_allowed and
        (expected_length == null or expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        !body_allowed or
            (expected_length != null and expected_length.? == 0),
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        scratch.frames.items,
        protected_send,
    );
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

pub fn sendConnectionTrailers(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    trailers: []const http3.Qpack.HeaderField,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    options: anytype,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    const previous = entry.*;
    errdefer entry.* = previous;
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    try entry.send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    _ = bodies.finish(stream_id);
}

pub fn sendProtectedTrailers(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    trailers: []const http3.Qpack.HeaderField,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    scratch: *StreamMessageSendScratch,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    const previous = entry.*;
    errdefer entry.* = previous;
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &scratch.encoded,
        endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    if (entry.flow_limit) |limit| {
        const next_offset = std.math.add(
            u64,
            entry.send.next_offset,
            scratch.encoded.items.len,
        ) catch return error.InvalidFrameLength;
        if (next_offset > limit) return error.FlowControlBlocked;
    }
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    try entry.send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        scratch.frames.items,
        protected_send,
    );
    _ = bodies.finish(stream_id);
}
