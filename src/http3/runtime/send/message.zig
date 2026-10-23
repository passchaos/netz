const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const control_sender = @import("../control/send.zig");
const body_sender = @import("body.zig");
const streaming_head = @import("streaming_head.zig");
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
const sendConnectionFramesWithDeadline =
    body_sender.sendConnectionFramesWithDeadline;
const sendConnectionQpackEncoderInstructions =
    control_sender.sendConnectionQpackEncoderInstructions;
const sendConnectionQpackEncoderInstructionsWithDeadline =
    control_sender.sendConnectionQpackEncoderInstructionsWithDeadline;
const sendProtectedQpackEncoderInstructions =
    control_sender.sendProtectedQpackEncoderInstructions;
const sendProtectedQpackEncoderInstructionsWithDeadline =
    control_sender.sendProtectedQpackEncoderInstructionsWithDeadline;

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
    return sendConnectionMessageUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        request,
        options,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionMessageWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionMessageUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        request,
        options,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        deadline,
    );
}

fn sendConnectionMessageUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    try prepareConnectionMessage(
        connection.endpoint.allocator,
        scratch,
        stream_id,
        request,
        options,
        peer_settings,
        qpack,
    );
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try sendPreparedConnectionMessageUntil(
        connection,
        scratch,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
        deadline,
    );
    message_sent = true;
}

/// Encode and packetize one request before its QUIC stream ID is reserved.
/// This lets callers reject malformed requests without consuming stream
/// credit while retaining dynamic QPACK inserts for later field sections.
pub fn prepareConnectionMessage(
    allocator: std.mem.Allocator,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    request: http3.Request,
    options: anytype,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
) Error!void {
    scratch.reset();
    errdefer qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &scratch.encoded,
        allocator,
        peer_settings,
        stream_id,
        qpack,
    );
    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
}

/// Send a request prepared by `prepareConnectionMessage`. The caller retains
/// ownership of the corresponding QPACK section until this succeeds.
pub fn sendPreparedConnectionMessageUntil(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    options: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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

pub fn trySendConnectionStreamingRequestHeadLiteral(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    bodies: *OutboundBodySet,
    stream_id: u62,
    request: http3.Request,
    body_length: ?usize,
    options: anytype,
    peer_settings: http3.Settings,
) Error!void {
    scratch.reset();
    const streaming = try request.writeStreamingHead(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
        body_length,
    );
    const retain_body_state = streaming.body_allowed and
        (streaming.expected_length == null or
            streaming.expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        !retain_body_state,
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
    if (retain_body_state) {
        bodies.appendOpenAssumeCapacity(
            stream_id,
            send,
            streaming.expected_length,
        );
    }
}

pub fn trySendConnectionTrailersLiteral(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    trailers: []const http3.Qpack.HeaderField,
    peer_settings: http3.Settings,
    options: anytype,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    var staged = entry.*;
    scratch.reset();
    try http3.writeTrailers(
        &scratch.encoded,
        connection.endpoint.allocator,
        trailers,
        peer_settings,
    );
    try staged.send.appendFrames(
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
    _ = bodies.finish(stream_id);
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
    return sendConnectionResponseSequenceUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        informational,
        response,
        options,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionResponseSequenceWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionResponseSequenceUntil(
        connection,
        scratch,
        critical_scratch,
        stream_id,
        informational,
        response,
        options,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        deadline,
    );
}

fn sendConnectionResponseSequenceUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
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
    message_sent = true;
}

/// Encode a complete response without dynamic-table references and submit it
/// as exactly one QUIC packet. Event-loop adapters can safely retry pacing,
/// congestion, flow-control, and size failures because neither QPACK nor
/// stream-send state is committed before `Connection.trySend` succeeds.
pub fn trySendConnectionResponseLiteral(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    response: http3.Response,
    peer_settings: http3.Settings,
    fin: bool,
    release_received: usize,
) Error!u64 {
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

pub fn trySendConnectionStreamingResponseHeadLiteral(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    bodies: *OutboundBodySet,
    stream_id: u62,
    response: http3.Response,
    body_length: ?usize,
    trailers_pending: bool,
    options: anytype,
    peer_settings: http3.Settings,
) Error!bool {
    scratch.reset();
    const streaming = try response.writeStreamingHead(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
        body_length,
    );
    const retain_body_state = streaming.body_allowed and
        (trailers_pending or streaming.expected_length == null or
            streaming.expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        !retain_body_state,
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
    if (retain_body_state) {
        bodies.appendOpenAssumeCapacity(
            stream_id,
            send,
            streaming.expected_length,
        );
    }
    return retain_body_state;
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
    return sendProtectedMessageUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        request,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedMessageWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedMessageUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        request,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        deadline,
    );
}

fn sendProtectedMessageUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    try prepareConnectionMessage(
        endpoint.allocator,
        scratch,
        stream_id,
        request,
        config,
        peer_settings,
        qpack,
    );
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try sendPreparedProtectedMessageUntil(
        endpoint,
        to,
        config,
        scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        deadline,
    );
    message_sent = true;
}

pub fn sendPreparedProtectedMessageUntil(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    scratch: *StreamMessageSendScratch,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
    }
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
    return sendProtectedResponseSequenceUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        informational,
        response,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedResponseSequenceWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedResponseSequenceUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        informational,
        response,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        deadline,
    );
}

fn sendProtectedResponseSequenceUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
    }
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

const PushStreamingHeads = struct {
    parent_expected_length: ?usize,
    parent_body_allowed: bool,
    pushed_expected_length: ?usize,
    pushed_body_allowed: bool,
};

/// Encode only PUSH_PROMISE plus the parent and pushed response heads. DATA
/// and trailers deliberately remain outside this buffer so the caller can
/// advance them a packet at a time as QUIC flow-control credit is returned.
fn encodePushStreamingHeads(
    allocator: std.mem.Allocator,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    parent: *std.ArrayList(u8),
    pushed: *std.ArrayList(u8),
) Error!PushStreamingHeads {
    try response.validateBodySemantics();
    try push.response.validateBodySemantics();
    try http3.writePushPromiseDynamic(
        parent,
        allocator,
        push.push_id,
        push.request,
        peer_settings,
        request_stream_id,
        qpack,
    );
    var parent_head = response;
    parent_head.body = &.{};
    parent_head.trailers = &.{};
    const parent_streaming = try parent_head.writeStreamingHeadDynamic(
        parent,
        allocator,
        peer_settings,
        request_stream_id,
        response.body.len,
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
    for (push.informational) |informational| {
        try informational.writeDynamic(
            pushed,
            allocator,
            peer_settings,
            push_stream_id,
            qpack,
        );
    }
    var pushed_head = push.response;
    pushed_head.body = &.{};
    pushed_head.trailers = &.{};
    const pushed_streaming = try pushed_head.writeStreamingHeadDynamic(
        pushed,
        allocator,
        peer_settings,
        push_stream_id,
        push.response.body.len,
        qpack,
    );
    return .{
        .parent_expected_length = parent_streaming.expected_length,
        .parent_body_allowed = parent_streaming.body_allowed,
        .pushed_expected_length = pushed_streaming.expected_length,
        .pushed_body_allowed = pushed_streaming.body_allowed,
    };
}

fn retainStreamingBody(
    expected_length: ?usize,
    body_allowed: bool,
    trailers_pending: bool,
) bool {
    return body_allowed and
        (trailers_pending or expected_length == null or
            expected_length.? != 0);
}

pub fn sendConnectionPushStreamingHeads(
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
    bodies: *OutboundBodySet,
) Error!void {
    return sendConnectionPushStreamingHeadsUntil(
        connection,
        scratch,
        critical_scratch,
        options,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        bodies,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionPushStreamingHeadsWithDeadline(
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
    bodies: *OutboundBodySet,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionPushStreamingHeadsUntil(
        connection,
        scratch,
        critical_scratch,
        options,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        bodies,
        deadline,
    );
}

fn sendConnectionPushStreamingHeadsUntil(
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
    bodies: *OutboundBodySet,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    const streaming = try encodePushStreamingHeads(
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
    const retain_parent = retainStreamingBody(
        streaming.parent_expected_length,
        streaming.parent_body_allowed,
        response.trailers.len != 0,
    );
    const retain_pushed = retainStreamingBody(
        streaming.pushed_expected_length,
        streaming.pushed_body_allowed,
        push.response.trailers.len != 0,
    );
    var retained_ids: [2]u62 = undefined;
    var retained_count: usize = 0;
    if (retain_parent) {
        retained_ids[retained_count] = request_stream_id;
        retained_count += 1;
    }
    if (retain_pushed) {
        retained_ids[retained_count] = push_stream_id;
        retained_count += 1;
    }
    try bodies.reserveOpenMany(retained_ids[0..retained_count]);

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
    var parent_send = quic.stream_state.SendState.init(request_stream_id);
    try parent_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.parent.items,
        options.max_stream_frame_data,
        !retain_parent,
    );
    var pushed_send = quic.stream_state.SendState.init(push_stream_id);
    try pushed_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.pushed.items,
        options.max_stream_frame_data,
        !retain_pushed,
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
    if (retain_parent) {
        bodies.appendOpenAssumeCapacity(
            request_stream_id,
            parent_send,
            streaming.parent_expected_length,
        );
    }
    if (retain_pushed) {
        bodies.appendOpenAssumeCapacity(
            push_stream_id,
            pushed_send,
            streaming.pushed_expected_length,
        );
    }
}

pub fn sendProtectedPushStreamingHeads(
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
    bodies: *OutboundBodySet,
) Error!void {
    return sendProtectedPushStreamingHeadsUntil(
        endpoint,
        to,
        config,
        scratch,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        bodies,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedPushStreamingHeadsWithDeadline(
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
    bodies: *OutboundBodySet,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedPushStreamingHeadsUntil(
        endpoint,
        to,
        config,
        scratch,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        bodies,
        deadline,
    );
}

fn sendProtectedPushStreamingHeadsUntil(
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
    bodies: *OutboundBodySet,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    const streaming = try encodePushStreamingHeads(
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
    const retain_parent = retainStreamingBody(
        streaming.parent_expected_length,
        streaming.parent_body_allowed,
        response.trailers.len != 0,
    );
    const retain_pushed = retainStreamingBody(
        streaming.pushed_expected_length,
        streaming.pushed_body_allowed,
        push.response.trailers.len != 0,
    );
    var retained_ids: [2]u62 = undefined;
    var retained_count: usize = 0;
    if (retain_parent) {
        retained_ids[retained_count] = request_stream_id;
        retained_count += 1;
    }
    if (retain_pushed) {
        retained_ids[retained_count] = push_stream_id;
        retained_count += 1;
    }
    try bodies.reserveOpenMany(retained_ids[0..retained_count]);

    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }
    var parent_send = quic.stream_state.SendState.init(request_stream_id);
    try parent_send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.parent.items,
        config.max_stream_frame_data,
        !retain_parent,
    );
    var pushed_send = quic.stream_state.SendState.init(push_stream_id);
    try pushed_send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.pushed.items,
        config.max_stream_frame_data,
        !retain_pushed,
    );
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
    }
    if (retain_parent) {
        bodies.appendOpenAssumeCapacity(
            request_stream_id,
            parent_send,
            streaming.parent_expected_length,
        );
    }
    if (retain_pushed) {
        bodies.appendOpenAssumeCapacity(
            push_stream_id,
            pushed_send,
            streaming.pushed_expected_length,
        );
    }
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
    return sendConnectionPushUntil(
        connection,
        scratch,
        critical_scratch,
        options,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionPushWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionPushUntil(
        connection,
        scratch,
        critical_scratch,
        options,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        deadline,
    );
}

fn sendConnectionPushUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
    return sendProtectedPushUntil(
        endpoint,
        to,
        config,
        scratch,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedPushWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedPushUntil(
        endpoint,
        to,
        config,
        scratch,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        deadline,
    );
}

fn sendProtectedPushUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }
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
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
    }
}

pub const sendConnectionStreamingHead = streaming_head.sendConnectionStreamingHead;
pub const sendConnectionStreamingHeadWithDeadline = streaming_head.sendConnectionStreamingHeadWithDeadline;
pub const sendConnectionStreamingHeadProgress = streaming_head.sendProgress;

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
    return sendProtectedStreamingHeadUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        expected_length,
        body_allowed,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        bodies,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedStreamingHeadWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedStreamingHeadUntil(
        endpoint,
        to,
        config,
        scratch,
        stream_id,
        expected_length,
        body_allowed,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
        bodies,
        deadline,
    );
}

fn sendProtectedStreamingHeadUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    const retain_body_state = body_allowed and
        (expected_length == null or expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        !body_allowed or
            (expected_length != null and expected_length.? == 0),
    );
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
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
    return sendConnectionTrailersUntil(
        connection,
        bodies,
        scratch,
        critical_scratch,
        stream_id,
        trailers,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionTrailersWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendConnectionTrailersUntil(
        connection,
        bodies,
        scratch,
        critical_scratch,
        stream_id,
        trailers,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
        deadline,
    );
}

fn sendConnectionTrailersUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
    try entry.send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
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
    return sendProtectedTrailersUntil(
        endpoint,
        to,
        config,
        next_packet_number,
        protected_send,
        bodies,
        stream_id,
        trailers,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        scratch,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedTrailersWithDeadline(
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
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    return sendProtectedTrailersUntil(
        endpoint,
        to,
        config,
        next_packet_number,
        protected_send,
        bodies,
        stream_id,
        trailers,
        peer_settings,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        scratch,
        deadline,
    );
}

fn sendProtectedTrailersUntil(
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
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
    if (deadline) |absolute| {
        try sendProtectedQpackEncoderInstructionsWithDeadline(
            endpoint,
            to,
            config,
            qpack,
            qpack_encoder_send,
            qpack_encoder_prefix_sent,
            next_packet_number,
            protected_send,
            absolute,
        );
    } else {
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
    }
    try entry.send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            scratch.frames.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            scratch.frames.items,
            protected_send,
        );
    }
    _ = bodies.finish(stream_id);
}
