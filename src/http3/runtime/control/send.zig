const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const send_packetizer = @import("../send/packetizer.zig");
const protected_send_module = @import("../send/protected.zig");
const send_scratch = @import("../send/scratch.zig");
const qpack_state = @import("../qpack/state.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const ProtectedSendState = protected_send_module.State;
const CriticalStreamSendScratch = send_scratch.Critical;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;

fn localSettings(options: anytype) http3.Settings {
    return if (@hasField(@TypeOf(options), "local_settings"))
        options.local_settings
    else
        .{};
}

fn maxFramesPerPacket(options: anytype) usize {
    return if (@hasField(@TypeOf(options), "max_frames_per_packet"))
        options.max_frames_per_packet
    else
        8;
}

fn maxStreamFrameData(options: anytype) usize {
    return if (@hasField(@TypeOf(options), "max_stream_frame_data"))
        options.max_stream_frame_data
    else
        1200;
}

fn sendConnectionFrames(
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
) Error!void {
    try send_packetizer.send(
        connection.endpoint.allocator,
        connection,
        frames,
        max_frames_per_packet,
    );
}

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: *ProtectedSendState,
) Error!void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

pub const ControlFrameKind = enum { goaway };
pub const PushControlFrameKind = enum { max_push_id, cancel_push };

pub fn controlFramePayloadInto(
    control: *http3.ControlState,
    storage: *[http3.max_single_varint_frame_len]u8,
    kind: ControlFrameKind,
    value: u64,
) Error![]const u8 {
    return switch (kind) {
        .goaway => control.writeGoAwayInto(storage, value),
    };
}

pub fn sendConnectionControlFrame(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: anytype,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_goaway_id = control.local_goaway_id;
    errdefer control.local_goaway_id = previous_goaway_id;
    const payload = try controlFramePayloadInto(control, &payload_storage, kind, value);
    try sendConnectionControlBytes(connection, control_send, options, payload);
}

pub fn pushControlFramePayloadInto(
    control: *http3.ControlState,
    storage: *[http3.max_single_varint_frame_len]u8,
    kind: PushControlFrameKind,
    push_id: u64,
) Error![]const u8 {
    return switch (kind) {
        .max_push_id => control.writeMaxPushIdInto(storage, push_id),
        .cancel_push => {
            const max_push_id = control.local_max_push_id orelse
                return error.PushIdExceeded;
            if (push_id > max_push_id) return error.PushIdExceeded;
            return http3.writeCancelPushFrameInto(storage, push_id);
        },
    };
}

pub fn sendConnectionControlBytes(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: anytype,
    payload: []const u8,
) Error!void {
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frame_storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(
        control_send,
        &frame_storage,
        payload,
        maxStreamFrameData(options),
    );
    try sendConnectionFrames(connection, frames, maxFramesPerPacket(options));
}

/// Split a small control message without allocating a temporary frame list.
/// The largest runtime control payload is a canonical PRIORITY_UPDATE at 19
/// bytes, so even the deliberately tiny one-byte STREAM chunk size used by
/// tests fits the fixed frame array.
pub fn controlFramesInto(
    control_send: *quic.stream_state.SendState,
    storage: *[http3.max_priority_update_frame_len]quic.Frame,
    payload: []const u8,
    max_frame_data_len: usize,
) Error![]const quic.Frame {
    std.debug.assert(payload.len <= storage.len);
    if (control_send.fin_sent) return error.FinalSizeMismatch;
    if (max_frame_data_len == 0) return error.InvalidStreamRange;
    const next_offset = std.math.add(
        u64,
        control_send.next_offset,
        payload.len,
    ) catch return error.InvalidStreamRange;
    var payload_offset: usize = 0;
    var frame_count: usize = 0;
    while (payload_offset < payload.len) {
        const chunk_len = @min(
            max_frame_data_len,
            payload.len - payload_offset,
        );
        storage[frame_count] = .{ .stream = .{
            .stream_id = control_send.stream_id,
            .offset = control_send.next_offset + payload_offset,
            .data = payload[payload_offset..][0..chunk_len],
            .fin = false,
        } };
        frame_count += 1;
        payload_offset += chunk_len;
    }
    control_send.next_offset = next_offset;
    return storage[0..frame_count];
}

pub fn sendConnectionPushControl(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: anytype,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_max_push_id = control.local_max_push_id;
    errdefer control.local_max_push_id = previous_max_push_id;
    const payload = try pushControlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        push_id,
    );
    try sendConnectionControlBytes(connection, control_send, options, payload);
}

pub fn sendConnectionPriorityUpdate(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: anytype,
    stream_id: u62,
    priority: http3.Priority,
) Error!void {
    try sendConnectionPriorityUpdateRaw(
        connection,
        control_send,
        options,
        http3.FrameType.priority_update_request,
        stream_id,
        priority,
    );
}

pub fn sendConnectionPriorityUpdateRaw(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: anytype,
    frame_type: u64,
    prioritized_element_id: u64,
    priority: http3.Priority,
) Error!void {
    var payload_storage: [http3.max_priority_update_frame_len]u8 = undefined;
    const payload = switch (frame_type) {
        http3.FrameType.priority_update_request => try http3.writePriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        http3.FrameType.priority_update_push => try http3.writePushPriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        else => return error.InvalidPriorityUpdate,
    };
    try sendConnectionControlBytes(connection, control_send, options, payload);
}

pub fn sendProtectedControlFrame(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_goaway_id = control.local_goaway_id;
    errdefer control.local_goaway_id = previous_goaway_id;
    const payload = try controlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        value,
    );
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
}

pub fn sendProtectedPushControl(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_max_push_id = control.local_max_push_id;
    errdefer control.local_max_push_id = previous_max_push_id;
    const payload = try pushControlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        push_id,
    );
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
}

pub fn sendProtectedControlBytes(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    payload: []const u8,
) Error!void {
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frame_storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(
        control_send,
        &frame_storage,
        payload,
        config.max_stream_frame_data,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames,
        config.max_frames_per_packet,
        protected_send,
    );
}

pub fn sendProtectedPriorityUpdate(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
    priority: http3.Priority,
) Error!void {
    try sendProtectedPriorityUpdateRaw(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        http3.FrameType.priority_update_request,
        stream_id,
        priority,
    );
}

pub fn sendProtectedPriorityUpdateRaw(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    frame_type: u64,
    prioritized_element_id: u64,
    priority: http3.Priority,
) Error!void {
    var payload_storage: [http3.max_priority_update_frame_len]u8 = undefined;
    const payload = switch (frame_type) {
        http3.FrameType.priority_update_request => try http3.writePriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        http3.FrameType.priority_update_push => try http3.writePushPriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        else => return error.InvalidPriorityUpdate,
    };
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
}

pub fn sendConnectionSettings(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: anytype,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    scratch.reset();
    try control.writeSettingsStream(
        &scratch.payload,
        connection.endpoint.allocator,
        localSettings(options),
    );
    const control_end = scratch.payload.items.len;
    const encoder_start = control_end;
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }
    const encoder_end = scratch.payload.items.len;
    const decoder_start = encoder_end;
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }

    // Append all bytes before forming borrowing slices so an ArrayList growth
    // cannot invalidate an earlier control/QPACK STREAM descriptor.
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items[0..control_end],
        control_end,
        false,
    );
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(
            encoder_stream_id,
        );
    }
    if (encoder_end != encoder_start) {
        try qpack_encoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[encoder_start..encoder_end],
            encoder_end - encoder_start,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (scratch.payload.items.len != decoder_start) {
        try qpack_decoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[decoder_start..],
            scratch.payload.items.len - decoder_start,
            false,
        );
    }
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        maxFramesPerPacket(options),
    );
    if (encoder_end != encoder_start) qpack_encoder_prefix_sent.* = true;
    if (scratch.payload.items.len != decoder_start) {
        qpack_decoder_prefix_sent.* = true;
    }
}

/// Submit the complete local critical-stream preface in one packet without
/// waiting for pacing. All HTTP/3 send cursors remain unchanged when the
/// packet cannot be submitted, so an endpoint loop can retry verbatim.
pub fn trySendConnectionSettings(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: anytype,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    scratch.reset();
    try control.writeSettingsStream(
        &scratch.payload,
        connection.endpoint.allocator,
        localSettings(options),
    );
    const control_end = scratch.payload.items.len;
    const encoder_start = control_end;
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }
    const encoder_end = scratch.payload.items.len;
    const decoder_start = encoder_end;
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }

    if (control_send.stream_id != stream_id) {
        control_send.* = quic.stream_state.SendState.init(stream_id);
    }
    try control_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items[0..control_end],
        control_end,
        false,
    );
    const encoder_stream_id = if (is_client)
        client_qpack_encoder_stream_id
    else
        server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(
            encoder_stream_id,
        );
    }
    if (encoder_end != encoder_start) {
        try qpack_encoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[encoder_start..encoder_end],
            encoder_end - encoder_start,
            false,
        );
    }
    const decoder_stream_id = if (is_client)
        client_qpack_decoder_stream_id
    else
        server_qpack_decoder_stream_id;
    if (qpack_decoder_send.stream_id != decoder_stream_id) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            decoder_stream_id,
        );
    }
    if (scratch.payload.items.len != decoder_start) {
        try qpack_decoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[decoder_start..],
            scratch.payload.items.len - decoder_start,
            false,
        );
    }
    if (scratch.frames.items.len > maxFramesPerPacket(options) or
        try connection.packetLenForFramesAtOffset(
            0,
            scratch.frames.items,
        ) > connection.currentSendDatagramSize())
    {
        return error.DatagramTooLarge;
    }
    try connection.trySend(scratch.frames.items);
    if (encoder_end != encoder_start) qpack_encoder_prefix_sent.* = true;
    if (scratch.payload.items.len != decoder_start) {
        qpack_decoder_prefix_sent.* = true;
    }
}

pub fn sendConnectionQpackEncoderInstructions(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    qpack: *QpackEncodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: anytype,
) Error!void {
    const pending = qpack.pendingEncoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    scratch.reset();
    try scratch.payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }
    scratch.payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items,
        maxStreamFrameData(options),
        false,
    );
    // Keep the critical encoder stream in an earlier packet than any field
    // section that may depend on it, including when frame-list chunking is one.
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        maxFramesPerPacket(options),
    );
    prefix_sent.* = true;
    qpack.clearEncoderInstructions();
}

pub fn sendConnectionQpackFeedback(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: anytype,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    scratch.reset();
    try scratch.payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &scratch.payload,
        connection.endpoint.allocator,
    );
    scratch.payload.appendSliceAssumeCapacity(pending);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items,
        maxStreamFrameData(options),
        false,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        maxFramesPerPacket(options),
    );
    prefix_sent.* = true;
    qpack.clearDecoderInstructions();
}

/// Submit pending decoder instructions once without waiting for pacing. The
/// QPACK queue and stream offset remain unchanged when transport backpressure
/// rejects the packet, so an endpoint owner can retry after its next turn.
pub fn trySendConnectionQpackFeedback(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: anytype,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    scratch.reset();
    try scratch.payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &scratch.payload,
        connection.endpoint.allocator,
    );
    scratch.payload.appendSliceAssumeCapacity(pending);
    const prefix_len = scratch.payload.items.len - pending.len;
    const frame_limit = @max(@as(usize, 1), maxFramesPerPacket(options));
    var low: usize = 1;
    var high: usize = pending.len;
    var fitting: usize = 0;
    while (low <= high) {
        const candidate = low + (high - low) / 2;
        var staged = send_state.*;
        scratch.frames.clearRetainingCapacity();
        try staged.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[0 .. prefix_len + candidate],
            maxStreamFrameData(options),
            false,
        );
        if (scratch.frames.items.len <= frame_limit and
            try connection.packetLenForFramesAtOffset(
                0,
                scratch.frames.items,
            ) <= connection.currentSendDatagramSize())
        {
            fitting = candidate;
            low = candidate + 1;
        } else {
            high = candidate - 1;
        }
    }
    if (fitting == 0) return error.DatagramTooLarge;

    var staged_send = send_state.*;
    scratch.frames.clearRetainingCapacity();
    try staged_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items[0 .. prefix_len + fitting],
        maxStreamFrameData(options),
        false,
    );
    try connection.trySend(scratch.frames.items);
    send_state.* = staged_send;
    prefix_sent.* = true;
    qpack.consumeDecoderInstructions(fitting);
}

pub fn cancelConnectionRequest(
    connection: *quic.one_rtt.Connection,
    critical_scratch: *CriticalStreamSendScratch,
    qpack: *QpackDecodeState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: anytype,
    stream_id: u62,
    application_error_code: u64,
    cancel_qpack: bool,
) Error!void {
    const send_state = connection.sendStreamStats(stream_id);
    if (send_state == null or
        (send_state.?.final_size == null and send_state.?.reset == null))
    {
        try connection.resetStream(stream_id, application_error_code);
    }
    try connection.sendStopSending(stream_id, application_error_code);
    if (cancel_qpack) {
        try qpack.recordStreamCancellation(stream_id);
        try sendConnectionQpackFeedback(
            connection,
            critical_scratch,
            qpack,
            qpack_decoder_send,
            qpack_decoder_prefix_sent,
            options,
        );
    }
}

pub fn sendProtectedSettings(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    // appendFrames advances offsets before the UDP send. Restoring all three
    // streams makes a retry emit identical bytes at identical offsets after an
    // allocation or socket failure (including a partially sent frame batch).
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try control.writeSettingsStream(
        payload,
        endpoint.allocator,
        config.local_settings,
    );
    const control_end = payload.items.len;
    const encoder_start = control_end;
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(payload, endpoint.allocator);
    }
    const encoder_end = payload.items.len;
    const decoder_start = encoder_end;
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(payload, endpoint.allocator);
    }

    // Form borrowing slices only after every append is complete: growing the
    // shared byte list while frames already point into it would invalidate the
    // earlier control/QPACK STREAM descriptors.
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(
        frames,
        endpoint.allocator,
        payload.items[0..control_end],
        control_end,
        false,
    );
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(encoder_stream_id);
    }
    if (encoder_end != encoder_start) {
        try qpack_encoder_send.appendFrames(
            frames,
            endpoint.allocator,
            payload.items[encoder_start..encoder_end],
            encoder_end - encoder_start,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (payload.items.len != decoder_start) {
        try qpack_decoder_send.appendFrames(
            frames,
            endpoint.allocator,
            payload.items[decoder_start..],
            payload.items.len - decoder_start,
            false,
        );
    }
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    if (encoder_end != encoder_start) qpack_encoder_prefix_sent.* = true;
    if (payload.items.len != decoder_start) qpack_decoder_prefix_sent.* = true;
}

pub fn sendProtectedQpackEncoderInstructions(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    qpack: *QpackEncodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    const pending = qpack.pendingEncoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(payload, endpoint.allocator);
    }
    payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        false,
    );
    // Encoder-stream bytes must be visible before any request/response field
    // section that could depend on them. A separate send also preserves this
    // ordering when max_frames_per_packet would otherwise split one frame list.
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    prefix_sent.* = true;
    qpack.clearEncoderInstructions();
}

pub fn sendProtectedQpackFeedback(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        payload,
        endpoint.allocator,
    );
    payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        false,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    prefix_sent.* = true;
    qpack.clearDecoderInstructions();
}

pub fn sendProtectedRequestCancellation(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    qpack: *QpackDecodeState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
    application_error_code: u64,
    local_final_size: u64,
    send_reset: bool,
    cancel_qpack: bool,
) Error!void {
    const frames = [_]quic.Frame{
        .{ .reset_stream = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = local_final_size,
        } },
        .{ .stop_sending = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        } },
    };
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        if (send_reset) &frames else frames[1..],
        config.max_frames_per_packet,
        protected_send,
    );
    if (cancel_qpack) {
        try qpack.recordStreamCancellation(stream_id);
        try sendProtectedQpackFeedback(
            endpoint,
            to,
            config,
            qpack,
            qpack_decoder_send,
            qpack_decoder_prefix_sent,
            next_packet_number,
            protected_send,
        );
    }
}
