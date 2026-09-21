//! Incremental WebTransport session control over the Extended CONNECT stream.
//!
//! The HTTP/3 layer owns HEADERS/QPACK negotiation. After it detaches the
//! established CONNECT stream, this state machine consumes DATA frame payloads
//! as one continuous Capsule Protocol byte stream. Unknown capsules are skipped
//! without buffering their values; CLOSE retains at most the specification's
//! 1024-byte UTF-8 reason.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const association = @import("stream_association.zig");

pub const max_close_reason: usize = 1024;

pub const Error = webtransport.Error || http3.runtime.Error || error{
    InvalidSessionState,
};

pub const Event = union(enum) {
    draining,
    closed: Close,
    reset: webtransport.StreamError,

    pub const Close = struct {
        code: u32,
        /// Borrowed from `Control`; valid until that control is deinitialized.
        reason: []const u8,
    };
};

const VarIntDecoder = struct {
    bytes: [8]u8 = undefined,
    len: u8 = 0,
    expected: u8 = 0,

    fn reset(self: *VarIntDecoder) void {
        self.len = 0;
        self.expected = 0;
    }

    fn feed(self: *VarIntDecoder, byte: u8) ?u64 {
        if (self.len == 0) self.expected = quic.varint.encodedLen(byte);
        self.bytes[self.len] = byte;
        self.len += 1;
        if (self.len != self.expected) return null;
        const decoded = quic.varint.decodeSlice(
            self.bytes[0..self.expected],
        ) catch unreachable;
        self.reset();
        return decoded.value;
    }
};

const H3Stage = enum {
    frame_type,
    frame_length,
    frame_payload,
};

const CapsuleStage = enum {
    capsule_type,
    capsule_length,
    capsule_value,
};

pub const Control = struct {
    session_id: webtransport.SessionId,
    state: webtransport.SessionState,
    local_drain_sent: bool = false,
    local_drain_started: bool = false,
    local_close_started: bool = false,
    peer_drain_reported: bool = false,
    local_close_sent: bool = false,
    /// The CONNECT send direction became permanently unusable while a local
    /// CLOSE capsule was pending. The capsule must never be replayed, but
    /// associated stream cleanup may still be retried.
    local_close_failed: bool = false,
    terminal_reported: bool = false,

    h3_stage: H3Stage = .frame_type,
    h3_varint: VarIntDecoder = .{},
    h3_frame_type: u64 = 0,
    h3_payload_remaining: u64 = 0,

    capsule_stage: CapsuleStage = .capsule_type,
    capsule_varint: VarIntDecoder = .{},
    capsule_type: u64 = 0,
    capsule_value_remaining: u64 = 0,
    close_code_bytes: [4]u8 = undefined,
    close_code_len: u8 = 0,
    close_reason: [max_close_reason]u8 = undefined,
    close_reason_len: usize = 0,

    pub fn init(session_id: webtransport.SessionId) Error!Control {
        var state: webtransport.SessionState = .{};
        try state.establish(session_id);
        return .{ .session_id = session_id, .state = state };
    }

    pub fn ensureOpen(self: Control) Error!void {
        if (!self.state.established or self.state.closed or
            self.local_drain_started or self.local_close_started)
        {
            return error.InvalidSessionState;
        }
    }

    pub fn beginLocalClose(self: *Control) Error!void {
        try self.ensureOpen();
        self.local_close_started = true;
    }

    pub fn beginLocalDrain(self: *Control) Error!void {
        try self.ensureOpen();
        self.local_drain_started = true;
    }

    pub fn recordLocalDrain(self: *Control) Error!void {
        if (self.local_drain_started) {
            self.local_drain_started = false;
        } else {
            try self.ensureOpen();
        }
        if (self.local_drain_sent) return;
        self.local_drain_sent = true;
        self.state.drain();
    }

    pub fn recordLocalClose(
        self: *Control,
        code: u32,
    ) Error!void {
        if (self.local_close_started) {
            self.local_close_started = false;
            self.local_close_sent = true;
            if (!self.state.closed) self.state.close(code);
            return;
        }
        if (!self.state.established or self.state.closed) {
            return error.InvalidSessionState;
        }
        self.local_close_sent = true;
        self.state.close(code);
    }

    pub fn recordLocalCloseFailure(
        self: *Control,
        code: u32,
    ) void {
        self.local_drain_started = false;
        self.local_close_started = false;
        self.local_close_failed = true;
        if (!self.state.closed) self.state.close(code);
    }

    /// Block until the next peer drain/close/reset event.
    pub fn receive(
        self: *Control,
        connection: *quic.one_rtt.Connection,
        context: anytype,
        comptime receive_progress: anytype,
    ) !Event {
        while (true) {
            if (try self.poll(connection)) |event| return event;
            try receive_progress(context);
        }
    }

    pub fn poll(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!?Event {
        return self.pollInternal(connection, false);
    }

    /// Inspect buffered CONNECT-stream capsules without waiting for pacing.
    /// Parser state and QUIC receive bytes remain unchanged when a required
    /// MAX_DATA/MAX_STREAM_DATA update cannot be submitted.
    pub fn pollOnce(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!?Event {
        return self.pollInternal(connection, true);
    }

    fn pollInternal(
        self: *Control,
        connection: *quic.one_rtt.Connection,
        single_attempt: bool,
    ) Error!?Event {
        const available = connection.availableReceivedStream(
            self.session_id.value,
        ) orelse &.{};
        if (available.len != 0) {
            const snapshot = self.*;
            const result = self.consume(available) catch |err| {
                self.* = snapshot;
                return err;
            };
            const release_result = if (single_attempt)
                connection.tryReleaseReceivedCapacity(
                    self.session_id.value,
                    result.consumed,
                )
            else
                connection.releaseReceivedCapacity(
                    self.session_id.value,
                    result.consumed,
                );
            release_result catch |err| {
                self.* = snapshot;
                return err;
            };
            if (result.event) |event| return event;
        }

        const stats = connection.recvStreamStats(
            self.session_id.value,
        ) orelse return null;
        if (stats.reset) |reset| {
            if (self.terminal_reported) return null;
            self.terminal_reported = true;
            self.state.close(0);
            return .{ .reset = .fromHttp3(
                reset.application_error_code,
            ) };
        }
        if (stats.final_size != null and
            stats.bytes_read == stats.final_size.? and
            !self.terminal_reported)
        {
            if (!self.atMessageBoundary()) return error.InvalidCapsule;
            // A clean CONNECT FIN without WT_CLOSE_SESSION is defined as a
            // normal close with code zero and an empty reason.
            self.close_reason_len = 0;
            self.terminal_reported = true;
            self.state.close(0);
            return .{ .closed = .{
                .code = 0,
                .reason = self.close_reason[0..0],
            } };
        }
        return null;
    }

    fn consume(
        self: *Control,
        bytes: []const u8,
    ) Error!struct {
        consumed: usize,
        event: ?Event,
    } {
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.terminal_reported) return error.InvalidCapsule;
            const byte = bytes[offset];
            offset += 1;
            switch (self.h3_stage) {
                .frame_type => {
                    const frame_type = self.h3_varint.feed(byte) orelse
                        continue;
                    if (forbiddenConnectStreamFrame(frame_type)) {
                        return error.UnexpectedFrame;
                    }
                    self.h3_frame_type = frame_type;
                    self.h3_stage = .frame_length;
                },
                .frame_length => {
                    const length = self.h3_varint.feed(byte) orelse
                        continue;
                    self.h3_payload_remaining = length;
                    self.h3_stage = .frame_payload;
                    if (length == 0) self.finishH3Frame();
                },
                .frame_payload => {
                    std.debug.assert(self.h3_payload_remaining != 0);
                    self.h3_payload_remaining -= 1;
                    if (self.h3_frame_type == http3.FrameType.data) {
                        if (try self.feedCapsuleByte(byte)) |event| {
                            if (self.h3_payload_remaining == 0) {
                                self.finishH3Frame();
                            }
                            return .{
                                .consumed = offset,
                                .event = event,
                            };
                        }
                    }
                    if (self.h3_payload_remaining == 0) {
                        self.finishH3Frame();
                    }
                },
            }
        }
        return .{ .consumed = offset, .event = null };
    }

    pub fn feed(
        self: *Control,
        bytes: []const u8,
    ) Error!?Event {
        return (try self.consume(bytes)).event;
    }

    /// Feed Capsule Protocol payload bytes after HTTP/3 DATA framing has
    /// already been removed by a higher-level streaming reader.
    ///
    /// `consumed` lets adapters retain any bytes after the first event in a
    /// fixed pending buffer and replay them on the next poll.
    pub fn feedCapsulePayload(
        self: *Control,
        bytes: []const u8,
    ) Error!struct {
        consumed: usize,
        event: ?Event,
    } {
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.terminal_reported) return error.InvalidCapsule;
            const event = try self.feedCapsuleByte(bytes[offset]);
            offset += 1;
            if (event) |value| {
                return .{ .consumed = offset, .event = value };
            }
        }
        return .{ .consumed = offset, .event = null };
    }

    /// Interpret clean Extended CONNECT FIN after the H3 layer consumed all
    /// DATA frames. A partial capsule at FIN is a protocol error.
    pub fn finishCapsulePayload(self: *Control) Error!?Event {
        if (self.terminal_reported) return null;
        if (self.capsule_stage != .capsule_type or
            self.capsule_varint.len != 0)
        {
            return error.InvalidCapsule;
        }
        self.close_reason_len = 0;
        self.terminal_reported = true;
        self.state.close(0);
        return .{ .closed = .{
            .code = 0,
            .reason = self.close_reason[0..0],
        } };
    }

    fn finishH3Frame(self: *Control) void {
        self.h3_stage = .frame_type;
        self.h3_frame_type = 0;
        self.h3_payload_remaining = 0;
    }

    fn feedCapsuleByte(
        self: *Control,
        byte: u8,
    ) Error!?Event {
        switch (self.capsule_stage) {
            .capsule_type => {
                const capsule_type = self.capsule_varint.feed(byte) orelse
                    return null;
                self.capsule_type = capsule_type;
                self.capsule_stage = .capsule_length;
            },
            .capsule_length => {
                const length = self.capsule_varint.feed(byte) orelse
                    return null;
                self.capsule_value_remaining = length;
                if (self.capsule_type ==
                    webtransport.CapsuleType.drain_webtransport_session)
                {
                    if (length != 0) return error.InvalidCapsule;
                    self.resetCapsule();
                    if (self.peer_drain_reported) return null;
                    self.peer_drain_reported = true;
                    self.state.drain();
                    return .draining;
                }
                if (self.capsule_type ==
                    webtransport.CapsuleType.close_webtransport_session)
                {
                    if (length < 4 or
                        length > 4 + max_close_reason)
                    {
                        return error.InvalidCapsule;
                    }
                    self.close_code_len = 0;
                    self.close_reason_len = 0;
                }
                self.capsule_stage = .capsule_value;
                if (length == 0) self.resetCapsule();
            },
            .capsule_value => {
                if (self.capsule_type ==
                    webtransport.CapsuleType.close_webtransport_session)
                {
                    if (self.close_code_len < 4) {
                        self.close_code_bytes[self.close_code_len] = byte;
                        self.close_code_len += 1;
                    } else {
                        self.close_reason[self.close_reason_len] = byte;
                        self.close_reason_len += 1;
                    }
                }
                self.capsule_value_remaining -= 1;
                if (self.capsule_value_remaining == 0) {
                    if (self.capsule_type ==
                        webtransport.CapsuleType.close_webtransport_session)
                    {
                        if (!std.unicode.utf8ValidateSlice(
                            self.close_reason[0..self.close_reason_len],
                        )) {
                            return error.InvalidCapsule;
                        }
                        const code = std.mem.readInt(
                            u32,
                            &self.close_code_bytes,
                            .big,
                        );
                        // Keep the completed reason length: the event borrows
                        // this fixed buffer after parser state is reset.
                        self.capsule_stage = .capsule_type;
                        self.capsule_type = 0;
                        self.capsule_value_remaining = 0;
                        self.terminal_reported = true;
                        self.state.close(code);
                        return .{ .closed = .{
                            .code = code,
                            .reason = self.close_reason[0..self.close_reason_len],
                        } };
                    }
                    self.resetCapsule();
                }
            },
        }
        return null;
    }

    fn resetCapsule(self: *Control) void {
        self.capsule_stage = .capsule_type;
        self.capsule_type = 0;
        self.capsule_value_remaining = 0;
    }

    fn atMessageBoundary(self: Control) bool {
        return self.h3_stage == .frame_type and
            self.h3_varint.len == 0 and
            self.capsule_stage == .capsule_type and
            // `capsule_type` is also the stage used while a type varint is
            // incomplete. FIN there is truncation, not an empty clean close.
            self.capsule_varint.len == 0;
    }
};

/// A successful Extended CONNECT remains an HTTP/3 request stream. RFC 9114
/// permits DATA plus extension frames explicitly allowed for that stream; all
/// other known HTTP/3 frame types, and the reserved HTTP/2 code points, are a
/// connection error. Unknown extension/grease frames remain ignorable.
fn forbiddenConnectStreamFrame(frame_type: u64) bool {
    return switch (frame_type) {
        http3.FrameType.headers,
        http3.FrameType.cancel_push,
        http3.FrameType.settings,
        http3.FrameType.push_promise,
        http3.FrameType.goaway,
        http3.FrameType.origin,
        http3.FrameType.max_push_id,
        http3.FrameType.priority_update_request,
        http3.FrameType.priority_update_push,
        http3.FrameType.webtransport_stream,
        0x02,
        0x06,
        0x08,
        0x09,
        => true,
        else => false,
    };
}

pub fn writeDrainInto(out: []u8) Error![]u8 {
    return http3.capsule.writeInto(
        out,
        webtransport.CapsuleType.drain_webtransport_session,
        &.{},
    );
}

pub fn writeCloseInto(
    out: []u8,
    code: u32,
    reason: []const u8,
) Error![]u8 {
    if (reason.len > max_close_reason or
        !std.unicode.utf8ValidateSlice(reason))
    {
        return error.InvalidCapsule;
    }
    var value: [4 + max_close_reason]u8 = undefined;
    std.mem.writeInt(u32, value[0..4], code, .big);
    @memcpy(value[4..][0..reason.len], reason);
    return http3.capsule.writeInto(
        out,
        webtransport.CapsuleType.close_webtransport_session,
        value[0 .. 4 + reason.len],
    );
}

pub fn terminateStreams(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
) Error!void {
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try connection.resetStream(
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
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try connection.resetStreamWithDeadline(
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
    for (registry.registered()) |*stream| {
        const has_send_side = stream.direction == .bidirectional or
            stream.locally_initiated;
        if (has_send_side and
            !stream.local_fin and
            stream.send_reset == null and
            stream.stopped == null)
        {
            try connection.tryResetStream(
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
