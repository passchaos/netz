//! Incremental WebTransport session control over the Extended CONNECT stream.
//!
//! The HTTP/3 layer owns HEADERS/QPACK negotiation. After it detaches the
//! established CONNECT stream, this state machine consumes DATA frame payloads
//! as one continuous Capsule Protocol byte stream. Unknown capsules are skipped
//! without buffering their values; CLOSE retains at most the specification's
//! 1024-byte UTF-8 reason.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const stream_termination = @import("session_control/stream_termination.zig");

pub const TerminateProgress = stream_termination.TerminateProgress;
pub const terminateStreams = stream_termination.terminateStreams;
pub const terminateStreamsOnce = stream_termination.terminateStreamsOnce;
pub const terminateStreamsWithDeadline = stream_termination.terminateStreamsWithDeadline;

pub const max_close_reason: usize = webtransport.max_close_reason;
const inline_close_reason_capacity: usize = 128;

pub const Error = webtransport.Error || http3.runtime.Error || error{
    InvalidSessionState,
} || std.mem.Allocator.Error;

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
    allocator: std.mem.Allocator,
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
    /// A peer sent bytes beyond WT_CLOSE_SESSION. The valid close event remains
    /// application-visible, while the CONNECT stream must be canceled with
    /// H3_MESSAGE_ERROR before normal FIN/cleanup can continue.
    post_terminal_data_pending: bool = false,
    post_terminal_data_rejected: bool = false,
    /// A malformed Capsule or truncated CONNECT message has been detected.
    /// Application sends stop immediately; socket-visible rejection commits
    /// only after its RESET_STREAM/STOP_SENDING packet is submitted.
    capsule_error_pending: bool = false,
    capsule_error_rejected: bool = false,

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
    close_reason_inline: [inline_close_reason_capacity]u8 = undefined,
    close_reason_heap: ?[]u8 = null,
    close_reason_len: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        session_id: webtransport.SessionId,
    ) Error!Control {
        var state: webtransport.SessionState = .{};
        try state.establish(session_id);
        return .{
            .allocator = allocator,
            .session_id = session_id,
            .state = state,
        };
    }

    pub fn deinit(self: *Control) void {
        self.clearCloseReason();
        self.* = undefined;
    }

    fn closeReason(self: *const Control) []const u8 {
        if (self.close_reason_heap) |reason| {
            return reason[0..self.close_reason_len];
        }
        return self.close_reason_inline[0..self.close_reason_len];
    }

    fn prepareCloseReason(self: *Control, len: usize) !void {
        std.debug.assert(self.close_reason_heap == null);
        if (len > self.close_reason_inline.len) {
            self.close_reason_heap = try self.allocator.alloc(u8, len);
        }
        self.close_reason_len = 0;
    }

    fn appendCloseReasonByte(self: *Control, byte: u8) void {
        if (self.close_reason_heap) |reason| {
            reason[self.close_reason_len] = byte;
        } else {
            self.close_reason_inline[self.close_reason_len] = byte;
        }
        self.close_reason_len += 1;
    }

    fn clearCloseReason(self: *Control) void {
        if (self.close_reason_heap) |reason| {
            std.crypto.secureZero(u8, reason);
            self.allocator.free(reason);
            self.close_reason_heap = null;
        } else {
            std.crypto.secureZero(
                u8,
                self.close_reason_inline[0..self.close_reason_len],
            );
        }
        self.close_reason_len = 0;
    }

    /// Restore parser state after a surrounding transport transaction fails.
    /// Any close-reason allocation created after the snapshot is released;
    /// bytes appended to an existing allocation are hidden by the old length.
    pub fn restoreSnapshot(self: *Control, snapshot: Control) void {
        if (self.close_reason_heap) |current| {
            const same_allocation = if (snapshot.close_reason_heap) |previous|
                current.ptr == previous.ptr
            else
                false;
            if (!same_allocation) {
                std.crypto.secureZero(u8, current);
                self.allocator.free(current);
            }
        }
        self.* = snapshot;
    }

    pub fn ensureOpen(self: Control) Error!void {
        if (!self.state.established or self.state.closed or
            self.local_drain_started or self.local_close_started or
            self.capsule_error_pending)
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
        if (self.terminal_reported) {
            if (available.len == 0 or self.handledInvalidCapsule()) {
                return null;
            }
            self.post_terminal_data_pending = true;
            _ = if (single_attempt)
                try self.tryRejectPostTerminalData(connection)
            else
                try self.rejectPostTerminalData(connection);
            return error.InvalidCapsule;
        }
        if (available.len != 0) {
            const snapshot = self.*;
            const result = self.consume(available) catch |err| {
                self.restoreSnapshot(snapshot);
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
                self.restoreSnapshot(snapshot);
                return err;
            };
            if (result.event != null and self.terminal_reported and
                available.len > result.consumed)
            {
                self.post_terminal_data_pending = true;
            }
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
            self.clearCloseReason();
            self.terminal_reported = true;
            self.state.close(0);
            return .{ .closed = .{
                .code = 0,
                .reason = &.{},
            } };
        }
        return null;
    }

    /// Cancel a CONNECT stream whose peer sent bytes after WT_CLOSE_SESSION.
    /// RESET_STREAM and STOP_SENDING are submitted together when both halves
    /// remain open; QUIC discards every already-buffered offending byte only
    /// after the terminal packet reaches the socket.
    pub fn rejectPostTerminalData(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!bool {
        if (!self.notePostTerminalData(connection)) return false;
        try connection.cancelStream(
            self.session_id.value,
            http3.ApplicationErrorCode.message_error,
        );
        self.commitPostTerminalDataRejection();
        return true;
    }

    /// One-attempt event-loop counterpart to `rejectPostTerminalData`.
    pub fn tryRejectPostTerminalData(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!bool {
        if (!self.notePostTerminalData(connection)) return false;
        try connection.tryCancelStream(
            self.session_id.value,
            http3.ApplicationErrorCode.message_error,
        );
        self.commitPostTerminalDataRejection();
        return true;
    }

    pub fn handledPostTerminalData(self: Control) bool {
        return self.post_terminal_data_rejected;
    }

    pub fn handledInvalidCapsule(self: Control) bool {
        return self.post_terminal_data_rejected or self.capsule_error_rejected;
    }

    /// Apply RFC 9297 malformed-message handling to this CONNECT stream.
    /// The parser caller retains InvalidCapsule as its one terminal result.
    pub fn rejectInvalidCapsule(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!bool {
        if (self.handledInvalidCapsule()) return false;
        self.capsule_error_pending = true;
        try connection.cancelStream(
            self.session_id.value,
            http3.ApplicationErrorCode.message_error,
        );
        self.commitCapsuleErrorRejection();
        return true;
    }

    /// A shared endpoint may defer pacing/congestion without accepting new
    /// application operations or consuming the invalid bytes before retry.
    pub fn tryRejectInvalidCapsule(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) Error!bool {
        if (self.handledInvalidCapsule()) return false;
        self.capsule_error_pending = true;
        try connection.tryCancelStream(
            self.session_id.value,
            http3.ApplicationErrorCode.message_error,
        );
        self.commitCapsuleErrorRejection();
        return true;
    }

    fn commitCapsuleErrorRejection(self: *Control) void {
        self.capsule_error_pending = false;
        self.capsule_error_rejected = true;
        self.terminal_reported = true;
        self.recordLocalCloseFailure(0);
        self.clearCloseReason();
    }

    fn notePostTerminalData(
        self: *Control,
        connection: *quic.one_rtt.Connection,
    ) bool {
        if (!self.terminal_reported or self.handledInvalidCapsule()) {
            return false;
        }
        if (!self.post_terminal_data_pending) {
            const available = connection.availableReceivedStream(
                self.session_id.value,
            ) orelse &.{};
            if (available.len == 0) return false;
            self.post_terminal_data_pending = true;
        }
        return true;
    }

    fn commitPostTerminalDataRejection(self: *Control) void {
        self.post_terminal_data_pending = false;
        self.post_terminal_data_rejected = true;
        // The CONNECT stream entered protocol-violation cleanup; suppress
        // every later CLOSE/FIN retry whether cancellation reset the send side
        // or a previously committed FIN left only STOP_SENDING to emit.
        self.local_close_failed = true;
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
        const snapshot = self.*;
        const result = self.consume(bytes) catch |err| {
            self.restoreSnapshot(snapshot);
            return err;
        };
        return result.event;
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
        const snapshot = self.*;
        var offset: usize = 0;
        while (offset < bytes.len) {
            if (self.terminal_reported) return error.InvalidCapsule;
            const event = self.feedCapsuleByte(bytes[offset]) catch |err| {
                self.restoreSnapshot(snapshot);
                return err;
            };
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
        self.clearCloseReason();
        self.terminal_reported = true;
        self.state.close(0);
        return .{ .closed = .{
            .code = 0,
            .reason = &.{},
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
                    try self.prepareCloseReason(@intCast(length - 4));
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
                        self.appendCloseReasonByte(byte);
                    }
                }
                self.capsule_value_remaining -= 1;
                if (self.capsule_value_remaining == 0) {
                    if (self.capsule_type ==
                        webtransport.CapsuleType.close_webtransport_session)
                    {
                        if (!std.unicode.utf8ValidateSlice(
                            self.closeReason(),
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
                            .reason = self.closeReason(),
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
        http3.FrameType.push_promise,
        => true,
        else => http3.messageStreamForbiddenFrame(frame_type),
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
