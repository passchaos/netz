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
    peer_drain_reported: bool = false,
    local_close_sent: bool = false,
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
        if (!self.state.established or self.state.closed) {
            return error.InvalidSessionState;
        }
    }

    pub fn recordLocalDrain(self: *Control) Error!void {
        try self.ensureOpen();
        if (self.local_drain_sent) return;
        self.local_drain_sent = true;
        self.state.drain();
    }

    pub fn recordLocalClose(
        self: *Control,
        code: u32,
    ) Error!void {
        try self.ensureOpen();
        self.local_close_sent = true;
        self.state.close(code);
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
        const available = connection.availableReceivedStream(
            self.session_id.value,
        ) orelse &.{};
        if (available.len != 0) {
            const snapshot = self.*;
            const result = self.consume(available) catch |err| {
                self.* = snapshot;
                return err;
            };
            connection.releaseReceivedCapacity(
                self.session_id.value,
                result.consumed,
            ) catch |err| {
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
            self.capsule_stage == .capsule_type;
    }
};

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
    }
}
