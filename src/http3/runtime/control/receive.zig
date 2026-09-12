const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const wire = @import("../../../internal/wire.zig");
const runtime_error = @import("../error.zig");
const stream_lifecycle = @import("../stream/lifecycle.zig");
const qpack_state = @import("../qpack/state.zig");
const exact_range_set = @import("../../../internal/exact_range_set.zig");

const Error = runtime_error.Error;
const ServerRequestLifecycle = stream_lifecycle.Server;
const QpackEncodeState = qpack_state.QpackEncodeState;

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;

pub const MessageStreamDisposition = enum {
    request_response,
    ignore,
};

pub fn validateServerGoAwayStreamId(stream_id: u64) http3.Error!void {
    // RFC 9114 requires a server GOAWAY identifier to be a client-initiated
    // bidirectional request stream ID.
    if ((stream_id & 0x3) != 0) return error.IdError;
}

pub fn validateClientGoAwayPushId(push_id: u64) http3.Error!void {
    if (push_id > quic.varint.max_value) return error.IdError;
}

pub const ServerPushIdSet = exact_range_set.Set;

pub const PromisedPushIds = union(enum) {
    none,
    slice: []const u64,
    set: *const ServerPushIdSet,

    pub fn contains(self: PromisedPushIds, push_id: u64) bool {
        return switch (self) {
            .none => false,
            .slice => |ids| std.mem.indexOfScalar(u64, ids, push_id) != null,
            .set => |ids| ids.contains(push_id),
        };
    }
};

pub fn validateNewServerPush(
    control: http3.ControlState,
    promised_push_ids: ServerPushIdSet,
    push_id: u64,
) Error!void {
    if (control.peer_goaway_id) |goaway_id| {
        if (push_id >= goaway_id) return error.GoAwayReceived;
    }
    if (control.pushCancelled(push_id)) return error.RequestCancelled;
    if (promised_push_ids.contains(push_id)) return error.DuplicatePushId;
}

pub fn rejectByLocalGoAway(
    control: http3.ControlState,
    role: ControlStreamRole,
    stream_id: u64,
) bool {
    return switch (role) {
        // A server GOAWAY carries the largest client-initiated request stream
        // ID that can still be processed. A client GOAWAY carries a push ID,
        // not a response stream ID.
        .server => !control.acceptsLocalRequestStream(stream_id),
        .client => false,
    };
}

pub fn messageStreamDisposition(
    stream_id: u64,
) Error!MessageStreamDisposition {
    if ((stream_id & 0x02) != 0) return .ignore;
    if ((stream_id & 0x01) != 0) return error.StreamCreationError;
    return .request_response;
}

pub const ControlStreamRole = enum {
    client,
    server,
};

pub const ServerRequestIdValidator = union(enum) {
    connection: *quic.one_rtt.Connection,
    static_limit: u64,

    fn accepts(self: @This(), stream_id: u64) bool {
        return switch (self) {
            .connection => |connection| connection
                .isPeerInitiatedBidirectionalStreamIdWithinLimit(stream_id),
            .static_limit => |limit| stream_id <= quic.varint.max_value and
                (stream_id & 0x03) == 0 and
                stream_id / 4 < limit,
        };
    }

    pub fn requestReceptionStopped(
        self: @This(),
        stream_id: u62,
    ) bool {
        return switch (self) {
            .connection => |connection| if (connection.recvStreamStats(
                stream_id,
            )) |stats| stats.stop_sending_sent != null else false,
            .static_limit => false,
        };
    }

    pub fn peerStreamClosed(
        self: @This(),
        stream_id: u62,
    ) bool {
        return switch (self) {
            .connection => |connection| connection.peerStreamClosed(stream_id),
            .static_limit => false,
        };
    }

    pub fn requestCompletedPeerStreamRelease(
        self: @This(),
        stream_id: u62,
    ) Error!bool {
        return switch (self) {
            .connection => |connection| {
                return connection.requestCompletedPeerStreamRelease(stream_id);
            },
            .static_limit => true,
        };
    }

    pub fn commitReceivedThrough(
        self: @This(),
        stream_id: u64,
        end_offset: u64,
    ) Error!void {
        switch (self) {
            .connection => |connection| try connection.commitReceivedThrough(
                stream_id,
                end_offset,
            ),
            .static_limit => {},
        }
    }
};

const ServerControlFrameValidator = struct {
    request_ids: ServerRequestIdValidator,
    promised_push_ids: PromisedPushIds,
    request_lifecycle: ?*const ServerRequestLifecycle,

    fn validate(
        context: *const anyopaque,
        state: http3.ControlState,
        frame: http3.Frame,
    ) http3.Error!http3.ControlState.FrameDisposition {
        const self: *const ServerControlFrameValidator =
            @ptrCast(@alignCast(context));
        switch (frame.frame_type) {
            http3.FrameType.goaway => try validateClientGoAwayPushId(
                try http3.parseGoAwayPayload(frame.payload),
            ),
            http3.FrameType.origin => return error.UnexpectedFrame,
            http3.FrameType.cancel_push => {
                const push_id = try http3.parseCancelPushPayload(
                    frame.payload,
                );
                const within_limit = if (state.peer_max_push_id) |max_push_id|
                    push_id <= max_push_id
                else
                    false;
                if (!within_limit) return error.PushIdExceeded;
                if (!self.promised_push_ids.contains(push_id)) {
                    return error.IdError;
                }
            },
            http3.FrameType.priority_update_request => {
                const update = try http3.parsePriorityUpdatePayload(
                    frame.payload,
                );
                if (!self.request_ids.accepts(
                    update.prioritized_element_id,
                )) return error.IdError;
                if (state.retired_request_priority_through) |retired| {
                    const stream_id: u62 = @intCast(
                        update.prioritized_element_id,
                    );
                    const active = if (self.request_lifecycle) |lifecycle|
                        lifecycle.contains(stream_id)
                    else
                        false;
                    if (!active and stream_id <= retired) return .ignore;
                }
            },
            http3.FrameType.priority_update_push => {
                const update = try http3.parsePriorityUpdatePayload(
                    frame.payload,
                );
                const within_limit = if (state.peer_max_push_id) |max_push_id|
                    update.prioritized_element_id <= max_push_id
                else
                    false;
                if (!within_limit or
                    !self.promised_push_ids.contains(
                        update.prioritized_element_id,
                    )) return error.IdError;
                if (state.pushCancelled(update.prioritized_element_id)) {
                    return .ignore;
                }
                if (state.retired_push_priority_through) |retired| {
                    if (update.prioritized_element_id <= retired) {
                        return .ignore;
                    }
                }
            },
            else => {},
        }
        return .apply;
    }
};

const ClientControlFrameValidator = struct {
    fn validate(
        _: *const anyopaque,
        _: http3.ControlState,
        frame: http3.Frame,
    ) http3.Error!http3.ControlState.FrameDisposition {
        switch (frame.frame_type) {
            http3.FrameType.goaway => try validateServerGoAwayStreamId(
                try http3.parseGoAwayPayload(frame.payload),
            ),
            http3.FrameType.max_push_id,
            http3.FrameType.cancel_push,
            http3.FrameType.priority_update_request,
            http3.FrameType.priority_update_push,
            => return error.UnexpectedFrame,
            else => {},
        }
        return .apply;
    }
};

pub fn configureQpackEncoderFromPeerSettings(
    control: http3.ControlState,
    qpack: *QpackEncodeState,
) Error!void {
    if (!control.settings.received) return;
    const capacity = std.math.cast(
        usize,
        control.settings.peer.qpack_max_table_capacity,
    ) orelse return error.InvalidSetting;
    try qpack.configurePeerLimits(
        capacity,
        control.settings.peer.qpack_blocked_streams,
    );
}

pub fn applyControlStreamFrameForRole(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame, role: ControlStreamRole) Error!bool {
    return applyControlStreamFrameForRoleWithPushes(
        control,
        allocator,
        stream,
        role,
        .none,
        if (role == .server)
            .{ .static_limit = quic.max_stream_count }
        else
            null,
        null,
    );
}

pub fn applyControlStreamFrameForRoleWithPushes(
    control: *http3.ControlState,
    allocator: std.mem.Allocator,
    stream: quic.StreamFrame,
    role: ControlStreamRole,
    promised_push_ids: PromisedPushIds,
    request_id_validator: ?ServerRequestIdValidator,
    request_lifecycle: ?*const ServerRequestLifecycle,
) Error!bool {
    const server_validator = ServerControlFrameValidator{
        .request_ids = request_id_validator orelse
            .{ .static_limit = quic.max_stream_count },
        .promised_push_ids = promised_push_ids,
        .request_lifecycle = request_lifecycle,
    };
    const client_validator = ClientControlFrameValidator{};
    // HTTP/3 control, QPACK, and push streams are unidirectional.  Request and
    // response STREAM frames are already validated by the message decoder, so
    // skip the expensive control-state clone/rollback path for the common
    // bidirectional data path.
    if ((stream.stream_id & 0x02) == 0) return false;
    if (role == .server and stream.offset == 0) {
        if (peekUniStreamType(stream) == .push) return error.StreamCreationError;
    }
    if (stream.offset == 0) {
        switch (peekUniStreamType(stream) orelse return false) {
            .control, .qpack_encoder, .qpack_decoder => {},
            else => return false,
        }
    } else if (!isRegisteredCriticalStream(control.*, stream.stream_id)) {
        return false;
    }
    return applyControlStreamFrameValidated(
        control,
        allocator,
        stream,
        switch (role) {
            .server => .{
                .context = &server_validator,
                .validate = ServerControlFrameValidator.validate,
            },
            .client => .{
                .context = &client_validator,
                .validate = ClientControlFrameValidator.validate,
            },
        },
    );
}

pub fn peekUniStreamType(stream: quic.StreamFrame) ?http3.StreamType {
    var prefix_cursor = wire.Cursor.init(stream.data);
    return @enumFromInt(quic.varint.decode(&prefix_cursor) catch return null);
}

pub fn applyControlStreamFrame(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame) Error!bool {
    return applyControlStreamFrameValidated(control, allocator, stream, null);
}

pub fn applyControlStreamFrameValidated(
    control: *http3.ControlState,
    allocator: std.mem.Allocator,
    stream: quic.StreamFrame,
    validator: ?http3.ControlState.FrameValidator,
) Error!bool {
    const previous_control_stream_id = control.peer_control_stream_id;
    errdefer control.peer_control_stream_id = previous_control_stream_id;
    // HTTP/3 control and QPACK streams are unidirectional QUIC streams.  Offset
    // zero carries the stream type varint; subsequent frames on an already
    // registered critical stream contain only that stream's payload.
    if ((stream.stream_id & 0x02) == 0) return false;
    const stream_offset = std.math.cast(usize, stream.offset) orelse
        return error.InvalidStreamRange;
    const stream_end = std.math.add(
        usize,
        stream_offset,
        stream.data.len,
    ) catch return error.InvalidStreamRange;
    if (isRegisteredCriticalStream(control.*, stream.stream_id)) {
        try rejectClosedCriticalStream(stream);
    }
    if (control.peer_control_stream_id != null and
        control.peer_control_stream_id.? == stream.stream_id)
    {
        if (stream_end <= control.peer_control_stream_consumed_offset) {
            return true;
        }
        if (stream_offset > control.peer_control_stream_consumed_offset) {
            return error.BufferTooShort;
        }
        const payload_start =
            control.peer_control_stream_consumed_offset - stream_offset;
        try control.appendControlPayloadValidated(
            allocator,
            stream.data[payload_start..],
            validator,
        );
        control.peer_control_stream_consumed_offset = stream_end;
        return true;
    }
    if (stream.offset != 0) {
        if ((control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream.stream_id) or
            (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream.stream_id))
        {
            return error.QpackDynamicTableUnsupported;
        }
        return false;
    }

    if (stream.data.len == 0) return false;
    var prefix_cursor = wire.Cursor.init(stream.data);
    const stream_type = peekUniStreamType(stream) orelse return false;
    _ = quic.varint.decode(&prefix_cursor) catch unreachable;
    switch (stream_type) {
        .control => {
            try rejectClosedCriticalStream(stream);
            try control.registerControlStream(stream.stream_id);
            const apply_start = @max(
                prefix_cursor.pos,
                control.peer_control_stream_consumed_offset,
            );
            if (apply_start < stream.data.len) {
                try control.appendControlPayloadValidated(
                    allocator,
                    stream.data[apply_start..],
                    validator,
                );
            }
            control.peer_control_stream_consumed_offset = stream_end;
        },
        .qpack_encoder, .qpack_decoder => {
            try rejectClosedCriticalStream(stream);
            try control.registerQpackStream(stream_type, stream.stream_id);
            if (stream.data[prefix_cursor.pos..].len != 0) return error.QpackDynamicTableUnsupported;
        },
        else => return false,
    }
    return true;
}

pub fn isRegisteredCriticalStream(control: http3.ControlState, stream_id: u64) bool {
    return (control.peer_control_stream_id != null and control.peer_control_stream_id.? == stream_id) or
        (control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream_id) or
        (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream_id);
}

fn isLocalCriticalStream(role: ControlStreamRole, stream_id: u64) bool {
    return switch (role) {
        .client => stream_id == client_control_stream_id or stream_id == client_qpack_encoder_stream_id or stream_id == client_qpack_decoder_stream_id,
        .server => stream_id == server_control_stream_id or stream_id == server_qpack_encoder_stream_id or stream_id == server_qpack_decoder_stream_id,
    };
}

pub fn rejectCriticalStreamClosureFrame(control: http3.ControlState, frame: quic.Frame, role: ControlStreamRole) Error!void {
    switch (frame) {
        .reset_stream => |reset| {
            if (isRegisteredCriticalStream(control, reset.stream_id)) return error.ClosedCriticalStream;
        },
        .stop_sending => |stop| {
            // RFC 9204 §4.2 also forbids requesting closure of the peer's
            // QPACK streams.  Treat STOP_SENDING for our locally-created
            // critical streams the same way tquic/quic-zig treat reset/FIN:
            // as H3_CLOSED_CRITICAL_STREAM at the HTTP/3 layer.
            if (isLocalCriticalStream(role, stop.stream_id)) return error.ClosedCriticalStream;
        },
        else => {},
    }
}

pub fn rejectClosedCriticalStream(stream: quic.StreamFrame) Error!void {
    // RFC 9114 §6.2.1 and RFC 9204 §4.2 make the control stream and both
    // QPACK streams connection-long-lived critical streams.  Mature stacks
    // (tquic, quic-zig) surface a FIN on any of these streams as
    // H3_CLOSED_CRITICAL_STREAM instead of silently accepting a truncated
    // control/QPACK context.
    if (stream.fin) return error.ClosedCriticalStream;
}
