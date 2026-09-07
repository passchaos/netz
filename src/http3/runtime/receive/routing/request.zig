const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const runtime_error = @import("../../error.zig");
const connect_datagram = @import("../../datagram.zig");
const control_receive = @import("../../control/receive.zig");
const qpack_state = @import("../../qpack/state.zig");
const buffered_request = @import("../../stream/buffered/request.zig");
const stream_lifecycle = @import("../../stream/lifecycle.zig");
const streaming_set = @import("../../stream/set.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const RequestStreamSet = buffered_request.Set;
const ServerRequestLifecycle = stream_lifecycle.Server;
const StreamingRequestSet = streaming_set.Set;
const ServerRequestIdValidator = control_receive.ServerRequestIdValidator;
const rejectCriticalStreamClosureFrame =
    control_receive.rejectCriticalStreamClosureFrame;
const messageStreamDisposition = control_receive.messageStreamDisposition;
const applyControlStreamFrameForRoleWithPushes =
    control_receive.applyControlStreamFrameForRoleWithPushes;
const configureQpackEncoderFromPeerSettings =
    control_receive.configureQpackEncoderFromPeerSettings;
const rejectByLocalGoAway = control_receive.rejectByLocalGoAway;
pub fn serverRequestReceived(
    control: *http3.ControlState,
    lifecycle: *ServerRequestLifecycle,
    stream_id: u62,
    initial_priority: http3.Priority,
) Error!void {
    const priority = if (control.requestPriorityUpdate(stream_id)) |update|
        update.priority()
    else
        initial_priority;
    try lifecycle.markReceived(
        stream_id,
        priority,
    );
    // Admission consumes only this stream's pre-request hint. A higher request
    // can arrive while a lower one remains active, so receipt alone must not
    // advance the terminal watermark.
    control.removeRequestPriority(lifecycle.memoryAllocator(), stream_id);
}

pub fn prepareServerRequestReceived(
    lifecycle: *ServerRequestLifecycle,
) Error!void {
    try lifecycle.prepareMarkReceived();
}

pub fn serverRequestReceivedAssumeCapacity(
    control: *http3.ControlState,
    lifecycle: *ServerRequestLifecycle,
    stream_id: u62,
    initial_priority: http3.Priority,
) void {
    const priority = if (control.requestPriorityUpdate(stream_id)) |update|
        update.priority()
    else
        initial_priority;
    lifecycle.markReceivedAssumeCapacity(stream_id, priority);
    control.removeRequestPriority(lifecycle.memoryAllocator(), stream_id);
}

pub fn finishServerRequest(
    control: *http3.ControlState,
    lifecycle: *ServerRequestLifecycle,
    stream_id: u64,
) void {
    lifecycle.markFinished(stream_id);
    control.retireRequestPriority(lifecycle.memoryAllocator(), stream_id);
}

pub fn reconcileServerRequestPriorities(
    control: *http3.ControlState,
    lifecycle: *ServerRequestLifecycle,
) void {
    var index: usize = 0;
    while (index < control.priorityUpdates().len) {
        const update = control.priorityUpdates()[index];
        if (update.frame_type != http3.FrameType.priority_update_request) {
            index += 1;
            continue;
        }
        const stream_id = std.math.cast(
            u62,
            update.payload.prioritized_element_id,
        ) orelse {
            // Role validation rejects this before reconciliation. Keeping the
            // loop total makes this helper safe to call in test scaffolding.
            index += 1;
            continue;
        };
        if (lifecycle.updatePriority(stream_id, update.priority())) {
            control.removeRequestPriority(lifecycle.memoryAllocator(), stream_id);
            continue;
        }
        index += 1;
    }
    control.discardRetiredPriorityUpdates(lifecycle.memoryAllocator());
}

pub const RequestStreamReset = struct {
    from: net.IpAddress,
    stream_id: u62,
    application_error_code: u64,
};

pub fn requestResetError(application_error_code: u64) Error {
    return if (application_error_code ==
        http3.ApplicationErrorCode.request_rejected)
        error.RequestRejected
    else
        error.RequestCancelled;
}

/// Route one packet through the shared server-side HTTP/3 stream state.
///
/// Aggregate and incremental consumers intentionally share this function:
/// control/QPACK classification, GOAWAY rejection, peer-address validation,
/// concurrency accounting, and reset cancellation must not drift merely
/// because an application chooses a different body-consumption API.
pub fn applyServerRequestPacketFrames(
    from: net.IpAddress,
    frames: []const quic.Frame,
    allocator: std.mem.Allocator,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    max_blocked_streams: u64,
    request_streams: *RequestStreamSet,
    streaming_requests: ?*StreamingRequestSet,
    request_lifecycle: *ServerRequestLifecycle,
    request_id_validator: ServerRequestIdValidator,
    peer_promised_push_ids: []const u64,
    detached_stream_id: ?u62,
    detached_streams: ?*connect_datagram.Registry,
) Error!?RequestStreamReset {
    var first_reset: ?RequestStreamReset = null;
    for (frames) |frame| {
        try rejectCriticalStreamClosureFrame(control.*, frame, .server);
        const maybe_stream_id: ?u62 = switch (frame) {
            .stream => |stream| @intCast(stream.stream_id),
            .reset_stream => |reset| @intCast(reset.stream_id),
            else => null,
        };
        if (maybe_stream_id) |stream_id| {
            if (request_id_validator.peerStreamClosed(stream_id)) continue;
        }
        if (frame == .reset_stream and
            (frame.reset_stream.stream_id & 0x02) != 0)
        {
            qpack_decode.discardPeerUniStream(
                frame.reset_stream.stream_id,
            );
        }
        if (frame == .reset_stream and
            (try messageStreamDisposition(
                frame.reset_stream.stream_id,
            )) == .request_response)
        {
            const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
            if (detached_streams) |detached| {
                if (detached.contains(stream_id)) {
                    // Detached associations report their own terminal state.
                    // Do not let reset of CONNECT A abort a receive that is
                    // currently waiting for unrelated request B. Terminal
                    // observation happens after queued DATAGRAMs are routed.
                    continue;
                }
            }
            const replaces_stream =
                request_streams.contains(stream_id) or
                if (streaming_requests) |streaming|
                    streaming.contains(stream_id)
                else
                    false;
            if (!replaces_stream and
                request_id_validator.requestReceptionStopped(stream_id))
            {
                _ = try request_id_validator
                    .requestCompletedPeerStreamRelease(stream_id);
                continue;
            }
            var cancel_qpack = try request_streams
                .requiresQpackCancellation(
                stream_id,
                qpack_decode.table,
            );
            if (streaming_requests) |streaming| {
                cancel_qpack = cancel_qpack or
                    try streaming.hasUnacknowledgedDynamicSection(
                        stream_id,
                        qpack_decode.table,
                    );
                // Reserve before mutating QPACK or destroying the reader. This
                // makes reset routing transactional under allocator failure.
                const new_reset = try streaming.prepareReset(
                    from,
                    stream_id,
                    frame.reset_stream.application_error_code,
                    request_streams.count(),
                    replaces_stream,
                );
                if (!new_reset) continue;
                // Reserve decoder feedback before retiring the reader. If the
                // event queue has been reserved, all remaining operations are
                // allocation-free and cannot strand one half of the state.
                if (cancel_qpack) {
                    try qpack_decode.recordStreamCancellation(stream_id);
                    cancel_qpack = false;
                }
                streaming.recordPreparedNewResetAssumeCapacity(
                    from,
                    stream_id,
                    frame.reset_stream.application_error_code,
                );
            }
            if (cancel_qpack) {
                try qpack_decode.recordStreamCancellation(stream_id);
            }
            request_streams.remove(stream_id);
            finishServerRequest(control, request_lifecycle, stream_id);
            _ = try request_id_validator
                .requestCompletedPeerStreamRelease(stream_id);
            if (first_reset == null) {
                first_reset = .{
                    .from = from,
                    .stream_id = stream_id,
                    .application_error_code = frame.reset_stream.application_error_code,
                };
            }
            continue;
        }
        if (frame != .stream) continue;
        if ((detached_stream_id != null and
            frame.stream.stream_id == detached_stream_id.?) or
            (detached_streams != null and
                detached_streams.?.contains(
                    std.math.cast(u62, frame.stream.stream_id) orelse
                        return error.UnexpectedStream,
                )))
        {
            // QUIC has already assembled this frame in the connection receive
            // state. Its protocol adapter consumes it directly.
            qpack_decode.discardPeerUniStream(frame.stream.stream_id);
            continue;
        }
        if ((frame.stream.stream_id & 0x02) != 0) {
            const classified = try qpack_decode.classifyPeerUniFrame(
                frame.stream,
            ) orelse continue;
            switch (classified.stream_type) {
                .control => {
                    if (!try applyControlStreamFrameForRoleWithPushes(
                        control,
                        allocator,
                        classified.frame,
                        .server,
                        peer_promised_push_ids,
                        request_id_validator,
                        request_lifecycle,
                    )) return error.UnexpectedStream;
                    reconcileServerRequestPriorities(
                        control,
                        request_lifecycle,
                    );
                    try configureQpackEncoderFromPeerSettings(
                        control.*,
                        qpack_encode,
                    );
                },
                .qpack_decoder => try qpack_encode.applyDecoderStreamFrame(
                    control,
                    classified.frame,
                ),
                .qpack_encoder => try qpack_decode.applyEncoderStreamFrame(
                    control,
                    classified.frame,
                ),
                .push => return error.StreamCreationError,
                .unknown => {},
            }
            qpack_decode.commitPeerUniFrame(classified.frame);
            continue;
        }
        if ((try messageStreamDisposition(
            frame.stream.stream_id,
        )) == .ignore) continue;
        const stream_id: u62 = @intCast(frame.stream.stream_id);
        const tracked = request_streams.contains(stream_id) or
            if (streaming_requests) |streaming|
                streaming.contains(stream_id)
            else
                false;
        if (!tracked and
            request_id_validator.requestReceptionStopped(stream_id))
        {
            _ = try request_id_validator
                .requestCompletedPeerStreamRelease(stream_id);
            continue;
        }
        if (rejectByLocalGoAway(control.*, .server, stream_id)) {
            return error.RequestRejected;
        }
        if (streaming_requests) |streaming| {
            try streaming.insertRequest(request_streams, from, frame.stream);
        } else {
            try request_streams.insert(from, frame.stream);
        }
    }
    try validateBlockedStreamBudget(
        max_blocked_streams,
        qpack_decode.table,
        request_streams,
        streaming_requests,
    );
    return first_reset;
}

pub fn validateBlockedStreamBudget(
    max_blocked_streams: u64,
    table: http3.Qpack.DynamicTable,
    request_streams: *RequestStreamSet,
    streaming_requests: ?*StreamingRequestSet,
) Error!void {
    const buffered_blocked = try request_streams.blockedStreamCount(
        table,
    );
    if (streaming_requests) |streaming| {
        const total_blocked = std.math.add(
            u64,
            buffered_blocked,
            try streaming.blockedStreamCount(table),
        ) catch return error.QpackDecompressionFailed;
        if (total_blocked > max_blocked_streams) {
            return error.QpackDecompressionFailed;
        }
    } else if (buffered_blocked > max_blocked_streams) {
        return error.QpackDecompressionFailed;
    }
}
