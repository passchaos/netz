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
const webtransport_error = @import("../../../../internal/webtransport_error.zig");

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
    peer_promised_push_ids: control_receive.PromisedPushIds,
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
            const preserve_for_detached =
                hasDetachedAssociation(detached_stream_id, detached_streams) and
                shouldPreserveDetachedUniReset(
                    request_id_validator,
                    qpack_decode,
                    frame.reset_stream.stream_id,
                );
            qpack_decode.discardPeerUniStream(
                frame.reset_stream.stream_id,
            );
            if (!preserve_for_detached) {
                _ = try request_id_validator.requestCompletedPeerStreamRelease(
                    @intCast(frame.reset_stream.stream_id),
                );
            }
            continue;
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
                !request_lifecycle.contains(stream_id) and
                hasDetachedAssociation(detached_stream_id, detached_streams) and
                try detachedBidiResetBelongsToWebTransport(
                    request_id_validator,
                    stream_id,
                    frame.reset_stream.application_error_code,
                    frame.reset_stream.final_size,
                ))
            {
                // The WebTransport poller owns the terminal event once an
                // unclaimed client bidi stream is (or may still become) an
                // RFC 9297 association.
                continue;
            }
            if (try applyServerRequestReset(
                from,
                frame.reset_stream,
                control,
                qpack_decode,
                request_streams,
                streaming_requests,
                request_lifecycle,
                request_id_validator,
            )) |reset| {
                if (first_reset == null) first_reset = reset;
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
        if (hasDetachedAssociation(detached_stream_id, detached_streams) and
            shouldPreserveDetachedUniStream(
                request_id_validator,
                frame.stream,
            ))
        {
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
            const consumed_end = std.math.add(
                u64,
                classified.frame.offset,
                std.math.cast(
                    u64,
                    classified.frame.data.len,
                ) orelse return error.InvalidStreamRange,
            ) catch return error.InvalidStreamRange;
            try request_id_validator.commitReceivedThrough(
                classified.frame.stream_id,
                consumed_end,
            );
            if (classified.stream_type == .unknown and classified.frame.fin) {
                _ = try request_id_validator.requestCompletedPeerStreamRelease(
                    @intCast(classified.frame.stream_id),
                );
            }
            qpack_decode.commitPeerUniFrame(classified.frame);
            continue;
        }
        const stream_id: u62 = @intCast(frame.stream.stream_id);
        const tracked = request_streams.contains(stream_id) or
            if (streaming_requests) |streaming|
                streaming.contains(stream_id)
            else
                false;
        var request_frame = frame.stream;
        var replayed = false;
        if (hasDetachedAssociation(detached_stream_id, detached_streams) and
            !tracked and
            !request_lifecycle.contains(stream_id))
        {
            switch (try classifyDetachedBidiStream(
                request_id_validator,
                frame.stream,
            )) {
                .ordinary => {},
                .preserve => continue,
                .replay => |reassembled| {
                    request_frame = reassembled;
                    replayed = true;
                },
            }
        }
        if ((try messageStreamDisposition(
            request_frame.stream_id,
        )) == .ignore) continue;
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
            try streaming.insertRequest(request_streams, from, request_frame);
        } else {
            try request_streams.insert(from, request_frame);
            const copied_through = request_streams.contiguousEnd(
                stream_id,
            ) orelse return error.UnexpectedStream;
            try request_id_validator.commitReceivedThrough(
                stream_id,
                copied_through,
            );
        }
        if (replayed) {
            const connection = switch (request_id_validator) {
                .connection => |value| value,
                .static_limit => unreachable,
            };
            const stats = connection.recvStreamStats(stream_id) orelse
                return error.UnexpectedStream;
            if (stats.reset) |reset| {
                if (try applyServerRequestReset(
                    from,
                    .{
                        .stream_id = stream_id,
                        .application_error_code = reset.application_error_code,
                        .final_size = reset.final_size,
                    },
                    control,
                    qpack_decode,
                    request_streams,
                    streaming_requests,
                    request_lifecycle,
                    request_id_validator,
                )) |routed_reset| {
                    if (first_reset == null) first_reset = routed_reset;
                }
            }
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

fn applyServerRequestReset(
    from: net.IpAddress,
    reset: quic.ResetStreamFrame,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    request_streams: *RequestStreamSet,
    streaming_requests: ?*StreamingRequestSet,
    request_lifecycle: *ServerRequestLifecycle,
    request_id_validator: ServerRequestIdValidator,
) Error!?RequestStreamReset {
    const stream_id: u62 = @intCast(reset.stream_id);
    const replaces_stream = request_streams.contains(stream_id) or
        if (streaming_requests) |streaming|
            streaming.contains(stream_id)
        else
            false;
    if (!replaces_stream and
        request_id_validator.requestReceptionStopped(stream_id))
    {
        _ = try request_id_validator.requestCompletedPeerStreamRelease(stream_id);
        return null;
    }
    var cancel_qpack = try request_streams.requiresQpackCancellation(
        stream_id,
        qpack_decode.table,
    );
    if (streaming_requests) |streaming| {
        cancel_qpack = cancel_qpack or
            try streaming.hasUnacknowledgedDynamicSection(
                stream_id,
                qpack_decode.table,
            );
        // Reserve before mutating QPACK or destroying the reader. This makes
        // reset routing transactional under allocator failure.
        const new_reset = try streaming.prepareReset(
            from,
            stream_id,
            reset.application_error_code,
            request_streams.count(),
            replaces_stream,
        );
        if (!new_reset) return null;
        // Once the event queue has been reserved, all remaining operations
        // are allocation-free and cannot strand one half of the state.
        if (cancel_qpack) {
            try qpack_decode.recordStreamCancellation(stream_id);
            cancel_qpack = false;
        }
        streaming.recordPreparedNewResetAssumeCapacity(
            from,
            stream_id,
            reset.application_error_code,
        );
    }
    if (cancel_qpack) {
        try qpack_decode.recordStreamCancellation(stream_id);
    }
    request_streams.remove(stream_id);
    finishServerRequest(control, request_lifecycle, stream_id);
    _ = try request_id_validator.requestCompletedPeerStreamRelease(stream_id);
    return .{
        .from = from,
        .stream_id = stream_id,
        .application_error_code = reset.application_error_code,
    };
}

fn hasDetachedAssociation(
    detached_stream_id: ?u62,
    detached_streams: ?*connect_datagram.Registry,
) bool {
    return detached_stream_id != null or
        if (detached_streams) |detached|
            detached.associationCount() != 0
        else
            false;
}

fn shouldPreserveDetachedUniReset(
    request_id_validator: ServerRequestIdValidator,
    qpack_decode: *QpackDecodeState,
    stream_id: u64,
) bool {
    if (qpack_decode.classifiedPeerUniStreamType(stream_id) != null)
        return false;
    const connection = switch (request_id_validator) {
        .connection => |value| value,
        .static_limit => return true,
    };
    const stats = connection.recvStreamStats(stream_id) orelse return false;
    if (stats.bytes_read != 0) return true;
    const available = connection.retainedReceivedStream(stream_id) orelse
        return false;
    const prefix = quic.varint.decodeSlice(available) catch return false;
    return @as(http3.StreamType, @enumFromInt(prefix.value)) ==
        .webtransport_unidirectional;
}

fn shouldPreserveDetachedUniStream(
    request_id_validator: ServerRequestIdValidator,
    stream: quic.StreamFrame,
) bool {
    if ((stream.stream_id & 0x02) == 0) return false;
    const connection = switch (request_id_validator) {
        .connection => |value| value,
        .static_limit => return false,
    };
    const available = connection.availableReceivedStream(
        stream.stream_id,
    ) orelse return false;
    const prefix = quic.varint.decodeSlice(available) catch return false;
    return @as(http3.StreamType, @enumFromInt(prefix.value)) ==
        .webtransport_unidirectional;
}

const DetachedBidiRoute = union(enum) {
    ordinary,
    preserve,
    replay: quic.StreamFrame,
};

fn classifyDetachedBidiStream(
    request_id_validator: ServerRequestIdValidator,
    frame: quic.StreamFrame,
) Error!DetachedBidiRoute {
    if ((frame.stream_id & 0x03) != 0) return .ordinary;
    const connection = switch (request_id_validator) {
        .connection => |value| value,
        .static_limit => return .ordinary,
    };
    const stats = connection.recvStreamStats(frame.stream_id) orelse
        return .ordinary;
    if (stats.bytes_read != 0) return .preserve;
    if (try detachedBidiPrefixMayBelongToWebTransport(
        request_id_validator,
        @intCast(frame.stream_id),
    )) return .preserve;
    const available = connection.retainedReceivedStream(frame.stream_id) orelse
        return .ordinary;
    const available_len = std.math.cast(u64, available.len) orelse
        return error.InvalidStreamRange;
    const available_end = std.math.add(
        u64,
        stats.bytes_read,
        available_len,
    ) catch return error.InvalidStreamRange;
    return .{ .replay = .{
        .stream_id = frame.stream_id,
        .offset = stats.bytes_read,
        .data = available,
        .fin = stats.final_size != null and
            stats.final_size.? == available_end,
    } };
}

fn detachedBidiPrefixMayBelongToWebTransport(
    request_id_validator: ServerRequestIdValidator,
    stream_id: u62,
) Error!bool {
    const connection = switch (request_id_validator) {
        .connection => |value| value,
        .static_limit => return false,
    };
    const available = connection.retainedReceivedStream(stream_id) orelse
        return false;
    const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
        // Neither HTTP/3 nor WebTransport owns an ambiguous prefix yet. Keep
        // it solely in QUIC storage so a later offset-zero fragment can make
        // the classification without duplicating or consuming bytes.
        error.BufferTooShort => return true,
        else => return err,
    };
    return prefix.value == http3.FrameType.webtransport_stream;
}

fn detachedBidiResetBelongsToWebTransport(
    request_id_validator: ServerRequestIdValidator,
    stream_id: u62,
    application_error_code: u64,
    final_size: u64,
) Error!bool {
    const connection = switch (request_id_validator) {
        .connection => |value| value,
        .static_limit => return false,
    };
    const mapped_error = webtransport_error.isStreamError(
        application_error_code,
    );
    const stats = connection.recvStreamStats(stream_id) orelse
        return final_size != 0 or mapped_error;
    if (stats.bytes_read != 0) return true;
    const available = connection.retainedReceivedStream(stream_id) orelse
        return final_size > stats.bytes_read or mapped_error;
    const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
        error.BufferTooShort => {
            const available_len = std.math.cast(u64, available.len) orelse
                return error.InvalidStreamRange;
            const available_end = std.math.add(
                u64,
                stats.bytes_read,
                available_len,
            ) catch return error.InvalidStreamRange;
            return final_size > available_end or mapped_error;
        },
        else => return err,
    };
    return prefix.value == http3.FrameType.webtransport_stream;
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
