const std = @import("std");
const runtime_error = @import("../../error.zig");
const control_sender = @import("../../control/send.zig");
const connection_error = @import("../../receive/connection_error.zig");

const Error = runtime_error.Error;

const failure = @import("failure.zig");
const data = @import("../../receive/message_data.zig");

pub fn submit(client: anytype, value: failure.Failure) Error!void {
    const identity = client.push_streams.identityForStream(value.stream_id) orelse {
        if (client.push_streams.promiseCompleted(value.push_id)) return;
        return error.UnexpectedStream;
    };
    if (identity.push_id != value.push_id or identity.request_stream_id != value.request_stream_id) return error.UnexpectedStream;
    const cancel_qpack = client.qpack_decode.table.max_capacity != 0;
    if (cancel_qpack) try client.qpack_decode.prepareStreamCancellation();
    try client.established.connection.trySendStopSending(value.stream_id, value.application_error_code);
    _ = try client.established.connection.requestCompletedPeerStreamRelease(value.stream_id);
    if (cancel_qpack) client.qpack_decode.recordStreamCancellationAssumeCapacity(value.stream_id);
    client.qpack_decode.discardPeerUniStream(value.stream_id);
    client.push_streams.failStream(value.stream_id);
    // Decoder feedback has its own retained cursor. A socket failure here
    // cannot replace the parser cause after scoped cancellation completed.
    client.flushResponsePacketFeedbackOnce() catch {};
}

pub fn progress(client: anytype, target_push_id: ?u64, output: ?*?failure.Failure) Error!void {
    const pending = &client.pending_push_failures;
    if (pending.count() == 0) return;
    const connection = &client.established.connection;
    if (connection.closing() or connection.draining() or connection.closed()) {
        pending.clear();
        return error.ConnectionClosed;
    }
    // A peer RESET can remove the reader before our STOP_SENDING retry. Keep
    // the parser cause observable once and retire the promise without sending
    // on a transport stream that has already completed.
    for (pending.items.items) |value| {
        if (target_push_id) |id| if (value.push_id != id) continue;
        if (client.push_streams.containsStream(value.stream_id)) continue;
        client.push_streams.retireFailedPromise(value.push_id);
        _ = pending.take(value.stream_id);
        if (output) |sink| sink.* = value;
        return value.err;
    }
    const target: ?u62 = if (target_push_id) |id| client.push_streams.streamIdForPush(id) orelse return else null;
    if (output) |sink| {
        if (pending.take(target)) |value| {
            sink.* = value;
            return value.err;
        }
    } else if (try pending.poll(client, target, submit)) |value| return value.err;
}

pub fn retain(client: anytype, stream_id: ?u62, err: anyerror, output: ?*?failure.Failure) Error!void {
    if (failure.Failure.fromError(&client.push_streams, stream_id, err)) |value| {
        client.push_streams.suspendFailedStream(value.stream_id);
        if (output) |sink| {
            sink.* = value;
            return;
        }
        client.pending_push_failures.append(value);
        try progress(client, value.push_id, null);
        return;
    }
    try connection_error.closeConnection(&client.established.connection, err);
}

/// Public cancellation can supersede a retained parser rejection after its
/// CANCEL_PUSH commits. Its separate STOP_SENDING queue then owns completion.
pub fn discard(client: anytype, push_id: u64) void {
    for (client.pending_push_failures.items.items) |value| {
        if (value.push_id != push_id) continue;
        _ = client.pending_push_failures.take(value.stream_id);
        return;
    }
}

pub fn access(client: anytype, push_id: u64, out: []u8, comptime operation: data.Operation, comptime once: bool) Error!?usize {
    try progress(client, push_id, null);
    const entry = client.push_streams.findByPushId(push_id) orelse return error.UnexpectedStream;
    const reader = if (entry.reader) |*value| value else return error.UnexpectedStream;
    if (client.push_streams.failurePending(reader.streamId())) return null;
    if (once) {
        data.releaseCapacityOnce(&client.established.connection, reader) catch |err| switch (err) {
            error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
            else => return err,
        };
    } else try data.releaseCapacity(&client.established.connection, reader);
    return switch (operation) {
        .read => reader.readData(out),
        .skip => reader.skipData(),
        .available => reader.availableDataBytes(),
    } catch |err| {
        if (runtime_error.dataReadPeerError(err)) {
            if (runtime_error.messageStreamErrorCode(err) != null) try client.pending_push_failures.reserve(client.allocator);
            try retain(client, reader.streamId(), err, null);
        }
        return err;
    };
}

/// Match the stateful policy on the preconfigured-key runtime. Preserve peer
/// provenance before failStream swap-removes and frees the active reader.
pub fn protected(
    client: anytype,
    stream_id: ?u62,
    from: ?std.Io.net.IpAddress,
    err: anyerror,
) void {
    const peer = from orelse client.quic_client.peer;
    if (stream_id) |id| {
        if (runtime_error.messageStreamErrorCode(err)) |code| {
            if (client.qpack_decode.table.max_capacity != 0) {
                client.qpack_decode.recordStreamCancellation(id) catch {};
            }
            client.protected_send.sendFrames(
                &client.quic_client.endpoint,
                peer,
                client.config.send_keys,
                client.config.peer_connection_id,
                &client.next_packet_number,
                &.{.{ .stop_sending = .{ .stream_id = id, .application_error_code = code } }},
                client.config.max_frames_per_packet,
            ) catch {};
            client.qpack_decode.discardPeerUniStream(id);
            client.push_streams.failStream(id);
            control_sender.sendProtectedQpackFeedback(
                &client.quic_client.endpoint,
                peer,
                client.config,
                &client.qpack_decode,
                &client.qpack_decoder_send,
                &client.qpack_decoder_prefix_sent,
                &client.next_packet_number,
                &client.protected_send,
            ) catch {};
            return;
        }
    }
    connection_error.sendProtectedClose(
        &client.quic_client.endpoint,
        peer,
        client.config,
        &client.next_packet_number,
        &client.protected_send,
        err,
    );
}
