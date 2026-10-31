//! Complete requests share the streaming send cursor and paced DATA writer.
const std = @import("std");
const http3 = @import("../../mod.zig");
const control_send = @import("../control/send.zig");
const streaming_head = @import("../send/streaming_head.zig");
const field_section = @import("../send/field_section.zig");
const ReceiveTimeoutError = @import("../error.zig").ReceiveTimeoutError;

pub fn send(client: anytype, request: http3.Request, deadline: ?std.Io.Clock.Timestamp, hooks: anytype) ReceiveTimeoutError!u62 {
    if (client.dispatcher_bound) return error.InvalidDispatcherState;
    if (client.callback_reader_active) return error.ConcurrentRead;
    const id = client.next_stream_id;
    const next = std.math.add(u62, id, 4) catch return error.StreamCreationError;
    if (!client.control.acceptsRequestStream(id)) return error.GoAwayReceived;
    const existing = client.request_lifecycle.contains(id);
    const extended = hasProtocol(request.headers);
    if (!existing) {
        try client.request_lifecycle.open(id, request.method, extended);
    } else if (!client.request_lifecycle.matchesRequest(id, request.method, extended) or !hooks.retryable(client, id, next)) {
        return error.UnexpectedStream;
    }
    var reserved = existing;
    const checkpoint = client.qpack_encode.checkpoint();
    var head_committed: usize = 0;
    errdefer {
        if (head_committed == 0) client.qpack_encode.rollbackAfter(checkpoint);
        if (reserved and head_committed != 0) {
            // The convenience API cannot return a partial-upload owner. Retire
            // only this stream; never replay bytes at its committed offset.
            client.next_stream_id = next;
            client.abandonExtendedConnectOnce(id);
        } else if (reserved and hooks.retryable(client, id, next)) {
            client.next_stream_id = id;
        } else {
            if (reserved and client.established.connection.nextLocalBidirectionalStreamId() == next) client.next_stream_id = next;
            _ = client.request_lifecycle.finish(id) catch false;
            _ = client.outbound_bodies.finish(id);
        }
    }
    client.stream_send_scratch.reset();
    try request.writeCompleteHeadDynamic(
        &client.stream_send_scratch.encoded,
        client.allocator,
        client.control.settings.peer,
        id,
        &client.qpack_encode,
    );
    while (true) {
        sendSettings(client, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                if (client.established.connection.closed()) return err;
                try hooks.receive(client, id, deadline);
                continue;
            },
            else => return err,
        };
        break;
    }
    if (!existing) {
        const transport_id = try hooks.open(client, deadline);
        std.debug.assert(transport_id == id);
        reserved = true;
    }
    const trailers_pending = request.trailers.len != 0;
    const body_allowed = !std.mem.eql(u8, request.method, "CONNECT") or extended;
    while (true) {
        streaming_head.sendProgress(
            &client.established.connection,
            &client.stream_send_scratch,
            &client.critical_stream_send_scratch,
            id,
            request.body.len,
            body_allowed,
            trailers_pending,
            client.options,
            &client.qpack_encode,
            &client.qpack_encoder_send,
            &client.qpack_encoder_prefix_sent,
            &client.outbound_bodies,
            &head_committed,
            deadline,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                if (client.established.connection.closed()) return err;
                try hooks.receive(client, id, deadline);
                continue;
            },
            else => return err,
        };
        break;
    }
    client.next_stream_id = next;
    if (request.body.len != 0) {
        if (deadline) |absolute| {
            var progress: http3.runtime.BodyWriteProgress = .{};
            try client.sendRequestBodyPacedWithDeadline(id, request.body, !trailers_pending, &progress, absolute);
        } else {
            try client.sendRequestBodyPaced(id, request.body, !trailers_pending);
        }
    }
    if (trailers_pending) {
        try sendTrailers(client, id, request.trailers, deadline, hooks);
    }
    return id;
}

fn sendTrailers(client: anytype, id: u62, trailers: []const http3.Qpack.HeaderField, deadline: ?std.Io.Clock.Timestamp, hooks: anytype) ReceiveTimeoutError!void {
    const base_offset = (try client.outbound_bodies.prepareTrailers(id)).send.next_offset;
    const checkpoint = client.qpack_encode.checkpoint();
    var committed: usize = 0;
    errdefer if (committed == 0) client.qpack_encode.rollbackAfter(checkpoint);
    client.stream_send_scratch.reset();
    try http3.writeTrailersDynamic(&client.stream_send_scratch.encoded, client.allocator, trailers, client.control.settings.peer, id, &client.qpack_encode);
    while (true) {
        sendTrailerProgress(client, id, base_offset, &committed, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                if (client.established.connection.closed()) return err;
                try hooks.receive(client, id, deadline);
                continue;
            },
            else => return err,
        };
        break;
    }
    _ = client.outbound_bodies.finish(id);
}

fn sendTrailerProgress(client: anytype, id: u62, base_offset: u64, committed: *usize, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
    if (deadline) |absolute| {
        try control_send.sendConnectionQpackEncoderInstructionsWithDeadline(&client.established.connection, &client.critical_stream_send_scratch, &client.qpack_encode, &client.qpack_encoder_send, &client.qpack_encoder_prefix_sent, client.options, absolute);
    } else {
        try control_send.sendConnectionQpackEncoderInstructions(&client.established.connection, &client.critical_stream_send_scratch, &client.qpack_encode, &client.qpack_encoder_send, &client.qpack_encoder_prefix_sent, client.options);
    }
    try field_section.sendProgress(&client.established.connection, id, client.stream_send_scratch.encoded.items, base_offset, true, committed, client.options.max_stream_frame_data, deadline);
}

fn hasProtocol(headers: []const http3.Qpack.HeaderField) bool {
    for (headers) |header| if (std.mem.eql(u8, header.name, ":protocol")) return true;
    return false;
}

fn sendSettings(client: anytype, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
    if (deadline) |absolute| {
        try control_send.sendConnectionSettingsWithDeadline(
            &client.established.connection,
            &client.critical_stream_send_scratch,
            &client.control,
            &client.control_send,
            &client.qpack_encoder_send,
            &client.qpack_encoder_prefix_sent,
            &client.qpack_decoder_send,
            &client.qpack_decoder_prefix_sent,
            client.options,
            2,
            absolute,
        );
    } else {
        try control_send.sendConnectionSettings(
            &client.established.connection,
            &client.critical_stream_send_scratch,
            &client.control,
            &client.control_send,
            &client.qpack_encoder_send,
            &client.qpack_encoder_prefix_sent,
            &client.qpack_decoder_send,
            &client.qpack_decoder_prefix_sent,
            client.options,
            2,
        );
    }
}

test {
    _ = @import("complete_request_tests.zig");
}
