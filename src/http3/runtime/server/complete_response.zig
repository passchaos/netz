//! Complete final and informational responses share flow-aware field sections.
const std = @import("std");
const http3 = @import("../../mod.zig");
const response_headers = @import("response.zig");
const control_send = @import("../control/send.zig");
const streaming_head = @import("../send/streaming_head.zig");
const trailers_send = @import("../send/complete_trailers.zig");
const ReceiveTimeoutError = @import("../error.zig").ReceiveTimeoutError;

pub const Cancellation = struct {
    stream_id: u62,
    needs_cancel: bool = true,
};

pub fn send(server: anytype, id: u62, informational: []const http3.InformationalResponse, response: http3.Response, deadline: ?std.Io.Clock.Timestamp, hooks: anytype) ReceiveTimeoutError!void {
    if (server.dispatcher_bound) return error.InvalidDispatcherState;
    hooks.flush(server);
    if (!server.request_lifecycle.contains(id)) return error.UnexpectedStream;
    const allocator = server.established.connection.endpoint.allocator;
    var header_storage: [response_headers.header_stack_capacity]http3.Qpack.HeaderField = undefined;
    var prepared = try response_headers.prepare(allocator, response, response_headers.automaticDate(server.options.auto_date_header, server.established.connection.endpoint.io, response), &header_storage);
    defer prepared.deinit(allocator);
    const checkpoint = server.qpack_encode.checkpoint();
    var committed: usize = 0;
    errdefer {
        if (committed == 0) server.qpack_encode.rollbackAfter(checkpoint) else hooks.abandon(server, id);
    }
    server.stream_send_scratch.reset();
    for (informational) |info| try info.writeDynamic(&server.stream_send_scratch.encoded, allocator, server.control.settings.peer, id, &server.qpack_encode);
    try prepared.value.writeCompleteHeadDynamic(&server.stream_send_scratch.encoded, allocator, server.control.settings.peer, id, &server.qpack_encode);
    // Reserve fallback cancellation storage before any response byte becomes
    // visible. A later network/pacing refusal cannot force allocation in unwind.
    try server.pending_response_cancellations.ensureUnusedCapacity(allocator, 1);
    while (true) {
        _ = try hooks.before(server, id, deadline);
        sendSettings(server, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                if (server.established.connection.closed()) return err;
                try hooks.receive(server, id, deadline);
                continue;
            },
            else => return err,
        };
        break;
    }
    const body_allowed = !prepared.value.suppressesBody();
    const trailers_pending = body_allowed and response.trailers.len != 0;
    while (true) {
        _ = try hooks.before(server, id, deadline);
        streaming_head.sendProgress(&server.established.connection, &server.stream_send_scratch, &server.critical_stream_send_scratch, id, if (body_allowed) response.body.len else 0, body_allowed, trailers_pending, server.options, &server.qpack_encode, &server.qpack_encoder_send, &server.qpack_encoder_prefix_sent, &server.outbound_bodies, &committed, deadline) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                if (server.established.connection.closed()) return err;
                try hooks.receive(server, id, deadline);
                continue;
            },
            else => return err,
        };
        break;
    }
    if (body_allowed and response.body.len != 0) try hooks.body(server, id, response.body, !trailers_pending, deadline);
    if (trailers_pending) try trailers_send.send(server, id, response.trailers, deadline, hooks);
    hooks.finish(server, id);
}

fn sendSettings(server: anytype, deadline: ?std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
    if (deadline) |absolute| {
        try control_send.sendConnectionSettingsWithDeadline(&server.established.connection, &server.critical_stream_send_scratch, &server.control, &server.control_send, &server.qpack_encoder_send, &server.qpack_encoder_prefix_sent, &server.qpack_decoder_send, &server.qpack_decoder_prefix_sent, server.options, 3, absolute);
    } else {
        try control_send.sendConnectionSettings(&server.established.connection, &server.critical_stream_send_scratch, &server.control, &server.control_send, &server.qpack_encoder_send, &server.qpack_encoder_prefix_sent, &server.qpack_decoder_send, &server.qpack_decoder_prefix_sent, server.options, 3);
    }
}
