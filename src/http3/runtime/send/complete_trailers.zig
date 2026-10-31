//! Complete-message trailing HEADERS share an exact flow-aware cursor.
const std = @import("std");
const http3 = @import("../../mod.zig");
const control_send = @import("../control/send.zig");
const field_section = @import("field_section.zig");
const ReceiveTimeoutError = @import("../error.zig").ReceiveTimeoutError;

pub fn send(client: anytype, id: u62, trailers: []const http3.Qpack.HeaderField, deadline: ?std.Io.Clock.Timestamp, hooks: anytype) ReceiveTimeoutError!void {
    const allocator = if (@hasField(@TypeOf(client.*), "allocator")) client.allocator else client.established.connection.endpoint.allocator;
    const base_offset = (try client.outbound_bodies.prepareTrailers(id)).send.next_offset;
    const checkpoint = client.qpack_encode.checkpoint();
    var committed: usize = 0;
    errdefer if (committed == 0) client.qpack_encode.rollbackAfter(checkpoint);
    client.stream_send_scratch.reset();
    try http3.writeTrailersDynamic(&client.stream_send_scratch.encoded, allocator, trailers, client.control.settings.peer, id, &client.qpack_encode);
    while (true) {
        if (@hasField(@TypeOf(hooks), "before")) _ = try hooks.before(client, id, deadline);
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
    try field_section.sendProgress(&client.established.connection, id, client.stream_send_scratch.encoded.items, base_offset, true, committed, client.options.max_stream_frame_data, client.options.max_frames_per_packet, deadline);
}
