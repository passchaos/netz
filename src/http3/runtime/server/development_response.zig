//! Deadline-aware development response mutation, serialized by the Server owner.
const std = @import("std");
const http3 = @import("../../mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const server_response = @import("response.zig");
const development_send = @import("../development/send.zig");
const development_settings = @import("../../runtime.zig").development_settings;
const net = std.Io.net;

fn lock(io: std.Io, mutex: *std.Io.Mutex, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(io, until);
        if (!mutex.tryLock()) return error.ConcurrencyUnavailable;
        _ = deadline_policy.usableAwake(io, until) catch |err| {
            mutex.unlock(io);
            return err;
        };
    } else mutex.lockUncancelable(io);
}

pub fn start(self: anytype, to: net.IpAddress, stream_id: u62, response: http3.Response, body_length: ?usize, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
    try lock(self.quic_server.endpoint.io, &self.peer_state_mutex, deadline);
    defer self.peer_state_mutex.unlock(
        self.quic_server.endpoint.io,
    );
    const peer = self.streaming_peers.find(to) orelse
        return error.UnexpectedStream;
    const response_context = try peer.prepareResponseHead(
        stream_id,
        self.streaming_mode,
    );
    errdefer peer.abandonEncodedResponse(stream_id);
    try lock(self.quic_server.endpoint.io, &self.response_send_mutex, deadline);
    defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
    var response_headers_stack: [server_response.header_stack_capacity]http3.Qpack.HeaderField =
        undefined;
    var prepared = try server_response.prepare(
        self.quic_server.endpoint.allocator,
        response,
        server_response.automaticDate(
            self.limits.auto_date_header,
            self.quic_server.endpoint.io,
            response,
        ),
        &response_headers_stack,
    );
    defer prepared.deinit(self.quic_server.endpoint.allocator);
    const streaming = try prepared.value.writeStreamingHeadDynamic(
        &response_context.scratch.encoded,
        self.quic_server.endpoint.allocator,
        development_settings,
        stream_id,
        body_length,
        response_context.qpack_encode,
    );
    // Successful Extended CONNECT keeps HTTP/3 DATA enabled even though
    // it intentionally has no Content-Length and remains open until the
    // adapted protocol closes it.
    const keep_extended_connect_open = prepared.value.extended_connect and
        prepared.value.status >= 200 and prepared.value.status < 300;
    const body_allowed = streaming.body_allowed or
        keep_extended_connect_open;
    const expected_length = if (keep_extended_connect_open)
        null
    else
        streaming.expected_length;
    const response_prefix_offset = peer.responsePrefixOffset(stream_id);
    var send_attempted = false;
    development_send.streamingHeadAtOffsetUntil(
        &self.quic_server.endpoint,
        to,
        response_context.scratch,
        stream_id,
        response_prefix_offset,
        expected_length,
        body_allowed,
        self.limits.max_stream_frame_data,
        response_context.outbound_bodies,
        &send_attempted,
        deadline,
    ) catch |err| {
        if (send_attempted) {
            peer.markSendFailed();
        } else {
            peer.discardResponseBody(stream_id);
        }
        return err;
    };
    peer.commitResponseHead(stream_id, body_allowed, expected_length);
}

pub fn trailers(self: anytype, to: net.IpAddress, stream_id: u62, fields: []const http3.Qpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
    try lock(self.quic_server.endpoint.io, &self.peer_state_mutex, deadline);
    defer self.peer_state_mutex.unlock(
        self.quic_server.endpoint.io,
    );
    const peer = self.streaming_peers.find(to) orelse
        return error.UnexpectedStream;
    const bodies = try peer.prepareResponseBody(stream_id);
    const body_entry = try bodies.prepareTrailers(stream_id);
    const response_context = peer.responseContext();
    const previous_offset = response_context.response_send_offsets.get(stream_id);
    var send_attempted = false;
    try response_context.response_send_offsets.put(
        self.quic_server.endpoint.allocator,
        stream_id,
        body_entry.send.next_offset,
    );
    errdefer if (!send_attempted) {
        if (previous_offset) |offset| {
            response_context.response_send_offsets.getPtr(stream_id).?.* = offset;
        } else _ = response_context.response_send_offsets.remove(stream_id);
    };
    try lock(self.quic_server.endpoint.io, &self.response_send_mutex, deadline);
    defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
    response_context.scratch.encoded.clearRetainingCapacity();
    try http3.writeTrailersDynamic(
        &response_context.scratch.encoded,
        self.quic_server.endpoint.allocator,
        fields,
        development_settings,
        stream_id,
        response_context.qpack_encode,
    );
    development_send.responsePrefixUntil(
        &self.quic_server.endpoint,
        to,
        response_context.scratch,
        stream_id,
        self.limits.max_stream_frame_data,
        response_context.response_send_offsets,
        true,
        deadline,
        &send_attempted,
    ) catch |err| {
        if (deadline == null or send_attempted) peer.markSendFailed();
        return err;
    };
    peer.commitResponseTrailers(stream_id);
}

pub fn cancel(self: anytype, to: net.IpAddress, stream_id: u62, code: u64, deadline: std.Io.Clock.Timestamp, comptime retire: anytype) anyerror!void {
    const io = self.quic_server.endpoint.io;
    try lock(io, &self.peer_state_mutex, deadline);
    defer self.peer_state_mutex.unlock(io);
    const peer = self.streaming_peers.find(to) orelse return error.UnexpectedStream;
    const prepared = try peer.prepareCancellation(stream_id);
    var attempted = false;
    development_send.requestCancellationUntil(&self.quic_server.endpoint, to, stream_id, code, prepared.local_final_size, prepared.send_reset, deadline, &attempted) catch |err| {
        if (attempted) {
            _ = peer.cancelRequest(stream_id) catch {};
            retire(self, to);
        }
        return err;
    };
    _ = try peer.cancelRequest(stream_id);
    retire(self, to);
}
