const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const request_buffer = @import("request_buffer.zig");
const control_receive = @import("../control/receive.zig");
const runtime_error = @import("../error.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const ReceiveTimeoutError = runtime_error.ReceiveTimeoutError;

pub fn streamBytes(
    endpoint: *quic.runtime.Endpoint,
    expected_peer: ?net.IpAddress,
    expected_stream_id: ?u62,
    max_stream_buffer: usize,
) Error!request_buffer.AssembledStream {
    return streamBytesUntil(
        endpoint,
        expected_peer,
        expected_stream_id,
        max_stream_buffer,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn streamBytesUntil(
    endpoint: *quic.runtime.Endpoint,
    expected_peer: ?net.IpAddress,
    expected_stream_id: ?u62,
    max_stream_buffer: usize,
    deadline: ?std.Io.Clock.Timestamp,
) ReceiveTimeoutError!request_buffer.AssembledStream {
    var receive: ?quic.stream_state.RecvState = null;
    defer if (receive) |*state| state.deinit();
    var datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty;
    errdefer {
        for (datagrams.items) |*datagram| datagram.deinit(endpoint.allocator);
        datagrams.deinit(endpoint.allocator);
    }
    var from: ?net.IpAddress = null;
    var stream_id: ?u62 = expected_stream_id;

    while (true) {
        var datagram = if (deadline) |absolute|
            try endpoint.receiveWithDeadline(absolute)
        else
            try endpoint.receive();
        var datagram_owned = true;
        errdefer if (datagram_owned) datagram.deinit(endpoint.allocator);
        if (expected_peer) |peer| {
            if (!datagram.from.eql(&peer)) {
                datagram.deinit(endpoint.allocator);
                datagram_owned = false;
                continue;
            }
        }

        var consumed = false;
        for (datagram.frames) |frame| {
            if (frame != .stream) continue;
            switch (try control_receive.messageStreamDisposition(
                frame.stream.stream_id,
            )) {
                .ignore => continue,
                .request_response => {},
            }
            const incoming_id: u62 = @intCast(frame.stream.stream_id);
            if (stream_id) |id| {
                if (incoming_id != id) {
                    if (expected_stream_id != null) {
                        return error.UnexpectedStream;
                    }
                    continue;
                }
            } else {
                stream_id = incoming_id;
            }
            if (from) |source| {
                if (!datagram.from.eql(&source)) continue;
            } else {
                from = datagram.from;
            }
            if (receive == null) {
                receive = quic.stream_state.RecvState.init(
                    endpoint.allocator,
                    incoming_id,
                    max_stream_buffer,
                );
            }
            const state = &receive.?;
            try state.insert(frame.stream);
            consumed = true;
            if (state.final_size != null and
                state.contiguous_end >= state.final_size.?)
            {
                // Completion owns the contiguous buffer already assembled by
                // RecvState. Move it into the result instead of cloning the
                // entire HTTP/3 message once more.
                const bytes = try state.takeCompleteBuffer();
                errdefer endpoint.allocator.free(bytes);
                try datagrams.append(endpoint.allocator, datagram);
                datagram_owned = false;
                return .{
                    .from = from.?,
                    .stream_id = stream_id.?,
                    .bytes = bytes,
                    .datagrams = try datagrams.toOwnedSlice(endpoint.allocator),
                };
            }
        }

        if (consumed) {
            try datagrams.append(endpoint.allocator, datagram);
            datagram_owned = false;
        } else {
            datagram.deinit(endpoint.allocator);
            datagram_owned = false;
        }
    }
}
