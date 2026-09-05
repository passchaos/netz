const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const datagram_queue = @import("datagram_queue.zig");
const packetizer = @import("../send/packetizer.zig");
const send_scratch = @import("../send/scratch.zig");
const body_sender = @import("../send/body.zig");
const outbound_body = @import("../stream/outbound_body.zig");

const net = std.Io.net;
const Error = runtime_error.Error;

pub fn streamMessage(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try appendStreamMessageFrames(
        &frames,
        endpoint.allocator,
        stream_id,
        bytes,
        max_stream_frame_data,
    );
    try packetizer.sendEndpoint(
        endpoint.allocator,
        endpoint,
        to,
        frames.items,
        1,
        null,
    );
}

pub fn retainDatagramFrames(
    queue: *datagram_queue.Queue,
    packet: quic.runtime.OwnedDatagram,
) Error!void {
    for (packet.frames) |frame| switch (frame) {
        .datagram => {
            var retained = try cloneDatagramFrame(
                queue.allocator,
                packet.from,
                packet.ecn,
                frame,
            );
            errdefer retained.deinit(queue.allocator);
            try queue.push(&retained);
        },
        else => {},
    };
}

pub fn cloneDatagramFrame(
    allocator: std.mem.Allocator,
    from: net.IpAddress,
    ecn: quic.packet_space.EcnCodepoint,
    frame: quic.Frame,
) Error!quic.runtime.OwnedDatagram {
    const frame_len = try frame.wireLen();
    const bytes = try allocator.alloc(u8, frame_len);
    errdefer allocator.free(bytes);
    var encoded = std.ArrayList(u8).initBuffer(bytes);
    try frame.writeAssumeCapacity(&encoded);
    std.debug.assert(encoded.items.len == frame_len);
    const frames = try allocator.alloc(quic.Frame, 1);
    errdefer allocator.free(frames);
    const parsed = try quic.parseFrame(bytes);
    std.debug.assert(parsed.consumed == bytes.len);
    frames[0] = parsed.frame;
    return .{ .from = from, .bytes = bytes, .ecn = ecn, .frames = frames };
}

pub fn streamingHead(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    scratch: *send_scratch.Message,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    max_stream_frame_data: usize,
    bodies: *outbound_body.Set,
    send_attempted: ?*bool,
) Error!void {
    return streamingHeadAtOffset(
        endpoint,
        to,
        scratch,
        stream_id,
        0,
        expected_length,
        body_allowed,
        max_stream_frame_data,
        bodies,
        send_attempted,
    );
}

pub fn streamingHeadAtOffset(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    scratch: *send_scratch.Message,
    stream_id: u62,
    initial_offset: u64,
    expected_length: ?usize,
    body_allowed: bool,
    max_stream_frame_data: usize,
    bodies: *outbound_body.Set,
    send_attempted: ?*bool,
) Error!void {
    const body_open = body_allowed and
        (expected_length == null or expected_length.? != 0);
    try bodies.reserveOpen(stream_id);
    var body_registered = false;
    var packet_send_attempted = false;
    errdefer if (body_registered and !packet_send_attempted) {
        _ = bodies.finish(stream_id);
    };

    var send = quic.stream_state.SendState.init(stream_id);
    send.next_offset = initial_offset;
    scratch.frames.clearRetainingCapacity();
    try send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        max_stream_frame_data,
        !body_open,
    );
    bodies.appendOpenAssumeCapacity(
        stream_id,
        send,
        if (body_open) expected_length else 0,
    );
    body_registered = true;
    defer if (send_attempted) |attempted| {
        attempted.* = packet_send_attempted;
    };
    try packetizer.sendEndpoint(
        endpoint.allocator,
        endpoint,
        to,
        scratch.frames.items,
        1,
        &packet_send_attempted,
    );
}

pub fn responsePrefix(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    scratch: *send_scratch.Message,
    stream_id: u62,
    max_stream_frame_data: usize,
    offsets: *std.AutoHashMapUnmanaged(u62, u64),
) Error!void {
    const slot = try offsets.getOrPut(endpoint.allocator, stream_id);
    const previous_offset = if (slot.found_existing) slot.value_ptr.* else 0;
    errdefer {
        if (!slot.found_existing) _ = offsets.remove(stream_id);
    }

    var send = quic.stream_state.SendState.init(stream_id);
    send.next_offset = previous_offset;
    scratch.frames.clearRetainingCapacity();
    try send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        max_stream_frame_data,
        false,
    );
    try packetizer.sendEndpoint(
        endpoint.allocator,
        endpoint,
        to,
        scratch.frames.items,
        1,
        null,
    );
    slot.value_ptr.* = send.next_offset;
}

pub fn requestCancellation(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    stream_id: u62,
    application_error_code: u64,
    local_final_size: u64,
    send_reset: bool,
) Error!void {
    const reset: quic.Frame = .{ .reset_stream = .{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
        .final_size = local_final_size,
    } };
    const stop: quic.Frame = .{ .stop_sending = .{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    } };
    if (send_reset) {
        try endpoint.sendFrames(to, &.{ reset, stop });
    } else {
        try endpoint.sendFrames(to, &.{stop});
    }
}

pub fn bodyChunk(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    bodies: *outbound_body.Set,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    max_stream_frame_data: usize,
    send_attempted_out: ?*bool,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    var send_attempted = false;
    errdefer {
        if (!send_attempted) entry.* = previous;
    }
    try bodies.prepareChunkForEntry(entry, data.len, fin);
    bodies.payload_scratch.clearRetainingCapacity();
    try body_sender.writeDataFrame(
        &bodies.payload_scratch,
        endpoint.allocator,
        data,
    );
    bodies.frame_scratch.clearRetainingCapacity();
    try entry.send.appendFrames(
        &bodies.frame_scratch,
        endpoint.allocator,
        bodies.payload_scratch.items,
        max_stream_frame_data,
        fin,
    );
    packetizer.sendEndpoint(
        endpoint.allocator,
        endpoint,
        to,
        bodies.frame_scratch.items,
        1,
        &send_attempted,
    ) catch |err| {
        if (send_attempted_out) |attempted| attempted.* = send_attempted;
        return err;
    };
    if (send_attempted_out) |attempted| attempted.* = send_attempted;
}

pub fn appendStreamMessageFrames(
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        frames,
        allocator,
        bytes,
        max_stream_frame_data,
        true,
    );
}
