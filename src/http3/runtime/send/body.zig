const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const body_batch = @import("../body_batch.zig");
const runtime_error = @import("../error.zig");
const protected_send_module = @import("protected.zig");
const send_packetizer = @import("packetizer.zig");
const outbound_body = @import("../stream/outbound_body.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const OutboundBodySet = outbound_body.Set;
const ProtectedSendState = protected_send_module.State;
const BodyChunk = body_batch.Chunk;

pub fn sendConnectionFrames(
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
) Error!void {
    try send_packetizer.send(
        connection.endpoint.allocator,
        connection,
        frames,
        max_frames_per_packet,
    );
}

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    protected_send: *ProtectedSendState,
) Error!void {
    try protected_send.sendFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames,
        config.max_frames_per_packet,
    );
}

pub fn batchProgressIsValid(
    sent_count: usize,
    protected_count: usize,
    staged_count: usize,
) bool {
    return sent_count <= protected_count and protected_count <= staged_count;
}
pub fn writeDataFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) Error!void {
    if (data.len == 0) return;
    try (http3.Frame{
        .frame_type = http3.FrameType.data,
        .payload = data,
        .consumed = 0,
    }).write(list, allocator);
}

const paced_body_frame_overhead_margin: usize = 64;

pub fn pacedBodyChunkLimit(options: anytype) usize {
    // A paced retry unit may be split into several QUIC STREAM frames, but
    // `sendConnectionFrames` packs only `max_frames_per_packet` of them into
    // one QUIC packet. Keep the DATA chunk within that per-packet frame budget
    // and leave a conservative allowance for HTTP/3 DATA framing, STREAM frame
    // prefixes, packet number, and AEAD overhead. The option defaults to 1 KiB
    // for compatibility with the standard 1200B path-MTU configuration, while
    // benchmarks can raise it once their handshake 1-RTT datagram size is also
    // raised.
    const frame_budget = options.max_stream_frame_data *|
        @max(@as(usize, 1), options.max_frames_per_packet);
    const data_budget = if (frame_budget > paced_body_frame_overhead_margin)
        frame_budget - paced_body_frame_overhead_margin
    else
        1;
    return @max(
        @as(usize, 1),
        @min(options.paced_body_chunk_bytes, data_budget),
    );
}

pub fn responseBodySendCapacity(
    remaining: usize,
    connection: usize,
    stream: usize,
    congestion: usize,
    datagram_size: usize,
    chunk_limit: usize,
) usize {
    if (remaining == 0) return 0;
    const credit = @min(
        connection,
        stream,
        congestion,
        datagram_size,
        chunk_limit,
    );
    // QUIC credit counts the HTTP/3 DATA prefix and QUIC STREAM-frame
    // metadata too. Requiring this conservative margin prevents a candidate
    // with only header-sized credit from winning urgency selection and then
    // blocking a lower-urgency response that could make useful progress.
    if (credit <= paced_body_frame_overhead_margin) return 0;
    return @min(remaining, credit - paced_body_frame_overhead_margin);
}

pub fn pacedProtectedBodyChunkLimit(config: anytype) usize {
    const frame_budget = config.max_stream_frame_data *|
        @max(@as(usize, 1), config.max_frames_per_packet);
    const data_budget = if (frame_budget > paced_body_frame_overhead_margin)
        frame_budget - paced_body_frame_overhead_margin
    else
        1;
    return @max(@as(usize, 1), data_budget);
}

pub fn sendConnectionBodyChunk(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: anytype,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    errdefer entry.* = previous;
    try bodies.prepareChunkForEntry(entry, data.len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    var prefix: body_batch.Prefix = undefined;
    if (options.enable_data_prefix_fast_path and
        try body_batch.appendDataStreamFrames(
            &entry.send,
            &bodies.frame_scratch,
            connection.endpoint.allocator,
            &prefix,
            data,
            fin,
            options.max_stream_frame_data,
            options.max_frames_per_packet,
        ))
    {
        try sendConnectionFrames(
            connection,
            bodies.frame_scratch.items,
            options.max_frames_per_packet,
        );
        if (fin) _ = bodies.finish(stream_id);
        return;
    }

    bodies.payload_scratch.clearRetainingCapacity();
    try writeDataFrame(
        &bodies.payload_scratch,
        connection.endpoint.allocator,
        data,
    );
    try entry.send.appendFrames(
        &bodies.frame_scratch,
        connection.endpoint.allocator,
        bodies.payload_scratch.items,
        options.max_stream_frame_data,
        fin,
    );
    try sendConnectionFrames(
        connection,
        bodies.frame_scratch.items,
        options.max_frames_per_packet,
    );
    if (fin) _ = bodies.finish(stream_id);
}

pub fn sendConnectionBodyBatchPaced(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: anytype,
    context: anytype,
    comptime receive_progress: anytype,
    comptime finish_stream: anytype,
) Error!void {
    var sent: usize = 0;
    while (sent < chunks.len) {
        sent += sendConnectionBodyBatchPacedProgress(
            connection,
            bodies,
            chunks[sent..],
            options,
            context,
            finish_stream,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receive_progress(context);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
    }
}

/// Send at most one transport-accepted prefix of `chunks`.
///
/// Returning after each socket-visible prefix gives higher-level schedulers a
/// replan point for newly received PRIORITY_UPDATE frames. The compatibility
/// batch API loops over this primitive to preserve its all-chunks contract.
pub fn sendConnectionBodyBatchPacedProgress(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: anytype,
    context: anytype,
    comptime finish_stream: anytype,
) Error!usize {
    if (chunks.len == 0) return 0;
    for (chunks, 0..) |chunk, i| {
        if (chunk.data.len > pacedBodyChunkLimit(options)) {
            return error.DatagramTooLarge;
        }
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (chunks[j].stream_id == chunk.stream_id) {
                return error.UnexpectedStream;
            }
        }
    }

    const Staged = struct {
        stream_id: u62,
        entry: OutboundBodySet.Entry,
        fin: bool,
    };
    var staged: [quic.one_rtt.max_batch_packets]Staged = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
        undefined;
    const count = @min(quic.one_rtt.max_batch_packets, chunks.len);
    const window = chunks[0..count];
    try bodies.batch_scratch.begin(bodies.allocator, count);

    for (window, 0..) |chunk, i| {
        const current = bodies.find(chunk.stream_id) orelse
            return error.UnexpectedStream;
        staged[i] = .{
            .stream_id = chunk.stream_id,
            .entry = current.*,
            .fin = chunk.fin,
        };
        try bodies.prepareChunkForEntry(
            &staged[i].entry,
            chunk.data.len,
            chunk.fin,
        );
        const frame_start = bodies.batch_scratch.frames.items.len;
        if (chunk.data.len == 0) {
            try staged[i].entry.send.appendFrames(
                &bodies.batch_scratch.frames,
                bodies.allocator,
                &.{},
                options.max_stream_frame_data,
                chunk.fin,
            );
        } else if (!try body_batch.appendDataStreamFrames(
            &staged[i].entry.send,
            &bodies.batch_scratch.frames,
            bodies.allocator,
            &bodies.batch_scratch.prefixes.items[i],
            chunk.data,
            chunk.fin,
            options.max_stream_frame_data,
            options.max_frames_per_packet,
        )) {
            return error.DatagramTooLarge;
        }
        const frame_len =
            bodies.batch_scratch.frames.items.len - frame_start;
        if (frame_len == 0 or
            frame_len > @max(@as(usize, 1), options.max_frames_per_packet))
        {
            return error.DatagramTooLarge;
        }
        bodies.batch_scratch.frame_ranges.items[i] = .{
            .start = frame_start,
            .len = frame_len,
        };
    }

    for (bodies.batch_scratch.frame_ranges.items[0..count], 0..) |range, i| {
        packets[i] = bodies.batch_scratch.frames.items[range.start .. range.start + range.len];
        if (try connection.packetLenForFramesAtOffset(
            i,
            packets[i],
        ) > connection.currentSendDatagramSize()) {
            return error.DatagramTooLarge;
        }
    }

    const result = try connection.sendManyProgress(packets[0..count]);
    if (!batchProgressIsValid(
        result.sent_count,
        result.protected_count,
        count,
    )) return error.Unexpected;

    // QUIC commits only the socket-visible prefix. Mirror that exact
    // prefix into HTTP/3 body offsets and FIN state; protected-but-unsent
    // suffix packets consumed nonces but had their transport flow state
    // rolled back and remain safe to retry under fresh packet numbers.
    for (staged[0..result.sent_count]) |committed| {
        const entry = bodies.find(committed.stream_id) orelse
            return error.UnexpectedStream;
        entry.* = committed.entry;
        if (committed.fin) {
            _ = bodies.finish(committed.stream_id);
            finish_stream(context, committed.stream_id);
        }
    }
    if (result.send_error) |err| return err;
    if (result.sent_count != result.protected_count) {
        return error.Unexpected;
    }
    if (result.sent_count == 0) return error.Unexpected;
    return result.sent_count;
}

pub fn sendProtectedBodyBatchPaced(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    context: anytype,
    comptime receive_progress: anytype,
    comptime finish_stream: anytype,
) Error!void {
    var sent: usize = 0;
    while (sent < chunks.len) {
        sent += sendProtectedBodyBatchProgress(
            endpoint,
            to,
            config,
            next_packet_number,
            protected_send,
            bodies,
            chunks[sent..],
            context,
            finish_stream,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receive_progress(context);
                continue;
            },
            else => return err,
        };
    }
}

pub fn sendProtectedBodyBatchProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    context: anytype,
    comptime finish_stream: anytype,
) Error!usize {
    if (chunks.len == 0) return 0;
    for (chunks, 0..) |chunk, i| {
        if (chunk.data.len > pacedProtectedBodyChunkLimit(config)) {
            return error.DatagramTooLarge;
        }
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (chunks[j].stream_id == chunk.stream_id) {
                return error.UnexpectedStream;
            }
        }
    }

    const Staged = struct {
        stream_id: u62,
        entry: OutboundBodySet.Entry,
        fin: bool,
    };
    var staged: [quic.one_rtt.max_batch_packets]Staged = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    const count = @min(quic.one_rtt.max_batch_packets, chunks.len);
    const window = chunks[0..count];
    try bodies.batch_scratch.begin(bodies.allocator, count);

    for (window, 0..) |chunk, i| {
        const current = bodies.find(chunk.stream_id) orelse
            return error.UnexpectedStream;
        staged[i] = .{
            .stream_id = chunk.stream_id,
            .entry = current.*,
            .fin = chunk.fin,
        };
        try bodies.prepareChunkForEntry(
            &staged[i].entry,
            chunk.data.len,
            chunk.fin,
        );
        const frame_start = bodies.batch_scratch.frames.items.len;
        if (chunk.data.len == 0) {
            try staged[i].entry.send.appendFrames(
                &bodies.batch_scratch.frames,
                bodies.allocator,
                &.{},
                config.max_stream_frame_data,
                chunk.fin,
            );
        } else if (!try body_batch.appendDataStreamFrames(
            &staged[i].entry.send,
            &bodies.batch_scratch.frames,
            bodies.allocator,
            &bodies.batch_scratch.prefixes.items[i],
            chunk.data,
            chunk.fin,
            config.max_stream_frame_data,
            config.max_frames_per_packet,
        )) {
            return error.DatagramTooLarge;
        }
        if (staged[i].entry.flow_limit) |limit| {
            if (staged[i].entry.send.next_offset > limit) {
                return error.FlowControlBlocked;
            }
        }
        const frame_len = bodies.batch_scratch.frames.items.len - frame_start;
        if (frame_len == 0 or
            frame_len > @max(@as(usize, 1), config.max_frames_per_packet))
        {
            return error.DatagramTooLarge;
        }
        bodies.batch_scratch.frame_ranges.items[i] = .{
            .start = frame_start,
            .len = frame_len,
        };
    }

    for (bodies.batch_scratch.frame_ranges.items[0..count], 0..) |range, i| {
        packets[i] = bodies.batch_scratch.frames.items[range.start .. range.start + range.len];
    }
    const result = try protected_send.sendPacketBatchProgress(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        packets[0..count],
    );
    if (!batchProgressIsValid(
        result.sent_count,
        result.protected_count,
        count,
    )) return error.Unexpected;

    // `sendFramesBatchIntoProgress` protects the complete window before the
    // socket call, but only the reported prefix reached the peer. Commit the
    // same prefix to HTTP/3 stream offsets and leave the suffix retryable.
    for (staged[0..result.sent_count]) |committed| {
        const entry = bodies.find(committed.stream_id) orelse
            return error.UnexpectedStream;
        entry.* = committed.entry;
        if (committed.fin) {
            _ = bodies.finish(committed.stream_id);
            finish_stream(context, committed.stream_id);
        }
    }
    if (result.send_error) |err| return err;
    if (result.sent_count == 0) return error.Unexpected;
    return result.sent_count;
}

pub fn sendProtectedBodyChunk(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    errdefer entry.* = previous;
    try bodies.prepareChunkForEntry(entry, data.len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    if (try body_batch.appendDataStreamFrames(
        &entry.send,
        &bodies.frame_scratch,
        endpoint.allocator,
        &bodies.data_prefix_scratch,
        data,
        fin,
        config.max_stream_frame_data,
        config.max_frames_per_packet,
    )) {
        if (entry.flow_limit) |limit| {
            if (entry.send.next_offset > limit) {
                return error.FlowControlBlocked;
            }
        }
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            bodies.frame_scratch.items,
            protected_send,
        );
        if (fin) _ = bodies.finish(stream_id);
        return;
    }

    bodies.payload_scratch.clearRetainingCapacity();
    try writeDataFrame(
        &bodies.payload_scratch,
        endpoint.allocator,
        data,
    );
    if (entry.flow_limit) |limit| {
        const next_offset = std.math.add(
            u64,
            entry.send.next_offset,
            bodies.payload_scratch.items.len,
        ) catch return error.InvalidFrameLength;
        if (next_offset > limit) return error.FlowControlBlocked;
    }
    try entry.send.appendFrames(
        &bodies.frame_scratch,
        endpoint.allocator,
        bodies.payload_scratch.items,
        config.max_stream_frame_data,
        fin,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config,
        next_packet_number,
        bodies.frame_scratch.items,
        protected_send,
    );
    if (fin) _ = bodies.finish(stream_id);
}
