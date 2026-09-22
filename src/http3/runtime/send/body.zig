const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
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
pub const max_paced_body_part_descriptors: usize = 128;

/// Cursor over borrowed body slices for one packet-sized HTTP/3 DATA
/// contribution. It splits only descriptors, never payload bytes into owned
/// storage, and advances a staged copy so callers can commit the cursor only
/// after the packet becomes socket-visible.
pub const BodyPartCursor = struct {
    parts: []const []const u8,
    part_index: usize = 0,
    part_offset: usize = 0,

    fn skipEmpty(self: *BodyPartCursor) void {
        while (self.part_index < self.parts.len and
            self.part_offset == self.parts[self.part_index].len)
        {
            self.part_index += 1;
            self.part_offset = 0;
        }
    }

    pub fn done(self: *BodyPartCursor) bool {
        self.skipEmpty();
        return self.part_index == self.parts.len;
    }

    /// Fill `output` with the next borrowed ranges. Each range is bounded by
    /// `max_part_bytes`, while their aggregate is bounded by `max_bytes`.
    pub fn next(
        self: *BodyPartCursor,
        output: [][]const u8,
        max_bytes: usize,
        max_part_bytes: usize,
    ) []const []const u8 {
        std.debug.assert(output.len != 0);
        std.debug.assert(max_bytes != 0);
        std.debug.assert(max_part_bytes != 0);
        self.skipEmpty();
        var count: usize = 0;
        var bytes: usize = 0;
        while (self.part_index < self.parts.len and
            count < output.len and bytes < max_bytes)
        {
            const part = self.parts[self.part_index];
            const len = @min(
                @min(part.len - self.part_offset, max_bytes - bytes),
                max_part_bytes,
            );
            std.debug.assert(len != 0);
            output[count] = part[self.part_offset..][0..len];
            count += 1;
            bytes += len;
            self.part_offset += len;
            self.skipEmpty();
        }
        return output[0..count];
    }
};

pub const ConnectionBodyBatchProgress = struct {
    /// Exact socket-visible prefix committed to HTTP/3 stream state.
    sent_count: usize,
    /// The transport can fail after the whole batch is protected, including
    /// in an endpoint interceptor before socket progress.
    send_error: ?quic.runtime.Error = null,
};

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

pub fn sendConnectionFramesWithDeadline(
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    try send_packetizer.sendWithDeadline(
        connection.endpoint.allocator,
        connection,
        frames,
        max_frames_per_packet,
        deadline,
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

test "HTTP/3 paced body-part cursor groups across slice boundaries" {
    var cursor = BodyPartCursor{
        .parts = &.{ "ab", &.{}, "cdef", "ghi" },
    };
    var storage: [3][]const u8 = undefined;

    const first = cursor.next(&storage, 5, 3);
    try std.testing.expectEqual(@as(usize, 2), first.len);
    try std.testing.expectEqualStrings("ab", first[0]);
    try std.testing.expectEqualStrings("cde", first[1]);
    try std.testing.expect(!cursor.done());

    const second = cursor.next(&storage, 5, 3);
    try std.testing.expectEqual(@as(usize, 2), second.len);
    try std.testing.expectEqualStrings("f", second[0]);
    try std.testing.expectEqualStrings("ghi", second[1]);
    try std.testing.expect(cursor.done());
}

test "HTTP/3 paced body-part cursor preserves a retry snapshot" {
    var cursor = BodyPartCursor{ .parts = &.{ "abc", "def" } };
    var staged = cursor;
    var first_storage: [2][]const u8 = undefined;
    const first = staged.next(&first_storage, 4, 3);
    try std.testing.expectEqual(@as(usize, 2), first.len);
    try std.testing.expectEqualStrings("abc", first[0]);
    try std.testing.expectEqualStrings("d", first[1]);
    try std.testing.expect(!cursor.done());

    cursor = staged;
    var second_storage: [2][]const u8 = undefined;
    const second = cursor.next(&second_storage, 4, 3);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqualStrings("ef", second[0]);
    try std.testing.expect(cursor.done());
}

test "HTTP/3 paced body-part cursor bounds descriptor batches" {
    var cursor = BodyPartCursor{
        .parts = &.{ "a", "", "b", "c", "d", "" },
    };
    var storage: [2][]const u8 = undefined;

    const first = cursor.next(&storage, 64, 64);
    try std.testing.expectEqual(@as(usize, 2), first.len);
    try std.testing.expectEqualStrings("a", first[0]);
    try std.testing.expectEqualStrings("b", first[1]);
    try std.testing.expect(!cursor.done());

    const second = cursor.next(&storage, 64, 64);
    try std.testing.expectEqual(@as(usize, 2), second.len);
    try std.testing.expectEqualStrings("c", second[0]);
    try std.testing.expectEqualStrings("d", second[1]);
    try std.testing.expect(cursor.done());
}

test "HTTP/3 paced body-part cursor accepts only empty parts" {
    var cursor = BodyPartCursor{ .parts = &.{ &.{}, &.{}, &.{} } };
    try std.testing.expect(cursor.done());
}

test "HTTP/3 paced body-part cursor collapses the eight-slice benchmark shape" {
    var payload: [4096]u8 = undefined;
    var input: [9][]const u8 = undefined;
    input[0] = "head";
    for (input[1..], 0..) |*part, index| {
        part.* = payload[index * 512 ..][0..512];
    }
    var cursor = BodyPartCursor{ .parts = &input };
    var storage: [7][]const u8 = undefined;
    var contribution_count: usize = 0;
    var byte_count: usize = 0;
    while (!cursor.done()) {
        const contribution = cursor.next(&storage, 3500, 3500);
        contribution_count += 1;
        for (contribution) |part| byte_count += part.len;
    }
    try std.testing.expectEqual(@as(usize, 2), contribution_count);
    try std.testing.expectEqual(@as(usize, 4100), byte_count);
}

pub fn sendConnectionBodyChunk(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: anytype,
) Error!void {
    return sendConnectionBodyChunkUntil(
        connection,
        bodies,
        stream_id,
        data,
        fin,
        options,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendConnectionBodyChunkWithDeadline(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: anytype,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return sendConnectionBodyChunkUntil(
        connection,
        bodies,
        stream_id,
        data,
        fin,
        options,
        deadline,
    );
}

fn sendConnectionBodyChunkUntil(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
        if (deadline) |absolute| {
            try sendConnectionFramesWithDeadline(
                connection,
                bodies.frame_scratch.items,
                options.max_frames_per_packet,
                absolute,
            );
        } else {
            try sendConnectionFrames(
                connection,
                bodies.frame_scratch.items,
                options.max_frames_per_packet,
            );
        }
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
    if (deadline) |absolute| {
        try sendConnectionFramesWithDeadline(
            connection,
            bodies.frame_scratch.items,
            options.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendConnectionFrames(
            connection,
            bodies.frame_scratch.items,
            options.max_frames_per_packet,
        );
    }
    if (fin) _ = bodies.finish(stream_id);
}

/// Send one bounded HTTP/3 DATA contribution borrowed from several slices.
/// Unlike the nonblocking one-packet helper below, this path may packetize the
/// contribution across several QUIC datagrams and batch their socket submit.
/// A partially visible transport error closes the QUIC connection before the
/// caller can retry, matching `sendConnectionBodyChunk`'s fail-closed contract.
pub fn sendConnectionBodyParts(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
    options: anytype,
) Error!void {
    var data_len: usize = 0;
    for (parts) |part| {
        data_len = std.math.add(usize, data_len, part.len) catch
            return error.InvalidContentLength;
    }
    if (data_len == 0) {
        return sendConnectionBodyChunk(
            connection,
            bodies,
            stream_id,
            &.{},
            fin,
            options,
        );
    }

    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    errdefer entry.* = previous;
    try bodies.prepareChunkForEntry(entry, data_len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    if (!try body_batch.appendDataStreamPartFrames(
        &entry.send,
        &bodies.frame_scratch,
        connection.endpoint.allocator,
        &bodies.data_prefix_scratch,
        parts,
        fin,
        options.max_stream_frame_data,
        options.max_frames_per_packet,
    )) return error.DatagramTooLarge;
    try sendConnectionFrames(
        connection,
        bodies.frame_scratch.items,
        options.max_frames_per_packet,
    );
    if (fin) _ = bodies.finish(stream_id);
}

/// Submit one complete HTTP/3 DATA contribution in one QUIC packet without
/// sleeping. Both QUIC and body-stream state remain unchanged when pacing,
/// congestion, flow control, or packet sizing prevents the attempt.
pub fn trySendConnectionBodyChunk(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: anytype,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    var staged = entry.*;
    try bodies.prepareChunkForEntry(&staged, data.len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    if (!try body_batch.appendDataStreamFrames(
        &staged.send,
        &bodies.frame_scratch,
        connection.endpoint.allocator,
        &bodies.data_prefix_scratch,
        data,
        fin,
        options.max_stream_frame_data,
        options.max_frames_per_packet,
    )) {
        bodies.payload_scratch.clearRetainingCapacity();
        try writeDataFrame(
            &bodies.payload_scratch,
            connection.endpoint.allocator,
            data,
        );
        try staged.send.appendFrames(
            &bodies.frame_scratch,
            connection.endpoint.allocator,
            bodies.payload_scratch.items,
            options.max_stream_frame_data,
            fin,
        );
    }
    if (bodies.frame_scratch.items.len == 0 or
        bodies.frame_scratch.items.len >
            @max(@as(usize, 1), options.max_frames_per_packet) or
        try connection.packetLenForFramesAtOffset(
            0,
            bodies.frame_scratch.items,
        ) > connection.currentSendDatagramSize())
    {
        return error.DatagramTooLarge;
    }
    try connection.trySend(bodies.frame_scratch.items);
    entry.* = staged;
    if (fin) _ = bodies.finish(stream_id);
}

/// Submit several borrowed slices as one HTTP/3 DATA frame and one QUIC
/// packet. The complete contribution is transactional: any validation or send
/// failure leaves the body length, STREAM offset, and FIN state unchanged.
pub fn trySendConnectionBodyParts(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    parts: []const []const u8,
    fin: bool,
    options: anytype,
) Error!void {
    var data_len: usize = 0;
    for (parts) |part| {
        data_len = std.math.add(usize, data_len, part.len) catch
            return error.InvalidContentLength;
    }
    if (data_len == 0) {
        return trySendConnectionBodyChunk(
            connection,
            bodies,
            stream_id,
            &.{},
            fin,
            options,
        );
    }

    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    var staged = entry.*;
    try bodies.prepareChunkForEntry(&staged, data_len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    if (!try body_batch.appendDataStreamPartFrames(
        &staged.send,
        &bodies.frame_scratch,
        connection.endpoint.allocator,
        &bodies.data_prefix_scratch,
        parts,
        fin,
        options.max_stream_frame_data,
        options.max_frames_per_packet,
    )) return error.DatagramTooLarge;
    if (bodies.frame_scratch.items.len == 0 or
        try connection.packetLenForFramesAtOffset(
            0,
            bodies.frame_scratch.items,
        ) > connection.currentSendDatagramSize())
    {
        return error.DatagramTooLarge;
    }
    try connection.trySend(bodies.frame_scratch.items);
    entry.* = staged;
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
        const progress = sendConnectionBodyBatchPacedProgress(
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
        sent += progress.sent_count;
        if (progress.send_error) |err| return err;
    }
}

/// Deadline-bounded counterpart to `sendConnectionBodyBatchPaced`.
///
/// `committed_chunks` is reset before validation and then tracks the exact
/// socket-visible prefix. It remains meaningful on timeout or a socket error;
/// callers may retry only `chunks[committed_chunks.*..]`.
pub fn sendConnectionBodyBatchPacedWithDeadline(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: anytype,
    context: anytype,
    comptime receive_progress: anytype,
    comptime finish_stream: anytype,
    committed_chunks: *usize,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    committed_chunks.* = 0;
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    try validateConnectionBodyBatch(bodies, chunks, options);
    while (committed_chunks.* < chunks.len) {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
        const progress = sendConnectionBodyBatchPacedProgress(
            connection,
            bodies,
            chunks[committed_chunks.*..],
            options,
            context,
            finish_stream,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receive_progress(context, deadline);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailabilityWithDeadline(deadline);
                continue;
            },
            else => return err,
        };
        committed_chunks.* += progress.sent_count;
        if (progress.send_error) |err| return err;
    }
}

fn validateConnectionBodyBatch(
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: anytype,
) Error!void {
    for (chunks, 0..) |chunk, index| {
        if (chunk.data.len > pacedBodyChunkLimit(options)) {
            return error.DatagramTooLarge;
        }
        for (chunks[0..index]) |previous| {
            if (previous.stream_id == chunk.stream_id) {
                return error.UnexpectedStream;
            }
        }
        const current = bodies.find(chunk.stream_id) orelse
            return error.UnexpectedStream;
        var staged = current.*;
        try bodies.prepareChunkForEntry(
            &staged,
            chunk.data.len,
            chunk.fin,
        );
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
) Error!ConnectionBodyBatchProgress {
    if (chunks.len == 0) return .{ .sent_count = 0 };
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
    }

    // sendManyProgress performs one exact, whole-prefix packet-size preflight
    // before reserving flow/congestion state, recovery ownership, packet
    // numbers, or touching the socket. Avoid walking every STREAM frame a
    // second time here; staged HTTP/3 body state is committed only for the
    // socket-visible prefix returned below.
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
    if (result.sent_count != result.protected_count) {
        if (result.send_error == null) return error.Unexpected;
    }
    if (result.sent_count == 0 and result.send_error == null) {
        return error.Unexpected;
    }
    return .{
        .sent_count = result.sent_count,
        .send_error = result.send_error,
    };
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
    try validateProtectedBodyBatch(bodies, chunks, config);
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

pub fn sendProtectedBodyBatchPacedWithDeadline(
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
    committed_chunks: *usize,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    committed_chunks.* = 0;
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    try validateProtectedBodyBatch(bodies, chunks, config);
    while (committed_chunks.* < chunks.len) {
        _ = try deadline_policy.usableAwake(endpoint.io, deadline);
        const progress = sendProtectedBodyBatchProgressUntil(
            endpoint,
            to,
            config,
            next_packet_number,
            protected_send,
            bodies,
            chunks[committed_chunks.*..],
            context,
            finish_stream,
            deadline,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receive_progress(context, deadline);
                continue;
            },
            else => return err,
        };
        committed_chunks.* += progress.sent_count;
        if (progress.send_error) |err| return err;
    }
}

fn validateProtectedBodyBatch(
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    config: anytype,
) Error!void {
    for (chunks, 0..) |chunk, index| {
        if (chunk.data.len > pacedProtectedBodyChunkLimit(config)) {
            return error.DatagramTooLarge;
        }
        for (chunks[0..index]) |previous| {
            if (previous.stream_id == chunk.stream_id) {
                return error.UnexpectedStream;
            }
        }
        const current = bodies.find(chunk.stream_id) orelse
            return error.UnexpectedStream;
        var staged = current.*;
        try bodies.prepareChunkForEntry(
            &staged,
            chunk.data.len,
            chunk.fin,
        );
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
    const progress = sendProtectedBodyBatchProgressUntil(
        endpoint,
        to,
        config,
        next_packet_number,
        protected_send,
        bodies,
        chunks,
        context,
        finish_stream,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
    if (progress.send_error) |err| return err;
    return progress.sent_count;
}

fn sendProtectedBodyBatchProgressUntil(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    context: anytype,
    comptime finish_stream: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!ConnectionBodyBatchProgress {
    if (chunks.len == 0) return .{ .sent_count = 0 };
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
    const result = if (deadline) |absolute|
        try protected_send.sendPacketBatchProgressWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            packets[0..count],
            absolute,
        )
    else
        try protected_send.sendPacketBatchProgress(
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
    if (result.sent_count == 0) {
        if (result.send_error) |err| return err;
        return error.Unexpected;
    }
    return .{
        .sent_count = result.sent_count,
        .send_error = result.send_error,
    };
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
    return sendProtectedBodyChunkUntil(
        endpoint,
        to,
        config,
        next_packet_number,
        protected_send,
        bodies,
        stream_id,
        data,
        fin,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendProtectedBodyChunkWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    _ = try deadline_policy.usableAwake(endpoint.io, deadline);
    return sendProtectedBodyChunkUntil(
        endpoint,
        to,
        config,
        next_packet_number,
        protected_send,
        bodies,
        stream_id,
        data,
        fin,
        deadline,
    );
}

fn sendProtectedBodyChunkUntil(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
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
        if (deadline) |absolute| {
            try protected_send.sendFramesWithDeadline(
                endpoint,
                to,
                config.send_keys,
                config.peer_connection_id,
                next_packet_number,
                bodies.frame_scratch.items,
                config.max_frames_per_packet,
                absolute,
            );
        } else {
            try sendProtectedFrames(
                endpoint,
                to,
                config,
                next_packet_number,
                bodies.frame_scratch.items,
                protected_send,
            );
        }
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
    if (deadline) |absolute| {
        try protected_send.sendFramesWithDeadline(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            bodies.frame_scratch.items,
            config.max_frames_per_packet,
            absolute,
        );
    } else {
        try sendProtectedFrames(
            endpoint,
            to,
            config,
            next_packet_number,
            bodies.frame_scratch.items,
            protected_send,
        );
    }
    if (fin) _ = bodies.finish(stream_id);
}
