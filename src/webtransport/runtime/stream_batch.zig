//! Cross-stream WebTransport writes backed by QUIC's stateful packet batch.
//!
//! Each input contributes at most one packet-sized application slice. The
//! transport may accept only a prefix of the staged packet array; registry
//! offsets and caller counts commit exactly that socket-visible prefix.

const std = @import("std");
const webtransport = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const stream_runtime = @import("stream.zig");

pub const Error = stream_runtime.Error;

pub const Write = struct {
    stream_id: u62,
    data: []const u8,
};

/// Validate each stream id once before prefix transmission or packet staging.
///
/// Keeping this separate makes duplicate/error rejection transactional: a bad
/// later item cannot leave an earlier stream's association prefix on the wire.
pub fn validate(
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
) Error!void {
    for (writes, 0..) |item, index| {
        if (item.data.len == 0) continue;
        const stream = registry.get(item.stream_id) orelse
            return error.UnknownStream;
        if ((stream.direction == .unidirectional and
            !stream.locally_initiated) or
            stream.send_reset != null or
            stream.stopped != null or
            stream.local_fin)
        {
            return error.InvalidStreamState;
        }
        for (writes[0..index]) |previous| {
            if (previous.data.len != 0 and
                previous.stream_id == item.stream_id)
            {
                return error.DuplicateStream;
            }
        }
    }
}

pub const Result = struct {
    /// Number of writes with a nonzero committed application prefix.
    progressed: usize,
    /// Socket error observed after an accepted packet prefix, if any.
    send_error: ?std.Io.net.Socket.SendError = null,
};

/// Write one fair packet-sized slice to every immediately sendable stream.
///
/// The output slice must have at least as many elements as `writes`. It is
/// cleared first and records application bytes committed for each input. Empty
/// writes are ignored. A stream ID may occur at most once per call.
pub fn write(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
) Error!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    if (writes.len == 0) return .{ .progressed = 0 };
    try validate(registry, writes);

    const packet_limit = @min(writes.len, quic.one_rtt.max_batch_packets);
    var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    var input_indices: [quic.one_rtt.max_batch_packets]usize = undefined;
    var stream_ids: [quic.one_rtt.max_batch_packets]u62 = undefined;
    var byte_counts: [quic.one_rtt.max_batch_packets]usize = undefined;

    while (true) {
        var packet_count: usize = 0;
        // Preserve FIFO among equal priorities while allowing callers to keep
        // a stable write array: each selection scans only the bounded packet
        // batch (currently at most 64 streams), not the payload bytes.
        while (packet_count < packet_limit) {
            const input_index = (try nextSendableWriteIndex(
                connection,
                registry,
                writes,
                input_indices[0..packet_count],
            )) orelse break;
            const item = writes[input_index];
            const stream = try stream_runtime.prepare(
                connection,
                registry,
                session_id,
                item.stream_id,
            );
            const credit = connection.streamSendCredit(item.stream_id);
            const count = @min(
                item.data.len,
                sendableBytes(credit),
            );
            // `prepare` can consume the final bytes of credit while sending a
            // stream's association prefix. The next candidate scan will now
            // skip this stream, rather than repeatedly selecting a blocked
            // high-priority stream and preventing transport progress.
            if (count == 0) continue;

            frames[packet_count][0] = .{ .stream = .{
                .stream_id = item.stream_id,
                .offset = stream.send_offset,
                .data = item.data[0..count],
                .fin = false,
            } };
            packets[packet_count] = &frames[packet_count];
            input_indices[packet_count] = input_index;
            stream_ids[packet_count] = item.stream_id;
            byte_counts[packet_count] = count;
            packet_count += 1;
        }

        if (packet_count == 0) {
            var has_data = false;
            for (writes) |item| has_data = has_data or item.data.len != 0;
            if (!has_data) return .{ .progressed = 0 };
            try stream_runtime.receiveSendProgress(connection);
            continue;
        }

        const sent = connection.sendManyProgress(packets[0..packet_count]) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try stream_runtime.receiveSendProgress(connection);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
        if (sent.sent_count > packet_count or
            sent.sent_count > sent.protected_count)
        {
            return error.Unexpected;
        }

        for (0..sent.sent_count) |packet_index| {
            const stream_id = stream_ids[packet_index];
            const count = byte_counts[packet_index];
            const stream = registry.get(stream_id) orelse
                return error.UnknownStream;
            stream.send_offset = std.math.add(
                u64,
                stream.send_offset,
                count,
            ) catch return error.IntegerOverflow;
            try registry.recordSent(stream_id, count, false);
            counts[input_indices[packet_index]] = count;
        }
        if (sent.sent_count == 0 and sent.send_error == null) {
            return error.Unexpected;
        }
        return .{
            .progressed = sent.sent_count,
            .send_error = sent.send_error,
        };
    }
}

/// Select the highest-priority input that can contribute application bytes.
///
/// Flow-control and congestion availability are deliberately part of runtime
/// selection rather than handled after priority selection. Otherwise a
/// blocked high-priority stream is selected forever: it never enters
/// `selected_indices`, the packet count does not advance, and the outer loop
/// never gets a chance to service ACK/MAX_DATA/MAX_STREAM_DATA packets.
fn nextSendableWriteIndex(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
    selected_indices: []const usize,
) Error!?usize {
    var selected_index: ?usize = null;
    var selected_priority: i32 = std.math.minInt(i32);
    for (writes, 0..) |item, input_index| {
        if (item.data.len == 0 or
            std.mem.indexOfScalar(usize, selected_indices, input_index) != null or
            sendableBytes(connection.streamSendCredit(item.stream_id)) == 0)
        {
            continue;
        }
        const priority = try registry.priority(item.stream_id);
        if (selected_index == null or priority > selected_priority) {
            selected_index = input_index;
            selected_priority = priority;
        }
    }
    return selected_index;
}

fn sendableBytes(credit: quic.one_rtt.SendCredit) usize {
    // Leave conservative room for the short-header packet and STREAM frame,
    // matching the single-stream writer's packet sizing policy.
    return @min(credit.max_datagram_size -| 128, credit.available());
}

fn nextWriteIndex(
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
    selected_indices: []const usize,
) Error!?usize {
    var selected_index: ?usize = null;
    var selected_priority: i32 = std.math.minInt(i32);
    for (writes, 0..) |item, input_index| {
        if (item.data.len == 0 or
            std.mem.indexOfScalar(usize, selected_indices, input_index) != null)
        {
            continue;
        }
        const priority = try registry.priority(item.stream_id);
        if (selected_index == null or priority > selected_priority) {
            selected_index = input_index;
            selected_priority = priority;
        }
    }
    return selected_index;
}

test "WebTransport batch selects high priority streams with stable ties" {
    const allocator = std.testing.allocator;
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const low = (try registry.openLocal(.bidirectional)).stream_id;
    const high_first = (try registry.openLocal(.bidirectional)).stream_id;
    const high_second = (try registry.openLocal(.bidirectional)).stream_id;
    try registry.setPriority(low, -4);
    try registry.setPriority(high_first, 7);
    try registry.setPriority(high_second, 7);
    const writes = [_]Write{
        .{ .stream_id = low, .data = "low" },
        .{ .stream_id = high_first, .data = "high-a" },
        .{ .stream_id = high_second, .data = "high-b" },
    };
    var selected: [3]usize = undefined;
    selected[0] = (try nextWriteIndex(&registry, &writes, &.{})).?;
    selected[1] = (try nextWriteIndex(
        &registry,
        &writes,
        selected[0..1],
    )).?;
    selected[2] = (try nextWriteIndex(
        &registry,
        &writes,
        selected[0..2],
    )).?;
    try std.testing.expectEqualSlices(
        usize,
        &.{ 1, 2, 0 },
        &selected,
    );
}
