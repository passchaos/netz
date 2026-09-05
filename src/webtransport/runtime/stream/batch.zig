//! Cross-stream WebTransport writes backed by QUIC's stateful packet batch.
//!
//! Each input contributes at most one packet-sized application slice. The
//! transport may accept only a prefix of the staged packet array; registry
//! offsets and caller counts commit exactly that socket-visible prefix.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const stream_runtime = @import("../stream.zig");

pub const Error = stream_runtime.Error;

pub const Write = struct {
    stream_id: u62,
    data: []const u8,
};

const Validation = struct {
    all_prefixes_sent: bool = true,
};

/// Validate each stream id once before prefix transmission or packet staging.
///
/// Keeping this separate makes duplicate/error rejection transactional: a bad
/// later item cannot leave an earlier stream's association prefix on the wire.
pub fn validate(
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
) Error!void {
    _ = try validateBatch(registry, writes);
}

fn validateBatch(
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
) Error!Validation {
    const validation_epoch = registry.beginBatchEpoch();
    var result: Validation = .{};
    for (writes) |item| {
        if (item.data.len == 0) continue;
        const mark = registry.markForBatch(
            item.stream_id,
            validation_epoch,
        ) orelse
            return error.UnknownStream;
        const stream = mark.stream;
        if ((stream.direction == .unidirectional and
            !stream.locally_initiated) or
            stream.send_reset != null or
            stream.stopped != null or
            stream.local_fin)
        {
            return error.InvalidStreamState;
        }
        if (!mark.first) return error.DuplicateStream;
        result.all_prefixes_sent = result.all_prefixes_sent and
            stream.prefix_sent;
    }
    return result;
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

    const packet_limit = @min(writes.len, quic.one_rtt.max_batch_packets);
    var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    var input_indices: [quic.one_rtt.max_batch_packets]usize = undefined;
    var byte_counts: [quic.one_rtt.max_batch_packets]usize = undefined;

    while (true) {
        // A blocked retry may have processed STOP_SENDING/RESET_STREAM, and a
        // prefix-aware pass may have completed every association prefix.
        // Revalidate the current registry state before each staging attempt.
        const validation = try validateBatch(registry, writes);
        const packet_count = if (validation.all_prefixes_sent)
            try stageSteadyBatch(
                connection,
                registry,
                writes,
                packet_limit,
                &frames,
                &packets,
                &input_indices,
                &byte_counts,
            )
        else
            try stagePrefixAwareBatch(
                connection,
                registry,
                session_id,
                writes,
                packet_limit,
                &frames,
                &packets,
                &input_indices,
                &byte_counts,
            );

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
            const input_index = input_indices[packet_index];
            const stream_id = writes[input_index].stream_id;
            const count = byte_counts[packet_index];
            const stream = registry.get(stream_id) orelse
                return error.UnknownStream;
            stream.send_offset = std.math.add(
                u64,
                stream.send_offset,
                count,
            ) catch return error.IntegerOverflow;
            try registry.recordSent(stream_id, count, false);
            counts[input_index] = count;
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

const OrderedWrite = struct {
    input_index: usize,
    priority: i32,
    byte_count: usize,
};

fn insertOrderedWrite(
    selected: []OrderedWrite,
    selected_count: *usize,
    limit: usize,
    candidate: OrderedWrite,
) void {
    std.debug.assert(limit <= selected.len);
    var position: usize = 0;
    while (position < selected_count.* and
        selected[position].priority >= candidate.priority)
    {
        position += 1;
    }
    if (position >= limit) return;
    const next_count = @min(selected_count.* + 1, limit);
    var move = next_count;
    while (move > position + 1) {
        move -= 1;
        selected[move] = selected[move - 1];
    }
    selected[position] = candidate;
    selected_count.* = next_count;
}

fn stageSteadyBatch(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    writes: []const Write,
    packet_limit: usize,
    frames: *[quic.one_rtt.max_batch_packets][1]quic.Frame,
    packets: *[quic.one_rtt.max_batch_packets][]const quic.Frame,
    input_indices: *[quic.one_rtt.max_batch_packets]usize,
    byte_counts: *[quic.one_rtt.max_batch_packets]usize,
) Error!usize {
    var selected: [quic.one_rtt.max_batch_packets]OrderedWrite = undefined;
    var selected_count: usize = 0;
    const common_available = @min(
        std.math.cast(
            usize,
            connection.connectionSendAvailable(),
        ) orelse std.math.maxInt(usize),
        connection.congestionAvailable(),
        connection.currentSendDatagramSize() -| 128,
    );
    for (writes, 0..) |item, input_index| {
        if (item.data.len == 0) continue;
        const stream = registry.get(item.stream_id) orelse
            return error.UnknownStream;
        std.debug.assert(stream.prefix_sent);
        const stream_available = std.math.cast(
            usize,
            connection.streamSendAvailable(item.stream_id),
        ) orelse std.math.maxInt(usize);
        const count = @min(item.data.len, common_available, stream_available);
        if (count == 0) continue;
        insertOrderedWrite(&selected, &selected_count, packet_limit, .{
            .input_index = input_index,
            .priority = stream.priority,
            .byte_count = count,
        });
    }
    for (selected[0..selected_count], 0..) |item, packet_index| {
        const input = writes[item.input_index];
        const stream = registry.get(input.stream_id) orelse
            return error.UnknownStream;
        frames[packet_index][0] = .{ .stream = .{
            .stream_id = input.stream_id,
            .offset = stream.send_offset,
            .data = input.data[0..item.byte_count],
            .fin = false,
        } };
        packets[packet_index] = &frames[packet_index];
        input_indices[packet_index] = item.input_index;
        byte_counts[packet_index] = item.byte_count;
    }
    return selected_count;
}

fn stagePrefixAwareBatch(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    packet_limit: usize,
    frames: *[quic.one_rtt.max_batch_packets][1]quic.Frame,
    packets: *[quic.one_rtt.max_batch_packets][]const quic.Frame,
    input_indices: *[quic.one_rtt.max_batch_packets]usize,
    byte_counts: *[quic.one_rtt.max_batch_packets]usize,
) Error!usize {
    var packet_count: usize = 0;
    const selection_epoch = registry.beginBatchEpoch();
    while (packet_count < packet_limit) {
        const input_index = (try nextSendableWriteIndex(
            connection,
            registry,
            writes,
            selection_epoch,
        )) orelse break;
        const item = writes[input_index];
        const mark = registry.markForBatch(
            item.stream_id,
            selection_epoch,
        ) orelse return error.UnknownStream;
        if (!mark.first) return error.Unexpected;
        const stream = try stream_runtime.prepare(
            connection,
            registry,
            session_id,
            item.stream_id,
        );
        const count = @min(
            item.data.len,
            sendableBytes(connection.streamSendCredit(item.stream_id)),
        );
        // Marking happens before `prepare`: if the association prefix consumes
        // the final credit, the next scan skips this stream and gives sendable
        // peers a chance to progress.
        if (count == 0) continue;

        frames[packet_count][0] = .{ .stream = .{
            .stream_id = item.stream_id,
            .offset = stream.send_offset,
            .data = item.data[0..count],
            .fin = false,
        } };
        packets[packet_count] = &frames[packet_count];
        input_indices[packet_count] = input_index;
        byte_counts[packet_count] = count;
        packet_count += 1;
    }
    return packet_count;
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
    selection_epoch: u64,
) Error!?usize {
    var selected_index: ?usize = null;
    var selected_priority: i32 = std.math.minInt(i32);
    for (writes, 0..) |item, input_index| {
        if (item.data.len == 0) continue;
        const selected = registry.markedForBatch(
            item.stream_id,
            selection_epoch,
        ) orelse return error.UnknownStream;
        if (selected or
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
    selection_epoch: u64,
) Error!?usize {
    var selected_index: ?usize = null;
    var selected_priority: i32 = std.math.minInt(i32);
    for (writes, 0..) |item, input_index| {
        if (item.data.len == 0) continue;
        const selected = registry.markedForBatch(
            item.stream_id,
            selection_epoch,
        ) orelse return error.UnknownStream;
        if (selected) continue;
        const priority = try registry.priority(item.stream_id);
        if (selected_index == null or priority > selected_priority) {
            selected_index = input_index;
            selected_priority = priority;
        }
    }
    return selected_index;
}

/// Narrow white-box helpers for the colocated stream batch tests.
pub const testing = struct {
    pub const Ordered = OrderedWrite;

    pub fn nextWrite(
        registry: *webtransport.StreamRegistry,
        writes: []const Write,
        selection_epoch: u64,
    ) Error!?usize {
        return nextWriteIndex(registry, writes, selection_epoch);
    }

    pub fn insertOrdered(
        selected: []Ordered,
        selected_count: *usize,
        limit: usize,
        candidate: Ordered,
    ) void {
        insertOrderedWrite(
            selected,
            selected_count,
            limit,
            candidate,
        );
    }
};
