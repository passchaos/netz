//! Cross-stream WebTransport writes backed by QUIC's stateful packet batch.
//!
//! Each input contributes at most one packet-sized application slice. The
//! transport may accept only a prefix of the staged packet array; registry
//! offsets and caller counts commit exactly that socket-visible prefix.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const stream_runtime = @import("../stream.zig");
const flow_send = @import("../flow/send.zig");
const flow_progress = @import("../flow/progress.zig");
const send_wait = @import("wait.zig");

pub const Error = stream_runtime.Error;
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

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
    return writeWithProgress(
        connection,
        registry,
        session_id,
        writes,
        counts,
        null,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

/// Relative-timeout counterpart to `write`. A non-positive duration returns
/// `Timeout` with `counts` cleared before any staging or transport work.
pub fn writeWithTimeout(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
    timeout: std.Io.Duration,
) TimeoutError!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    return writeWithProgress(
        connection,
        registry,
        session_id,
        writes,
        counts,
        (try deadline_policy.fromTimeout(connection.endpoint.io, timeout)).?,
        null,
    );
}

/// Write one fair packet-sized slice per sendable stream while retaining one
/// absolute awake-clock deadline across flow-control, congestion, and pacing
/// waits. `counts` is cleared before deadline validation and always describes
/// only the application bytes accepted by the socket during this call.
pub fn writeWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    return writeWithProgress(
        connection,
        registry,
        session_id,
        writes,
        counts,
        deadline,
        null,
    );
}

pub fn writeWithProgress(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
    deadline: ?std.Io.Clock.Timestamp,
    progress: ?flow_progress.Progress,
) TimeoutError!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    _ = try validateBatch(registry, writes);
    while (true) {
        try ensureDeadline(connection, deadline);
        if (hasApplicationData(writes)) try flow_send.wait(registry, progress, deadline);
        try ensureDeadline(connection, deadline);
        const result = writeOnceUntil(
            connection,
            registry,
            session_id,
            writes,
            counts,
            deadline,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try send_wait.receive(connection, deadline, progress);
                continue;
            },
            error.PacingLimited => {
                try send_wait.pacing(connection, deadline, progress);
                continue;
            },
            else => |other| return other,
        };
        if (result.progressed != 0 or
            result.send_error != null or
            !hasApplicationData(writes))
        {
            return result;
        }
        try send_wait.receive(connection, deadline, progress);
    }
}

/// Submit one fair packet batch without waiting for transport progress or
/// reading the endpoint socket. Counts and `send_error` retain the same
/// socket-visible-prefix contract as the blocking wrapper.
pub fn writeOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
) Error!Result {
    return writeOnceUntil(
        connection,
        registry,
        session_id,
        writes,
        counts,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn writeOnceUntil(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    counts: []usize,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!Result {
    if (counts.len < writes.len) return error.BufferTooShort;
    @memset(counts[0..writes.len], 0);
    if (writes.len == 0) return .{ .progressed = 0 };

    const packet_limit = @min(writes.len, quic.one_rtt.max_batch_packets);
    var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame = undefined;
    var input_indices: [quic.one_rtt.max_batch_packets]usize = undefined;
    var byte_counts: [quic.one_rtt.max_batch_packets]usize = undefined;
    var committed_streams: [quic.one_rtt.max_batch_packets]*webtransport.StreamState =
        undefined;
    var committed_offsets: [quic.one_rtt.max_batch_packets]u64 = undefined;
    var committed_bytes: [quic.one_rtt.max_batch_packets]u64 = undefined;

    const validation = try validateBatch(registry, writes);
    const staged_count = if (validation.all_prefixes_sent)
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
        try stagePrefixAwareBatchOnce(
            connection,
            registry,
            session_id,
            writes,
            packet_limit,
            &frames,
            &packets,
            &input_indices,
            &byte_counts,
            deadline,
        );

    var packet_count: usize = 0;
    var session_available = flow_send.available(registry);
    for (0..staged_count) |index| {
        const count = @min(byte_counts[index], session_available);
        if (count == 0) break;
        frames[index][0].stream.data = frames[index][0].stream.data[0..count];
        byte_counts[index] = count;
        session_available -= count;
        packet_count += 1;
    }

    if (packet_count == 0) {
        if (!hasApplicationData(writes)) return .{ .progressed = 0 };
        // Prefix-aware staging can make transport progress without committing
        // application bytes. Report that retryable zero prefix explicitly; a
        // shared endpoint will route MAX_* or ACK progress before calling us
        // again. If every prefix was already present, ask QUIC to emit its
        // normal BLOCKED signal and surface the precise backpressure error.
        if (!validation.all_prefixes_sent) return .{ .progressed = 0 };
        return if (connection.congestionAvailable() == 0)
            error.CongestionLimited
        else
            error.FlowControlBlocked;
    }

    // Complete every fallible registry lookup and overflow check before any
    // staged packet becomes socket-visible. The commit loop after send then
    // consists only of infallible assignments and caller-count updates.
    for (0..packet_count) |packet_index| {
        const input_index = input_indices[packet_index];
        const stream = registry.get(writes[input_index].stream_id) orelse
            return error.UnknownStream;
        committed_streams[packet_index] = stream;
        committed_offsets[packet_index] = std.math.add(
            u64,
            stream.send_offset,
            byte_counts[packet_index],
        ) catch return error.IntegerOverflow;
        committed_bytes[packet_index] = std.math.add(
            u64,
            stream.bytes_sent,
            byte_counts[packet_index],
        ) catch return error.IntegerOverflow;
    }

    try ensureDeadline(connection, deadline);
    const sent = try connection.sendManyProgressAt(
        packets[0..packet_count],
        monotonicNowNs(connection),
    );
    if (sent.sent_count > packet_count or
        sent.sent_count > sent.protected_count)
    {
        return error.Unexpected;
    }

    for (0..sent.sent_count) |packet_index| {
        const input_index = input_indices[packet_index];
        const stream = committed_streams[packet_index];
        stream.send_offset = committed_offsets[packet_index];
        stream.bytes_sent = committed_bytes[packet_index];
        flow_send.commit(registry, byte_counts[packet_index]);
        counts[input_index] = byte_counts[packet_index];
    }
    if (sent.sent_count == 0 and sent.send_error == null) {
        return error.Unexpected;
    }
    return .{
        .progressed = sent.sent_count,
        .send_error = sent.send_error,
    };
}

fn ensureDeadline(
    connection: *quic.one_rtt.Connection,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!void {
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
    }
}

fn monotonicNowNs(connection: *const quic.one_rtt.Connection) u64 {
    const timestamp = std.Io.Clock.awake.now(connection.endpoint.io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

fn hasApplicationData(writes: []const Write) bool {
    for (writes) |item| if (item.data.len != 0) return true;
    return false;
}

const OrderedWrite = struct {
    input_index: usize,
    priority: i32,
    byte_count: usize,
    send_offset: u64,
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
            .send_offset = stream.send_offset,
        });
    }
    for (selected[0..selected_count], 0..) |item, packet_index| {
        const input = writes[item.input_index];
        frames[packet_index][0] = .{ .stream = .{
            .stream_id = input.stream_id,
            .offset = item.send_offset,
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
    return stagePrefixAwareBatchWith(
        connection,
        registry,
        session_id,
        writes,
        packet_limit,
        frames,
        packets,
        input_indices,
        byte_counts,
        stream_runtime.prepare,
        null,
    );
}

fn stagePrefixAwareBatchOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    packet_limit: usize,
    frames: *[quic.one_rtt.max_batch_packets][1]quic.Frame,
    packets: *[quic.one_rtt.max_batch_packets][]const quic.Frame,
    input_indices: *[quic.one_rtt.max_batch_packets]usize,
    byte_counts: *[quic.one_rtt.max_batch_packets]usize,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!usize {
    return stagePrefixAwareBatchWith(
        connection,
        registry,
        session_id,
        writes,
        packet_limit,
        frames,
        packets,
        input_indices,
        byte_counts,
        stream_runtime.prepareOnce,
        deadline,
    );
}

fn stagePrefixAwareBatchWith(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    session_id: webtransport.SessionId,
    writes: []const Write,
    packet_limit: usize,
    frames: *[quic.one_rtt.max_batch_packets][1]quic.Frame,
    packets: *[quic.one_rtt.max_batch_packets][]const quic.Frame,
    input_indices: *[quic.one_rtt.max_batch_packets]usize,
    byte_counts: *[quic.one_rtt.max_batch_packets]usize,
    comptime prepare_stream: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) TimeoutError!usize {
    var packet_count: usize = 0;
    const selection_epoch = registry.beginBatchEpoch();
    while (packet_count < packet_limit) {
        try ensureDeadline(connection, deadline);
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
        const stream = try prepare_stream(
            connection,
            registry,
            session_id,
            item.stream_id,
        );
        const count = @min(
            item.data.len,
            sendableBytes(connection.streamSendCredit(item.stream_id)),
        );
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
    pub const StageSummary = struct {
        packet_count: usize,
        checksum: u64,
    };

    /// Stage the production steady-state path and consume its descriptors.
    /// This deliberately performs no socket I/O and commits no stream state,
    /// so a benchmark can isolate selection and frame construction cost.
    pub fn stageSteady(
        connection: *quic.one_rtt.Connection,
        registry: *webtransport.StreamRegistry,
        writes: []const Write,
    ) Error!StageSummary {
        var frames: [quic.one_rtt.max_batch_packets][1]quic.Frame = undefined;
        var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
            undefined;
        var input_indices: [quic.one_rtt.max_batch_packets]usize = undefined;
        var byte_counts: [quic.one_rtt.max_batch_packets]usize = undefined;
        const packet_count = try stageSteadyBatch(
            connection,
            registry,
            writes,
            @min(writes.len, quic.one_rtt.max_batch_packets),
            &frames,
            &packets,
            &input_indices,
            &byte_counts,
        );
        var checksum: u64 = 0;
        for (0..packet_count) |packet_index| {
            const frame = frames[packet_index][0].stream;
            checksum +%= frame.stream_id;
            checksum +%= frame.offset;
            checksum +%= frame.data.len;
            checksum +%= input_indices[packet_index];
            checksum +%= byte_counts[packet_index];
            std.mem.doNotOptimizeAway(packets[packet_index].ptr);
        }
        return .{
            .packet_count = packet_count,
            .checksum = checksum,
        };
    }

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
