//! DATA access preserves failed-message ownership and reports consumed bytes
//! before attempting their receive-credit advertisement.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const stream_set = @import("../stream/set.zig");
const Reader = @import("../stream/reader.zig").Reader;
const Error = runtime_error.Error;

pub const Operation = enum { read, available, skip };

pub fn access(
    context: anytype,
    connection: *quic.one_rtt.Connection,
    streams: *stream_set.Set,
    pending: anytype,
    allocator: std.mem.Allocator,
    stream_id: u62,
    out: []u8,
    comptime operation: Operation,
    comptime single_attempt: bool,
    comptime progress: anytype,
    comptime retain: anytype,
) Error!?usize {
    try progress(context, stream_id, null);
    const entry = streams.find(stream_id) orelse return error.UnexpectedStream;
    if (entry.message_failure_pending) return null;
    if (operation != .available) {
        if (single_attempt) {
            releaseCapacityOnce(connection, &entry.reader) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return null,
                else => return err,
            };
        } else {
            try releaseCapacity(connection, &entry.reader);
        }
    }
    const count = switch (operation) {
        .read => entry.reader.readData(out),
        .available => entry.reader.availableDataBytes(),
        .skip => entry.reader.skipData(),
    } catch |err| {
        if (runtime_error.dataReadPeerError(err)) {
            // DATA validation fails before consuming payload or changing the
            // parser phase. Reserving here keeps healthy reads allocation-free
            // and makes allocation failure retryable against the same bytes.
            if (runtime_error.messageStreamErrorCode(err) != null) try pending.reserve(allocator);
            try retain(context, stream_id, err, null);
        }
        return err;
    };
    // The next read or event poll releases newly consumed bytes. A socket or
    // pacing failure after consumption must never hide the count from callers.
    return count;
}

pub fn releaseCapacity(connection: *quic.one_rtt.Connection, reader: *Reader) Error!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    try connection.releaseReceivedCapacity(reader.streamId(), amount);
    reader.markCredited(amount);
}

pub fn releaseCapacityOnce(connection: *quic.one_rtt.Connection, reader: *Reader) Error!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    try connection.tryReleaseReceivedCapacity(reader.streamId(), amount);
    reader.markCredited(amount);
}

pub fn releaseCapacityWithDeadline(
    connection: *quic.one_rtt.Connection,
    reader: *Reader,
    deadline: std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    try connection.releaseReceivedCapacityWithDeadline(
        reader.streamId(),
        amount,
        deadline,
    );
    reader.markCredited(amount);
}
