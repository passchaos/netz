//! Blocking DATA writes with exact per-contribution commit boundaries.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const sender = @import("body.zig");
const outbound = @import("../stream/outbound_body.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const Error = @import("../error.zig").ReceiveTimeoutError;

pub const Result = enum { complete, cancelled };

fn capacity(connection: *quic.one_rtt.Connection, id: u62, remaining: usize, options: anytype) usize {
    const credit = connection.streamSendCredit(id);
    return sender.responseBodySendCapacity(
        remaining,
        std.math.cast(usize, credit.connection) orelse std.math.maxInt(usize),
        std.math.cast(usize, credit.stream) orelse std.math.maxInt(usize),
        credit.congestion,
        credit.max_datagram_size,
        sender.pacedBodyChunkLimit(options),
    );
}

/// Each contribution fits the current path, stream/connection credit and
/// congestion budget. It commits atomically, so a later deadline interruption
/// leaves progress at an HTTP/3 DATA boundary and the caller can send its suffix.
pub fn write(connection: *quic.one_rtt.Connection, bodies: *outbound.Set, options: anytype, context: anytype, id: u62, data: []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp, progress: anytype, comptime hooks: anytype) Error!Result {
    progress.* = .{};
    const current = bodies.find(id) orelse return error.UnexpectedStream;
    var validation = current.*;
    try bodies.prepareChunkForEntry(&validation, data.len, fin);
    if (data.len == 0 and !fin) return .complete;
    while (progress.committed_bytes < data.len or (fin and !progress.fin_committed)) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        if (try hooks.before(context, id, deadline)) return .cancelled;
        const remaining = data.len - progress.committed_bytes;
        var count = capacity(connection, id, remaining, options);
        if (remaining != 0 and count == 0) {
            try hooks.receive(context, id, deadline);
            continue;
        }
        while (true) {
            const last = count == remaining;
            sender.trySendConnectionBodyChunk(connection, bodies, id, data[progress.committed_bytes..][0..count], fin and last, options) catch |err| switch (err) {
                error.DatagramTooLarge => {
                    if (count <= 1) return err;
                    count = @max(@as(usize, 1), count / 2);
                    continue;
                },
                error.PacingLimited => {
                    if (deadline) |absolute| try connection.waitForPacingAvailabilityWithDeadline(absolute) else try connection.waitForPacingAvailability();
                    continue;
                },
                error.FlowControlBlocked, error.CongestionLimited => {
                    try hooks.receive(context, id, deadline);
                    break;
                },
                else => return err,
            };
            progress.committed_bytes += count;
            progress.fin_committed = fin and last;
            if (progress.fin_committed) try hooks.finish(context, id);
            break;
        }
    }
    return .complete;
}

/// The input slices stay borrowed. Contributions span slice boundaries, and
/// neither a blocked attempt nor a deadline advances the staged slice cursor.
pub fn writeParts(connection: *quic.one_rtt.Connection, bodies: *outbound.Set, options: anytype, context: anytype, id: u62, parts: []const []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp, progress: anytype, comptime hooks: anytype) Error!Result {
    progress.* = .{};
    var total: usize = 0;
    for (parts) |part| total = std.math.add(usize, total, part.len) catch return error.InvalidContentLength;
    const current = bodies.find(id) orelse return error.UnexpectedStream;
    var validation = current.*;
    try bodies.prepareChunkForEntry(&validation, total, fin);
    if (total == 0) return write(connection, bodies, options, context, id, &.{}, fin, deadline, progress, hooks);
    if (options.max_frames_per_packet < 2 or options.max_stream_frame_data == 0) {
        var sent: usize = 0;
        for (parts) |part| {
            if (part.len == 0) continue;
            var local: @TypeOf(progress.*) = .{};
            const result = write(connection, bodies, options, context, id, part, fin and sent + part.len == total, deadline, &local, hooks) catch |err| {
                progress.committed_bytes += local.committed_bytes;
                progress.fin_committed = local.fin_committed;
                return err;
            };
            progress.committed_bytes += local.committed_bytes;
            progress.fin_committed = local.fin_committed;
            if (result == .cancelled) return result;
            sent += part.len;
        }
        return .complete;
    }
    var cursor = sender.BodyPartCursor{ .parts = parts };
    var descriptors: [sender.max_paced_body_part_descriptors][]const u8 = undefined;
    while (!cursor.done()) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        if (try hooks.before(context, id, deadline)) return .cancelled;
        var count = capacity(connection, id, total - progress.committed_bytes, options);
        if (count == 0) {
            try hooks.receive(context, id, deadline);
            continue;
        }
        while (true) {
            var staged = cursor;
            const chunk = staged.next(&descriptors, count, options.max_stream_frame_data);
            const last = staged.done();
            sender.trySendConnectionBodyParts(connection, bodies, id, chunk, fin and last, options) catch |err| switch (err) {
                error.DatagramTooLarge => {
                    if (count <= 1) return err;
                    count = @max(@as(usize, 1), count / 2);
                    continue;
                },
                error.PacingLimited => {
                    if (deadline) |absolute| try connection.waitForPacingAvailabilityWithDeadline(absolute) else try connection.waitForPacingAvailability();
                    continue;
                },
                error.FlowControlBlocked, error.CongestionLimited => {
                    try hooks.receive(context, id, deadline);
                    break;
                },
                else => return err,
            };
            for (chunk) |part| progress.committed_bytes += part.len;
            progress.fin_committed = fin and last;
            cursor = staged;
            if (progress.fin_committed) try hooks.finish(context, id);
            break;
        }
    }
    return .complete;
}
