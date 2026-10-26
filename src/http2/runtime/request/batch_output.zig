//! Staged batch output records commitment for deadline and retry decisions.
const std = @import("std");

pub const Progress = struct {
    submitted: bool = false,
    committed: usize = 0,

    pub fn canDiscard(self: Progress, transport: anytype) bool {
        return self.committed == 0 and !transport.hasPendingWrite();
    }
};

pub fn bytes(transport: anytype, encoded: []const u8, deadline: ?std.Io.Clock.Timestamp, progress: *Progress) !void {
    progress.* = .{};
    if (encoded.len == 0) return;
    progress.submitted = true;
    if (deadline) |absolute| {
        try transport.writeAllWithDeadline(encoded, &progress.committed, absolute);
    } else {
        try transport.writeAll(encoded);
        progress.committed = encoded.len;
    }
}

pub fn parts(allocator: std.mem.Allocator, transport: anytype, segments: []const []const u8, scratch: *std.ArrayList(u8), deadline: ?std.Io.Clock.Timestamp, progress: *Progress) !void {
    progress.* = .{};
    if (deadline != null) {
        scratch.clearRetainingCapacity();
        for (segments) |segment| try scratch.appendSlice(allocator, segment);
        return bytes(transport, scratch.items, deadline, progress);
    }
    progress.submitted = true;
    if (segments.len == 2) try transport.writeAllParts(segments[0], segments[1]) else try transport.writeAllSlices(segments);
    for (segments) |segment| progress.committed += segment.len;
}

/// Undo only a round that committed no bytes. Stream IDs and already-written
/// request heads remain owned by the higher-level per-stream deadline driver.
pub fn undoRound(connection: anytype, views: anytype, offsets: []usize, reserved: []const usize, remaining_streams: *usize, comptime Hooks: anytype) void {
    var total: usize = 0;
    for (views, offsets, reserved) |view, *offset, amount| {
        if (amount == 0) continue;
        if (offset.* == view.body.len) remaining_streams.* += 1;
        offset.* -= amount;
        total += amount;
        (Hooks.window(connection, view.stream_id) catch unreachable).update(@intCast(amount)) catch unreachable;
    }
    connection.send_connection_window.update(@intCast(total)) catch unreachable;
}
