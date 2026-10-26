//! Bounded DATA bursts keep socket output under the same flow-control budget.
const std = @import("std");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");

pub fn writeBurst(
    comptime max_frames: usize,
    allocator: std.mem.Allocator,
    transport: anytype,
    stream_id: u31,
    payload: []const u8,
    end_stream: bool,
    chunk_size: usize,
    batch: *std.ArrayList(u8),
    deadline: ?std.Io.Clock.Timestamp,
    submitted: *bool,
) !void {
    submitted.* = false;
    std.debug.assert(payload.len != 0 and payload.len <= chunk_size *| max_frames);
    var headers: [max_frames][http2.FrameHeader.encoded_len]u8 = undefined;
    var parts: [2 * max_frames][]const u8 = undefined;
    var part_count: usize = 0;
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(payload.len, offset + chunk_size);
        const index = part_count / 2;
        try wire.encodeHeader(&headers[index], .data, if (end_stream and end == payload.len) 0x1 else 0, stream_id, end - offset);
        parts[part_count] = &headers[index];
        parts[part_count + 1] = payload[offset..end];
        part_count += 2;
        offset = end;
    }
    return submit(allocator, transport, parts[0..part_count], batch, deadline, submitted);
}

pub fn submit(allocator: std.mem.Allocator, transport: anytype, parts: []const []const u8, batch: *std.ArrayList(u8), deadline: ?std.Io.Clock.Timestamp, submitted: *bool) !void {
    submitted.* = false;
    if (deadline) |absolute| {
        batch.clearRetainingCapacity();
        for (parts) |part| try batch.appendSlice(allocator, part);
        var committed: usize = 0;
        submitted.* = true;
        try transport.writeAllWithDeadline(batch.items, &committed, absolute);
    } else {
        submitted.* = true;
        if (parts.len == 2) try transport.writeAllParts(parts[0], parts[1]) else try transport.writeAllSlices(parts);
    }
}

pub fn writeEmpty(allocator: std.mem.Allocator, transport: anytype, stream_id: u31, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) !void {
    if (deadline) |absolute| {
        var committed: usize = 0;
        try frame_io.writeTransportWithDeadline(allocator, transport, .data, if (end_stream) 0x1 else 0, stream_id, &.{}, &committed, absolute);
    } else try frame_io.writeTransport(allocator, transport, .data, if (end_stream) 0x1 else 0, stream_id, &.{});
}
