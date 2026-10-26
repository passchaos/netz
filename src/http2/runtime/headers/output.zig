//! A field block owns the shared wire until its final CONTINUATION completes.
const std = @import("std");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");

pub fn writeBlock(
    allocator: std.mem.Allocator,
    transport: anytype,
    stream_id: u31,
    block: []const u8,
    end_stream: bool,
    chunk_size: usize,
    batch: *std.ArrayList(u8),
    deadline: ?std.Io.Clock.Timestamp,
    submitted: *bool,
) !void {
    submitted.* = false;
    if (deadline) |absolute| {
        // Prepare every frame before submission: allocation failure must not
        // leave a peer waiting for CONTINUATION or change live HPACK state.
        batch.clearRetainingCapacity();
        try wire.appendHeaderBlock(batch, allocator, stream_id, block, end_stream, chunk_size);
        var committed: usize = 0;
        submitted.* = true;
        try transport.writeAllWithDeadline(batch.items, &committed, absolute);
        return;
    }
    const first_len = @min(block.len, chunk_size);
    var offset = first_len;
    submitted.* = true;
    try frame_io.writeTransport(allocator, transport, .headers, @as(u8, if (offset == block.len) 0x4 else 0) | @as(u8, if (end_stream) 0x1 else 0), stream_id, block[0..first_len]);
    while (offset < block.len) {
        const end = @min(block.len, offset + chunk_size);
        try frame_io.writeTransport(allocator, transport, .continuation, if (end == block.len) 0x4 else 0, stream_id, block[offset..end]);
        offset = end;
    }
}
