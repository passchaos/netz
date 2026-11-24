//! Shared admission before frame staging, transport writes or payload copies.
const std = @import("std");
const websocket = @import("../mod.zig");

pub fn outbound(options: anytype, opcode: websocket.Opcode, payload_len: usize) websocket.Error!void {
    var storage: [websocket.max_frame_header_len]u8 = undefined;
    const header = try websocket.writeFrameHeaderForLengthInto(&storage, opcode, payload_len, .{
        .mask_key = if (options.role == .client) .{ 0, 0, 0, 0 } else null,
    });
    if (!opcode.isControl() and payload_len > options.max_message_bytes) return error.PayloadTooLarge;
    const wire_len = std.math.add(usize, header.len, payload_len) catch return error.PayloadTooLarge;
    if (wire_len > options.max_frame_bytes) return error.PayloadTooLarge;
}

pub fn inbound(options: anytype, assembler: anytype, header: websocket.FrameHeader) websocket.Error!usize {
    try websocket.validateFrameHeader(header, .{
        .expect_mask = if (options.role == .server) .masked else .unmasked,
        .validate_utf8 = false,
    });
    const wire_len = try header.wireLen();
    if (wire_len > options.max_frame_bytes) return error.PayloadTooLarge;
    try assembler.validateFrameHeader(header);
    return wire_len;
}

pub fn requiredHeaderLen(prefix: [2]u8) usize {
    const extended: usize = switch (prefix[1] & 0x7f) {
        126 => 2,
        127 => 8,
        else => 0,
    };
    return 2 + extended + @as(usize, if (prefix[1] & 0x80 != 0) 4 else 0);
}

/// Control traffic remains available even with a zero application budget.
/// Small budgets also cap read-ahead; the default keeps its 16 KiB batching.
pub fn stagingLimit(options: anytype) usize {
    const message_window = @max(options.max_message_bytes, 125) +| websocket.max_frame_header_len;
    return @max(websocket.max_frame_header_len, @min(options.max_frame_bytes, message_window));
}
