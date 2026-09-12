const std = @import("std");
const websocket = @import("../../mod.zig");
const common = @import("../common.zig");

pub const FragmentRange = struct { start: usize, end: usize };

pub fn canSendOpcode(
    opcode: websocket.Opcode,
    close_sent: bool,
    close_received: bool,
) bool {
    if (close_sent) return false;
    if (close_received and opcode != .close) return false;
    return true;
}

pub fn finishIncomingMessage(
    allocator: std.mem.Allocator,
    message: websocket.MessageAssembler.Message,
    max_message_bytes: usize,
) !common.OwnedMessage {
    var payload = message.payload;
    if (message.compressed) {
        errdefer allocator.free(message.payload);
        payload = try websocket.decompressMessage(
            allocator,
            message.payload,
            max_message_bytes,
        );
        allocator.free(message.payload);
    }
    errdefer allocator.free(payload);
    if (message.opcode == .text and !message.utf8_validated and
        !std.unicode.utf8ValidateSlice(payload))
    {
        return error.InvalidUtf8;
    }
    return .{
        .opcode = message.opcode,
        .payload = payload,
        .was_compressed = message.compressed,
    };
}

pub fn compressedFragmentRange(
    total_len: usize,
    frame_count: usize,
    index: usize,
) FragmentRange {
    std.debug.assert(frame_count != 0);
    std.debug.assert(index < frame_count);
    const base = total_len / frame_count;
    const extra = total_len % frame_count;
    const start = index * base + @min(index, extra);
    const len = base + @intFromBool(index < extra);
    return .{ .start = start, .end = start + len };
}

test "WebSocket incoming compressed invalid UTF-8 releases both buffers once" {
    const allocator = std.testing.allocator;
    const invalid_utf8 = "\xc0\x80";
    const compressed = try websocket.compressMessage(allocator, invalid_utf8);
    // Ownership transfers to finishIncomingMessage even on failure. The
    // testing allocator makes a leaked or double-freed compressed/decoded
    // buffer fail this test directly.
    try std.testing.expectError(
        error.InvalidUtf8,
        finishIncomingMessage(allocator, .{
            .opcode = .text,
            .payload = compressed,
            .compressed = true,
        }, 32),
    );
}
