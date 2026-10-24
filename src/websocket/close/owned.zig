//! Close diagnostics may own a copied reason or a transferred frame payload.
const std = @import("std");
const websocket = @import("../mod.zig");

pub const OwnedCloseFrame = struct {
    code: websocket.CloseCode,
    reason: []u8,
    /// Original allocation when `reason` is a view after the two-byte code.
    /// Copying parsers and caller-constructed values own `reason` directly.
    allocation: ?[]u8 = null,

    pub fn deinit(self: *OwnedCloseFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.allocation orelse self.reason);
        self.* = undefined;
    }
};

/// Validate before taking ownership. On success the frame is consumed,
/// including an empty Close payload; on error the caller still owns it.
pub fn take(frame: *websocket.Frame, allocator: std.mem.Allocator) websocket.Error!?OwnedCloseFrame {
    if (frame.header.opcode != .close) return error.InvalidFrame;
    const parsed = try websocket.parseClosePayload(frame.payload);
    const result: ?OwnedCloseFrame = if (parsed) |value| .{
        .code = value.code,
        .reason = frame.payload[2..],
        .allocation = frame.payload,
    } else null;
    if (result == null) allocator.free(frame.payload);
    frame.* = undefined;
    return result;
}

test "WebSocket owned Close transfers the payload allocation without copying" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "", "diagnosis", "snowman \xe2\x98\x83" }) |reason| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        var payload: [125]u8 = undefined;
        const close_payload = try websocket.writeClosePayloadInto(&payload, .{ .code = .going_away, .reason = reason });
        try websocket.writeFrame(&encoded, allocator, .close, close_payload, .{});
        var frame = try websocket.parseFrame(allocator, encoded.items);
        const original = frame.payload;
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        var close = (take(&frame, failing.allocator()) catch |err| {
            frame.deinit(allocator);
            return err;
        }).?;
        defer close.deinit(allocator);
        try std.testing.expectEqual(original.ptr, close.allocation.?.ptr);
        try std.testing.expectEqual(original.len, close.allocation.?.len);
        try std.testing.expectEqual(original[2..].ptr, close.reason.ptr);
        try std.testing.expectEqualStrings(reason, close.reason);
        try std.testing.expect(!failing.has_induced_failure);
    }
}

test "WebSocket owned Close rejects invalid payloads without taking ownership" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "\x03", "\x03\xed", "\x03\xe8\xff" }) |payload| {
        var frame: websocket.Frame = .{
            .header = .{ .fin = true, .opcode = .close, .masked = false, .payload_len = payload.len, .mask_key = null, .header_len = 2 },
            .payload = try allocator.dupe(u8, payload),
            .consumed = payload.len + 2,
        };
        defer frame.deinit(allocator);
        const original = frame.payload;
        if (take(&frame, allocator)) |_| return error.TestUnexpectedResult else |_| {}
        try std.testing.expectEqual(original.ptr, frame.payload.ptr);
        try std.testing.expectEqualSlices(u8, payload, frame.payload);
    }
    var empty: websocket.Frame = .{
        .header = .{ .fin = true, .opcode = .close, .masked = false, .payload_len = 0, .mask_key = null, .header_len = 2 },
        .payload = try allocator.alloc(u8, 0),
        .consumed = 2,
    };
    try std.testing.expect((try take(&empty, allocator)) == null);
}
