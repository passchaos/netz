const std = @import("std");
const websocket = @import("../../../mod.zig");
const state = @import("../state.zig");

test "WebSocket message finalization owns failures and provenance" {
    const allocator = std.testing.allocator;
    const plain = "compressed provenance compressed provenance";
    const compressed = try websocket.compressMessage(allocator, plain);
    var message = try state.finishIncomingMessage(
        allocator,
        .{
            .opcode = .text,
            .payload = compressed,
            .compressed = true,
        },
        1024,
    );
    defer message.deinit(allocator);
    try std.testing.expect(message.was_compressed);
    try std.testing.expectEqualStrings(plain, message.payload);

    const bad_deflate = try allocator.dupe(u8, &.{ 0xff, 0xff, 0xff });
    try std.testing.expectError(
        error.InvalidFrame,
        state.finishIncomingMessage(allocator, .{
            .opcode = .text,
            .payload = bad_deflate,
            .compressed = true,
        }, 1024),
    );

    const bad_utf8 = try allocator.dupe(u8, "\xc0\x80");
    try std.testing.expectError(
        error.InvalidUtf8,
        state.finishIncomingMessage(allocator, .{
            .opcode = .text,
            .payload = bad_utf8,
            .compressed = false,
        }, 1024),
    );
}

test "WebSocket compressed fragment ranges are complete and balanced" {
    var previous_end: usize = 0;
    for (0..4) |index| {
        const range = state.compressedFragmentRange(10, 4, index);
        try std.testing.expectEqual(previous_end, range.start);
        try std.testing.expect(range.end - range.start == 2 or
            range.end - range.start == 3);
        previous_end = range.end;
    }
    try std.testing.expectEqual(@as(usize, 10), previous_end);
}

test "WebSocket send state permits only Close after peer Close" {
    try std.testing.expect(!state.canSendOpcode(.text, false, true));
    try std.testing.expect(!state.canSendOpcode(.binary, false, true));
    try std.testing.expect(!state.canSendOpcode(.ping, false, true));
    try std.testing.expect(state.canSendOpcode(.close, false, true));
    try std.testing.expect(!state.canSendOpcode(.close, true, true));
}
