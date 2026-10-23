const std = @import("std");

/// Account only credit still held after response processing. A rejected DATA
/// frame or callback can already return its exact payload credit; counting
/// that payload again would refund it twice during stream reset cleanup.
pub fn account(controls: anytype, state_index: usize, before: i64, after: i64) error{MessageTooLarge}!void {
    if (after > before) {
        // The connection's low-watermark update returned all held credit.
        for (controls) |*control| control.unreleased_connection_bytes = 0;
    } else if (after < before) {
        const control = &controls[state_index];
        control.unreleased_connection_bytes = std.math.add(
            usize,
            control.unreleased_connection_bytes,
            @intCast(before - after),
        ) catch return error.MessageTooLarge;
    }
}

test "HTTP/2 independent response credit excludes rejected DATA and preserves earlier content" {
    const Control = struct { unreleased_connection_bytes: usize };
    var controls = [_]Control{
        .{ .unreleased_connection_bytes = 3 },
        .{ .unreleased_connection_bytes = 7 },
    };
    // A rejected padded frame consumes five bytes and returns the same five.
    // Its zero net charge must not erase previously held content on any stream.
    try account(&controls, 0, 65525, 65525);
    try std.testing.expectEqual(@as(usize, 3), controls[0].unreleased_connection_bytes);
    try std.testing.expectEqual(@as(usize, 7), controls[1].unreleased_connection_bytes);
    try account(&controls, 0, 65525, 65520);
    try std.testing.expectEqual(@as(usize, 8), controls[0].unreleased_connection_bytes);
    try account(&controls, 1, 32765, 65535);
    for (controls) |control| try std.testing.expectEqual(@as(usize, 0), control.unreleased_connection_bytes);
}
