//! Padding release and low-watermark refill share one WINDOW_UPDATE plan.
const std = @import("std");

pub const Increments = struct {
    connection: ?u31,
    stream: ?u31,
};

pub fn plan(connection_available: usize, stream_available: usize, connection_target: usize, stream_target: usize, padding_bytes: u9, end_stream: bool) Increments {
    return .{
        .connection = increment(connection_available, connection_target, padding_bytes),
        .stream = if (end_stream) null else increment(stream_available, stream_target, padding_bytes),
    };
}

fn increment(available: usize, target: usize, padding_bytes: u9) ?u31 {
    const refill = if (available <= target / 2 and available < target) target - available else 0;
    const amount = @max(refill, @as(usize, padding_bytes));
    return if (amount == 0) null else @intCast(amount);
}

test "HTTP/2 padding credit merges with low-watermark refills and final stream closure" {
    try std.testing.expectEqual(Increments{ .connection = 3, .stream = 3 }, plan(65_530, 65_530, 65_535, 65_535, 3, false));
    try std.testing.expectEqual(Increments{ .connection = 32_771, .stream = 4 }, plan(32_764, 0, 65_535, 4, 3, false));
    try std.testing.expectEqual(Increments{ .connection = 3, .stream = null }, plan(65_532, 1, 65_535, 4, 3, true));
    try std.testing.expectEqual(Increments{ .connection = 1, .stream = 1 }, plan(65_534, 65_534, 65_535, 65_535, 1, false));
    try std.testing.expectEqual(Increments{ .connection = null, .stream = null }, plan(65_535, 0, 65_535, 4, 0, true));
    try std.testing.expectEqual(Increments{ .connection = 256, .stream = 256 }, plan(65_279, 65_279, 65_535, 65_535, 256, false));
}
