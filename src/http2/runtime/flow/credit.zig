const std = @import("std");

/// Credit owned by one stack-based message reader. Track the net DATA debit
/// after normal refills and rejection refunds, excluding adaptive grants, so
/// abandoning the reader can return exactly the credit it still owns.
pub const Tracker = struct {
    unreleased_connection_bytes: usize = 0,

    pub fn observe(self: *Tracker, before: i64, after: i64, adaptive_increment: u31) void {
        var controls = [_]Tracker{self.*};
        // Held receive credit is bounded by the HTTP/2 connection window.
        account(&controls, 0, before, after, adaptive_increment) catch unreachable;
        self.* = controls[0];
    }
};

/// Account only credit still held after message processing. A rejected DATA
/// frame or callback can already return its exact payload credit; counting
/// that payload again would refund it twice during stream reset cleanup.
pub fn account(controls: anytype, state_index: usize, before: i64, after: i64, adaptive_increment: u31) error{MessageTooLarge}!void {
    // An adaptive grant adds new capacity; it does not release DATA already
    // held by any stream. Remove the actual wire grant before observing how
    // much existing capacity DATA processing consumed or returned.
    const after_without_growth = after - @as(i64, adaptive_increment);
    if (after_without_growth > before) {
        // The connection's low-watermark update returned all held credit.
        for (controls) |*control| control.unreleased_connection_bytes = 0;
    } else if (after_without_growth < before) {
        const control = &controls[state_index];
        control.unreleased_connection_bytes = std.math.add(
            usize,
            control.unreleased_connection_bytes,
            @intCast(before - after_without_growth),
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
    try account(&controls, 0, 65525, 65525, 0);
    try std.testing.expectEqual(@as(usize, 3), controls[0].unreleased_connection_bytes);
    try std.testing.expectEqual(@as(usize, 7), controls[1].unreleased_connection_bytes);
    try account(&controls, 0, 65525, 65520, 0);
    try std.testing.expectEqual(@as(usize, 8), controls[0].unreleased_connection_bytes);
    try account(&controls, 1, 32765, 65535, 0);
    for (controls) |control| try std.testing.expectEqual(@as(usize, 0), control.unreleased_connection_bytes);
}

test "HTTP/2 independent response credit distinguishes adaptive grants from returned DATA" {
    const Control = struct { unreleased_connection_bytes: usize };
    var controls = [_]Control{
        .{ .unreleased_connection_bytes = 3 },
        .{ .unreleased_connection_bytes = 7 },
    };
    // Three DATA bytes and a two-byte grant appear as a one-byte debit.
    try account(&controls, 0, 65525, 65524, 2);
    try std.testing.expectEqual(@as(usize, 6), controls[0].unreleased_connection_bytes);
    // A larger grant must still retain that frame's two-byte debit.
    try account(&controls, 1, 65524, 65527, 5);
    try std.testing.expectEqual(@as(usize, 9), controls[1].unreleased_connection_bytes);
    // Rejected DATA is fully returned while a grant advances the window.
    try account(&controls, 0, 65527, 65529, 2);
    try std.testing.expectEqual(@as(usize, 6), controls[0].unreleased_connection_bytes);
    try std.testing.expectEqual(@as(usize, 9), controls[1].unreleased_connection_bytes);
    // A refill still releases prior DATA even when combined with growth.
    try account(&controls, 0, 32765, 65537, 2);
    for (controls) |control| try std.testing.expectEqual(@as(usize, 0), control.unreleased_connection_bytes);
}
