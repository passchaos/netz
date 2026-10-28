const std = @import("std");
const Retirements = @import("../retired_capacity.zig").Retirements;

test "deferred capacity retirement accumulates and drains each receipt once" {
    var retirements: Retirements = .{};
    var connections: usize = 5;
    retirements.retire(0);
    try std.testing.expectEqual(@as(usize, 0), retirements.drain(&connections));
    retirements.retire(2);
    retirements.retire(1);
    try std.testing.expectEqual(@as(usize, 5), connections);
    try std.testing.expectEqual(@as(usize, 3), retirements.drain(&connections));
    try std.testing.expectEqual(@as(usize, 2), connections);
    try std.testing.expectEqual(@as(usize, 0), retirements.drain(&connections));
    retirements.retire(2);
    try std.testing.expectEqual(@as(usize, 2), retirements.drain(&connections));
    try std.testing.expectEqual(@as(usize, 0), connections);
}

test "deferred capacity retirement survives concurrent publication and collection" {
    var retirements: Retirements = .{};
    var connections: usize = 4096;
    const Publisher = struct {
        fn run(value: *Retirements) void {
            for (0..1024) |_| value.retire(1);
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Publisher.run, .{&retirements});
        started += 1;
    }
    for (0..1024) |_| _ = retirements.drain(&connections);
    for (threads) |thread| thread.join();
    started = 0;
    _ = retirements.drain(&connections);
    try std.testing.expectEqual(@as(usize, 0), connections);
    try std.testing.expectEqual(@as(usize, 0), retirements.drain(&connections));
}
