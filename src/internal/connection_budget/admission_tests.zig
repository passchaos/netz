const std = @import("std");
const budget_mod = @import("../connection_budget.zig");

test "shared connection budget mutex admission preserves deadline and cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const budget = try budget_mod.Budget.create(std.testing.allocator, threaded.io(), 1);
    defer budget.deinit();
    try @import("../pool_admission_test_support.zig").exerciseBudget(budget, threaded.io());
}

test "shared connection budget allocation failure preserves reservation and unlocks admission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Reclaim = struct {
        fn run(_: *anyopaque) bool {
            return false;
        }
    };
    for ([_]bool{ false, true }) |reclaiming| {
        const budget = try budget_mod.Budget.create(std.testing.allocator, io, 1);
        defer {
            budget.allocator = std.testing.allocator;
            budget.deinit();
        }
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        budget.allocator = failing.allocator();
        try budget.tryReserve(null); // An available slot allocates no node.
        var waiter: budget_mod.Waiter = .{};
        defer budget.cancel(&waiter);
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        var context: u8 = 0;
        if (reclaiming) {
            try std.testing.expectError(error.OutOfMemory, budget.tryReserveReclaimingBefore(&waiter, .{ .context = &context, .reclaim = Reclaim.run }, deadline));
        } else {
            try std.testing.expectError(error.OutOfMemory, budget.tryReserveBefore(&waiter, deadline));
        }
        const acquired = budget.mutex.tryLock();
        if (acquired) budget.mutex.unlock(io) else budget.mutex.state.store(.unlocked, .release);
        try std.testing.expect(acquired);
        try std.testing.expectEqual(@as(usize, 1), budget.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
        try std.testing.expect(!waiter.linked and waiter.node == null);
        budget.release(1);
        // Returning capacity permits retry with the same failing allocator.
        try budget.tryReserveBefore(&waiter, deadline);
        budget.release(1);
    }
}
