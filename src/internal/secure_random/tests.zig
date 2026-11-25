//! Deterministic entropy cancellation, including the real zio offload path.
const std = @import("std");
const entropy = @import("../secure_random.zig");

pub const Probe = struct {
    protection: std.Io.CancelProtection = .unblocked,
    pending_cancel: bool = false,
    cancel_during_fill: bool = false,
    fail_entropy: bool = false,
    calls: usize = 0,
    protected_fill: bool = false,

    fn context(userdata: ?*anyopaque) *Probe {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn swap(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
        const self = context(userdata);
        const old = self.protection;
        self.protection = new;
        return old;
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        const self = context(userdata);
        if (self.protection == .unblocked and self.pending_cancel) {
            self.pending_cancel = false;
            return error.Canceled;
        }
    }
    fn random(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        const self = context(userdata);
        self.calls += 1;
        self.protected_fill = self.protection == .blocked;
        if (self.cancel_during_fill) self.pending_cancel = true;
        // The backend may yield and check cancellation before submitting work.
        try check(userdata);
        if (self.fail_entropy) return error.EntropyUnavailable;
        @memset(buffer, 0xa5);
    }
    const table: std.Io.VTable = blk: {
        var result = std.Io.failing.vtable.*;
        result.swapCancelProtection = swap;
        result.checkCancel = check;
        result.randomSecure = random;
        break :blk result;
    };
    pub fn io(self: *Probe) std.Io {
        return .{ .userdata = self, .vtable = &table };
    }
};

pub fn rejectsPending() !void {
    var probe: Probe = .{ .pending_cancel = true };
    var buffer: [32]u8 = @splat(0x55);
    try std.testing.expectError(error.Canceled, entropy.fill(probe.io(), &buffer));
    try std.testing.expectEqual(@as(usize, 0), probe.calls);
    try std.testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0x55))), &buffer);
    try std.testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);
}

pub fn joinsCanceledWork() !void {
    var probe: Probe = .{ .cancel_during_fill = true };
    var buffer: [32]u8 = undefined;
    try std.testing.expectError(error.Canceled, entropy.fill(probe.io(), &buffer));
    try std.testing.expectEqual(@as(usize, 1), probe.calls);
    try std.testing.expect(probe.protected_fill);
    try std.testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0xa5))), &buffer);
    try std.testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);
    try std.testing.expect(!probe.pending_cancel);
}

pub fn restoresProtection() !void {
    inline for (.{ false, true }) |fail| {
        var probe: Probe = .{ .fail_entropy = fail };
        var buffer: [16]u8 = undefined;
        if (fail) {
            try std.testing.expectError(error.EntropyUnavailable, entropy.fill(probe.io(), &buffer));
        } else {
            try entropy.fill(probe.io(), &buffer);
            try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xa5))), &buffer);
        }
        try std.testing.expect(probe.protected_fill);
        try std.testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);
    }
    var probe: Probe = .{ .fail_entropy = true, .cancel_during_fill = true };
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.EntropyUnavailable, entropy.fill(probe.io(), &buffer));
    try std.testing.expectEqual(std.Io.CancelProtection.unblocked, probe.protection);
    try std.testing.expectError(error.Canceled, probe.io().checkCancel());
}

pub fn preservesEnclosingGuard() !void {
    var probe: Probe = .{ .protection = .blocked, .pending_cancel = true };
    var buffer: [16]u8 = undefined;
    try entropy.fill(probe.io(), &buffer);
    try std.testing.expectEqual(std.Io.CancelProtection.blocked, probe.protection);
    try std.testing.expect(probe.pending_cancel);
    _ = probe.io().swapCancelProtection(.unblocked);
    try std.testing.expectError(error.Canceled, probe.io().checkCancel());
}

pub fn zioOffloadCancellation() !void {
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const Delegate = struct {
        io: std.Io,
        calls: usize = 0,
        ready: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        fn context(userdata: ?*anyopaque) *@This() {
            return @ptrCast(@alignCast(userdata.?));
        }
        fn swap(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
            return context(userdata).io.swapCancelProtection(new);
        }
        fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
            try context(userdata).io.checkCancel();
        }
        fn random(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
            const self = context(userdata);
            self.calls += 1;
            // Pause at the backend boundary until a real task cancel arrives.
            self.ready.set(self.io);
            self.release.waitUncancelable(self.io);
            try self.io.randomSecure(buffer);
        }
        fn run(observed: std.Io) !void {
            var buffer: [32]u8 = undefined;
            try std.testing.expectError(error.Canceled, entropy.fill(observed, &buffer));
            // Cancellation is consumed once and the guard has been restored.
            try observed.checkCancel();
            observed.recancel();
            try std.testing.expectError(error.Canceled, observed.checkCancel());
        }
        fn recancel(userdata: ?*anyopaque) void {
            context(userdata).io.recancel();
        }
    };
    var delegate: Delegate = .{ .io = io };
    var table = std.Io.failing.vtable.*;
    table.swapCancelProtection = Delegate.swap;
    table.checkCancel = Delegate.check;
    table.recancel = Delegate.recancel;
    table.randomSecure = Delegate.random;
    const observed: std.Io = .{ .userdata = &delegate, .vtable = &table };
    var worker = try @import("zio").spawn(Delegate.run, .{observed});
    errdefer {
        delegate.release.set(io);
        worker.cancel();
    }
    try delegate.ready.wait(io);
    // Request cancellation without joining while the backend gate is closed.
    worker.awaitable.?.cancel();
    delegate.release.set(io);
    try worker.join();
    try std.testing.expectEqual(@as(usize, 1), delegate.calls);
}
