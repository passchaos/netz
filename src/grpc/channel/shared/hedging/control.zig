//! Call-wide hedging commitment and transparent retry ownership.
const std = @import("std");
const call = @import("../../../call.zig");
const Status = @import("../../../wire.zig").Status;

/// Every scheduler, queued job, and endpoint using this control owns a reference.
pub const Control = struct {
    const no_winner = std.math.maxInt(u8);

    allocator: std.mem.Allocator,
    io: std.Io,
    refs: std.atomic.Value(usize) = .init(1),
    winning_index: std.atomic.Value(u8) = .init(no_winner),
    committed: std.Io.Event = .unset,
    transparent_used: std.atomic.Value(bool) = .init(false),
    non_fatal_mask: u32,

    pub fn create(allocator: std.mem.Allocator, io: std.Io, policy: call.HedgingPolicy) std.mem.Allocator.Error!*Control {
        var mask: u32 = 0;
        for (policy.non_fatal_status_codes) |status| mask |= statusBit(status);
        const self = try allocator.create(Control);
        self.* = .{ .allocator = allocator, .io = io, .non_fatal_mask = mask };
        return self;
    }

    pub fn retain(self: *Control) void {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    pub fn release(self: *Control) void {
        const previous = self.refs.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn winner(self: *const Control) ?u8 {
        const index = self.winning_index.load(.acquire);
        return if (index == no_winner) null else index;
    }

    /// The successful caller keeps its reference through event notification.
    pub fn commit(self: *Control, index: u8) bool {
        if (index == no_winner) return false;
        if (self.winning_index.cmpxchgStrong(no_winner, index, .acq_rel, .acquire) != null) return false;
        self.committed.set(self.io);
        return true;
    }

    pub fn isLoser(self: *const Control, index: u8) bool {
        return if (self.winner()) |committed_index| committed_index != index else false;
    }

    pub fn isNonFatal(self: *const Control, status: Status) bool {
        return self.non_fatal_mask & statusBit(status) != 0;
    }

    pub fn responseIsFatal(self: *const Control, response: call.UnaryResponse) bool {
        return response.was_dropped or response.status == .ok or !self.isNonFatal(response.status) or
            (if (response.transport) |transport| !transport.trailers_only else false);
    }

    pub fn errorIsFatal(self: *const Control, err: anyerror) bool {
        return !self.isNonFatal(.unavailable) or !canHedgeError(err);
    }

    pub fn takeTransparent(self: *Control, enabled: bool) bool {
        return enabled and self.transparent_used.cmpxchgStrong(false, true, .acq_rel, .acquire) == null;
    }

    fn statusBit(status: Status) u32 {
        return @as(u32, 1) << @as(u5, @intCast(@intFromEnum(status)));
    }
};

pub fn canHedgeError(err: anyerror) bool {
    return switch (err) {
        error.AddressUnavailable, error.BrokenPipe, error.ConnectionClosed, error.ConnectionRefused => true,
        error.ConnectionResetByPeer, error.ConnectionUnavailable, error.HostUnreachable, error.NameServerFailure => true,
        error.NetworkDown, error.NetworkUnreachable, error.NoAddressReturned, error.ReadFailed => true,
        error.SocketUnconnected, error.UnexpectedEof, error.UnknownHostName, error.WriteFailed => true,
        else => false,
    };
}

test "gRPC hedging control copies policy membership and classifies commitment" {
    var statuses: [2]Status = .{ .unavailable, .resource_exhausted };
    const control = try Control.create(std.testing.allocator, std.testing.io, .{
        .max_attempts = 2,
        .non_fatal_status_codes = &statuses,
    });
    defer control.release();
    @memset(&statuses, .ok);
    try std.testing.expect(control.isNonFatal(.unavailable));
    try std.testing.expect(control.isNonFatal(.resource_exhausted));
    try std.testing.expect(!control.isNonFatal(.ok));
    try std.testing.expect(!control.isNonFatal(.internal));
    var response: call.UnaryResponse = .{ .allocator = std.testing.allocator, .transport = null, .status = .unavailable, .status_message = &.{}, .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
    try std.testing.expect(!control.responseIsFatal(response)); // Legacy response_committed is true.
    response.transport = .{ .headers = &.{}, .status = 200, .body = &.{}, .trailers_only = true };
    try std.testing.expect(!control.responseIsFatal(response));
    response.transport.?.trailers_only = false;
    try std.testing.expect(control.responseIsFatal(response));
    response.transport = null;
    response.was_dropped = true;
    try std.testing.expect(control.responseIsFatal(response));
    response.was_dropped = false;
    response.status = .ok;
    try std.testing.expect(control.responseIsFatal(response));
    response.status = .internal;
    try std.testing.expect(control.responseIsFatal(response));
    try std.testing.expect(!control.errorIsFatal(error.ConnectionRefused));
    try std.testing.expect(!control.errorIsFatal(error.ConnectionResetByPeer));
    try std.testing.expect(control.errorIsFatal(error.OutOfMemory));
    try std.testing.expect(control.errorIsFatal(error.Timeout));
    try std.testing.expect(control.errorIsFatal(error.InvalidMetadata));
    const fatal_control = try Control.create(std.testing.allocator, std.testing.io, .{ .max_attempts = 2 });
    defer fatal_control.release();
    try std.testing.expect(fatal_control.errorIsFatal(error.ConnectionRefused));
}

test "gRPC hedging control outlives its creating owner and releases all references" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const control = try Control.create(allocator, std.testing.io, .{ .max_attempts = 2 });
            control.retain();
            control.release();
            defer control.release();
            try std.testing.expectEqual(@as(usize, 1), control.refs.load(.acquire));
            try std.testing.expectEqual(@as(?u8, null), control.winner());
            try std.testing.expect(!control.isLoser(1));
            try std.testing.expect(control.commit(1));
            try std.testing.expect(control.committed.isSet());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{});
}

test "gRPC hedging control disabled replay preserves the shared transparent budget" {
    const control = try Control.create(std.testing.allocator, std.testing.io, .{ .max_attempts = 2 });
    defer control.release();
    try std.testing.expect(!control.takeTransparent(false));
    try std.testing.expect(!control.transparent_used.load(.acquire));
    try std.testing.expect(control.takeTransparent(true));
    try std.testing.expect(!control.takeTransparent(true));
    try std.testing.expect(!control.takeTransparent(false));
    try std.testing.expect(!control.commit(255));
    try std.testing.expectEqual(@as(?u8, null), control.winner());
    try std.testing.expect(!control.committed.isSet());
}

test "gRPC hedging control has one concurrent winner and one call-wide transparent replay" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const control = try Control.create(std.testing.allocator, io, .{ .max_attempts = 5 });
    defer control.release();
    var start: std.Io.Event = .unset;
    var winners: std.atomic.Value(u8) = .init(0);
    var replays: std.atomic.Value(u8) = .init(0);
    const Attempt = struct {
        fn run(shared: *Control, gate: *std.Io.Event, index: u8, won: *std.atomic.Value(u8), replayed: *std.atomic.Value(u8)) void {
            defer shared.release();
            gate.wait(shared.io) catch return;
            if (shared.commit(index)) _ = won.fetchAdd(1, .monotonic);
            if (shared.takeTransparent(true)) _ = replayed.fetchAdd(1, .monotonic);
        }
    };
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    for (0..5) |index| {
        control.retain();
        group.concurrent(io, Attempt.run, .{ control, &start, @as(u8, @intCast(index)), &winners, &replays }) catch |err| {
            control.release();
            return err;
        };
    }
    start.set(io);
    try group.await(io);
    try std.testing.expectEqual(@as(u8, 1), winners.load(.acquire));
    try std.testing.expectEqual(@as(u8, 1), replays.load(.acquire));
    try std.testing.expect(control.committed.isSet());
    const winner = control.winner().?;
    for (0..5) |index| {
        const attempt_index: u8 = @intCast(index);
        try std.testing.expectEqual(attempt_index != winner, control.isLoser(attempt_index));
        try std.testing.expect(!control.commit(attempt_index));
    }
    try std.testing.expectEqual(@as(usize, 1), control.refs.load(.acquire));
}
