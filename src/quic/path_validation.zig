const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    NoPendingPathResponse,
    NoPendingPathChallenge,
    UnknownPathResponse,
} || std.mem.Allocator.Error;

pub const default_max_challenge_transmissions: u8 = 3;

pub const Challenge = struct {
    data: [8]u8,
    transmissions: u8 = 0,
    sent_time_ns: ?u64 = null,
    deadline_ns: ?u64 = null,
};

fn Fifo(comptime T: type) type {
    return struct {
        items: std.ArrayList(T) = .empty,
        head: usize = 0,

        const Self = @This();

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.items.deinit(allocator);
            self.* = undefined;
        }

        fn append(self: *Self, allocator: std.mem.Allocator, value: T) std.mem.Allocator.Error!void {
            self.compactIfEmpty();
            try self.items.append(allocator, value);
        }

        fn appendSlice(self: *Self, allocator: std.mem.Allocator, values: []const T) std.mem.Allocator.Error!void {
            self.compactIfEmpty();
            try self.items.appendSlice(allocator, values);
        }

        fn ensureUnusedCapacity(self: *Self, allocator: std.mem.Allocator, additional_count: usize) std.mem.Allocator.Error!void {
            self.compactIfEmpty();
            try self.items.ensureUnusedCapacity(allocator, additional_count);
        }

        fn appendAssumeCapacity(self: *Self, value: T) void {
            self.items.appendAssumeCapacity(value);
        }

        fn popFront(self: *Self) ?T {
            if (self.len() == 0) return null;
            const value = self.items.items[self.head];
            self.head += 1;
            self.compactIfEmpty();
            return value;
        }

        fn len(self: Self) usize {
            return self.items.items.len - self.head;
        }

        fn activeConst(self: Self) []const T {
            return self.items.items[self.head..];
        }

        fn compactIfEmpty(self: *Self) void {
            if (self.head != 0 and self.head == self.items.items.len) {
                self.items.clearRetainingCapacity();
                self.head = 0;
            }
        }
    };
}

pub const State = struct {
    allocator: std.mem.Allocator,
    pending_responses: Fifo([8]u8) = .{},
    pending_challenges: Fifo(Challenge) = .{},
    outstanding_challenges: std.ArrayList(Challenge) = .empty,
    failed_challenges: std.ArrayList(Challenge) = .empty,
    /// PATH_CHALLENGE/PATH_RESPONSE payloads are only 8 bytes, so keep value
    /// indexes for duplicate suppression and response matching. The FIFO lists
    /// still define send order, while these maps keep packet receive paths from
    /// scanning every queued/outstanding validation attempt.
    pending_response_index: std.AutoHashMapUnmanaged([8]u8, void) = .empty,
    pending_challenge_index: std.AutoHashMapUnmanaged([8]u8, void) = .empty,
    outstanding_challenge_index: std.AutoHashMapUnmanaged([8]u8, usize) = .empty,
    earliest_outstanding_deadline_ns: ?u64 = null,
    max_challenge_transmissions: u8 = default_max_challenge_transmissions,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.pending_responses.deinit(self.allocator);
        self.pending_challenges.deinit(self.allocator);
        self.outstanding_challenges.deinit(self.allocator);
        self.failed_challenges.deinit(self.allocator);
        self.pending_response_index.deinit(self.allocator);
        self.pending_challenge_index.deinit(self.allocator);
        self.outstanding_challenge_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clone(self: *const State, allocator: std.mem.Allocator) Error!State {
        var out = State.init(allocator);
        errdefer out.deinit();
        try out.pending_responses.appendSlice(allocator, self.pending_responses.activeConst());
        try out.pending_challenges.appendSlice(allocator, self.pending_challenges.activeConst());
        try out.outstanding_challenges.appendSlice(allocator, self.outstanding_challenges.items);
        try out.failed_challenges.appendSlice(allocator, self.failed_challenges.items);
        try out.rebuildIndexes();
        out.max_challenge_transmissions = self.max_challenge_transmissions;
        return out;
    }

    pub fn queueChallenge(self: *State, data: [8]u8) Error!void {
        if (self.outstanding_challenge_index.count() != 0 and
            self.outstanding_challenge_index.contains(data)) return;
        const slot = try self.pending_challenge_index.getOrPut(
            self.allocator,
            data,
        );
        if (slot.found_existing) return;
        errdefer _ = self.pending_challenge_index.remove(data);

        try self.pending_challenges.ensureUnusedCapacity(self.allocator, 1);
        self.pending_challenges.appendAssumeCapacity(.{ .data = data });
        slot.value_ptr.* = {};
    }

    pub fn receiveChallenge(self: *State, data: [8]u8) Error!bool {
        const slot = try self.pending_response_index.getOrPut(
            self.allocator,
            data,
        );
        if (slot.found_existing) return false;
        errdefer _ = self.pending_response_index.remove(data);

        try self.pending_responses.ensureUnusedCapacity(self.allocator, 1);
        self.pending_responses.appendAssumeCapacity(data);
        slot.value_ptr.* = {};
        return true;
    }

    pub fn nextResponseFrame(self: *State) Error!quic.Frame {
        const data = self.pending_responses.popFront() orelse return error.NoPendingPathResponse;
        _ = self.pending_response_index.remove(data);
        return .{ .path_response = .{ .data = data } };
    }

    pub fn peekResponseFrames(self: State, out: []quic.Frame) usize {
        const responses = self.pending_responses.activeConst();
        const count = @min(out.len, responses.len);
        for (responses[0..count], out[0..count]) |data, *frame| {
            frame.* = .{ .path_response = .{ .data = data } };
        }
        return count;
    }

    pub fn discardResponses(self: *State, count: usize) void {
        var discarded: usize = 0;
        while (discarded < count) : (discarded += 1) {
            const data = self.pending_responses.popFront() orelse return;
            _ = self.pending_response_index.remove(data);
        }
    }

    pub fn nextResponseFrames(self: *State, out: []quic.Frame) usize {
        var written: usize = 0;
        while (written < out.len) : (written += 1) {
            const data = self.pending_responses.popFront() orelse break;
            _ = self.pending_response_index.remove(data);
            out[written] = .{ .path_response = .{ .data = data } };
        }
        return written;
    }

    pub fn nextChallengeFrame(self: *State) Error!quic.Frame {
        return try self.nextChallengeFrameAt(null, null);
    }

    pub fn nextChallengeFrameAt(self: *State, now_ns: ?u64, timeout_ns: ?u64) Error!quic.Frame {
        if (self.pending_challenges.len() == 0) return error.NoPendingPathChallenge;
        try self.outstanding_challenges.ensureUnusedCapacity(self.allocator, 1);
        try self.outstanding_challenge_index.ensureUnusedCapacity(self.allocator, 1);
        const challenge = self.popPendingChallengeToOutstanding(now_ns, timeout_ns);
        return .{ .path_challenge = .{ .data = challenge.data } };
    }

    pub fn nextChallengeFramesAt(self: *State, out: []quic.Frame, now_ns: ?u64, timeout_ns: ?u64) Error!usize {
        const count = @min(out.len, self.pendingChallengeCount());
        if (count == 0) return 0;
        try self.outstanding_challenges.ensureUnusedCapacity(self.allocator, count);
        const outstanding_capacity = std.math.cast(
            @TypeOf(self.outstanding_challenge_index).Size,
            count,
        ) orelse return error.OutOfMemory;
        try self.outstanding_challenge_index.ensureUnusedCapacity(self.allocator, outstanding_capacity);

        var written: usize = 0;
        while (written < count) : (written += 1) {
            const challenge = self.popPendingChallengeToOutstanding(now_ns, timeout_ns);
            out[written] = .{ .path_challenge = .{ .data = challenge.data } };
        }
        return written;
    }

    pub fn receiveResponse(self: *State, data: [8]u8) Error!void {
        if (!self.receiveResponseValidated(data)) return error.UnknownPathResponse;
    }

    pub fn receiveResponseValidated(self: *State, data: [8]u8) bool {
        const index = self.outstanding_challenge_index.get(data) orelse return false;
        _ = self.removeOutstandingChallenge(index);
        return true;
    }

    pub fn pendingResponseCount(self: *const State) usize {
        return self.pending_responses.len();
    }

    pub fn pendingChallengeCount(self: *const State) usize {
        return self.pending_challenges.len();
    }

    pub fn outstandingChallengeCount(self: *const State) usize {
        return self.outstanding_challenges.items.len;
    }

    pub fn failedChallengeCount(self: *const State) usize {
        return self.failed_challenges.items.len;
    }

    pub fn earliestChallengeDeadline(self: *const State) ?u64 {
        return self.earliest_outstanding_deadline_ns;
    }

    pub fn checkTimeouts(self: *State, now_ns: u64) Error!usize {
        const earliest_deadline = self.earliest_outstanding_deadline_ns orelse
            return 0;
        if (now_ns < earliest_deadline) return 0;

        var expired: usize = 0;
        var i: usize = 0;
        while (i < self.outstanding_challenges.items.len) {
            const deadline = self.outstanding_challenges.items[i].deadline_ns orelse {
                i += 1;
                continue;
            };
            if (now_ns < deadline) {
                i += 1;
                continue;
            }

            const will_fail = self.outstanding_challenges.items[i].transmissions >=
                self.max_challenge_transmissions;
            if (will_fail) {
                try self.failed_challenges.ensureUnusedCapacity(self.allocator, 1);
                var challenge = self.removeOutstandingChallenge(i);
                challenge.sent_time_ns = null;
                challenge.deadline_ns = null;
                expired += 1;
                self.failed_challenges.appendAssumeCapacity(challenge);
            } else {
                try self.pending_challenges.ensureUnusedCapacity(self.allocator, 1);
                const data = self.outstanding_challenges.items[i].data;
                const slot = try self.pending_challenge_index.getOrPut(
                    self.allocator,
                    data,
                );
                std.debug.assert(!slot.found_existing);
                errdefer _ = self.pending_challenge_index.remove(data);
                var challenge = self.removeOutstandingChallenge(i);
                challenge.sent_time_ns = null;
                challenge.deadline_ns = null;
                expired += 1;
                self.pending_challenges.appendAssumeCapacity(challenge);
                slot.value_ptr.* = {};
            }
        }
        return expired;
    }

    fn popPendingChallengeToOutstanding(
        self: *State,
        now_ns: ?u64,
        timeout_ns: ?u64,
    ) Challenge {
        var challenge = self.pending_challenges.popFront().?;
        _ = self.pending_challenge_index.remove(challenge.data);
        challenge.transmissions +|= 1;
        challenge.sent_time_ns = now_ns;
        if (now_ns) |now| {
            if (timeout_ns) |timeout| {
                challenge.deadline_ns = std.math.add(
                    u64,
                    now,
                    timeout,
                ) catch std.math.maxInt(u64);
            }
        }
        const index = self.outstanding_challenges.items.len;
        self.outstanding_challenges.appendAssumeCapacity(challenge);
        self.outstanding_challenge_index.putAssumeCapacityNoClobber(
            challenge.data,
            index,
        );
        self.considerOutstandingDeadline(challenge.deadline_ns);
        return challenge;
    }

    fn removeOutstandingChallenge(self: *State, index: usize) Challenge {
        const old_len = self.outstanding_challenges.items.len;
        const removed = self.outstanding_challenges.swapRemove(index);
        _ = self.outstanding_challenge_index.remove(removed.data);
        if (index != old_len - 1) {
            const moved = self.outstanding_challenges.items[index];
            self.outstanding_challenge_index.getPtr(moved.data).?.* = index;
        }
        if (removed.deadline_ns != null and
            removed.deadline_ns == self.earliest_outstanding_deadline_ns)
        {
            self.recomputeOutstandingDeadline();
        }
        return removed;
    }

    fn considerOutstandingDeadline(self: *State, deadline: ?u64) void {
        const candidate = deadline orelse return;
        if (self.earliest_outstanding_deadline_ns == null or
            candidate < self.earliest_outstanding_deadline_ns.?)
        {
            self.earliest_outstanding_deadline_ns = candidate;
        }
    }

    fn recomputeOutstandingDeadline(self: *State) void {
        self.earliest_outstanding_deadline_ns = null;
        for (self.outstanding_challenges.items) |challenge| {
            self.considerOutstandingDeadline(challenge.deadline_ns);
        }
    }

    fn rebuildIndexes(self: *State) Error!void {
        const pending_response_count = std.math.cast(
            @TypeOf(self.pending_response_index).Size,
            self.pending_responses.len(),
        ) orelse return error.OutOfMemory;
        const pending_challenge_count = std.math.cast(
            @TypeOf(self.pending_challenge_index).Size,
            self.pending_challenges.len(),
        ) orelse return error.OutOfMemory;
        try self.pending_response_index.ensureUnusedCapacity(
            self.allocator,
            pending_response_count,
        );
        try self.pending_challenge_index.ensureUnusedCapacity(
            self.allocator,
            pending_challenge_count,
        );
        const outstanding_count = std.math.cast(
            @TypeOf(self.outstanding_challenge_index).Size,
            self.outstanding_challenges.items.len,
        ) orelse return error.OutOfMemory;
        try self.outstanding_challenge_index.ensureUnusedCapacity(
            self.allocator,
            outstanding_count,
        );

        for (self.pending_responses.activeConst()) |data| {
            self.pending_response_index.putAssumeCapacityNoClobber(data, {});
        }
        for (self.pending_challenges.activeConst()) |challenge| {
            self.pending_challenge_index.putAssumeCapacityNoClobber(challenge.data, {});
        }
        self.earliest_outstanding_deadline_ns = null;
        for (self.outstanding_challenges.items, 0..) |challenge, index| {
            self.outstanding_challenge_index.putAssumeCapacityNoClobber(
                challenge.data,
                index,
            );
            self.considerOutstandingDeadline(challenge.deadline_ns);
        }
    }
};

test "QUIC path validation state queues responses and validates challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const challenge = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    _ = try state.receiveChallenge(challenge);
    _ = try state.receiveChallenge(challenge);
    try std.testing.expectEqual(@as(usize, 1), state.pendingResponseCount());
    const response = try state.nextResponseFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &response.path_response.data);

    try state.queueChallenge(challenge);
    const challenge_frame = try state.nextChallengeFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &challenge_frame.path_challenge.data);
    try std.testing.expectEqual(@as(usize, 1), state.outstandingChallengeCount());
    try state.receiveResponse(challenge);
    try std.testing.expectEqual(@as(usize, 0), state.outstandingChallengeCount());
    try std.testing.expectError(error.UnknownPathResponse, state.receiveResponse(challenge));
}

test "QUIC path validation pending queues pop FIFO without shifting" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const a = [_]u8{ 'a', 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 'b', 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 'c', 0, 0, 0, 0, 0, 0, 3 };

    _ = try state.receiveChallenge(a);
    _ = try state.receiveChallenge(b);
    try std.testing.expectEqual(@as(usize, 2), state.pendingResponseCount());
    try std.testing.expectEqualSlices(u8, &a, &(try state.nextResponseFrame()).path_response.data);
    _ = try state.receiveChallenge(c);
    try std.testing.expectEqualSlices(u8, &b, &(try state.nextResponseFrame()).path_response.data);
    try std.testing.expectEqualSlices(u8, &c, &(try state.nextResponseFrame()).path_response.data);
    try std.testing.expectError(error.NoPendingPathResponse, state.nextResponseFrame());

    try state.queueChallenge(a);
    try state.queueChallenge(b);
    try std.testing.expectEqualSlices(u8, &a, &(try state.nextChallengeFrame()).path_challenge.data);
    try state.queueChallenge(c);

    var cloned = try state.clone(allocator);
    defer cloned.deinit();
    try std.testing.expectEqual(@as(usize, 2), cloned.pendingChallengeCount());
    try std.testing.expectEqualSlices(u8, &b, &(try cloned.nextChallengeFrame()).path_challenge.data);
    try std.testing.expectEqualSlices(u8, &c, &(try cloned.nextChallengeFrame()).path_challenge.data);
}

test "QUIC path validation drains response frames into caller storage" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const a = [_]u8{ 0xaa, 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 0xbb, 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 0xcc, 0, 0, 0, 0, 0, 0, 3 };
    _ = try state.receiveChallenge(a);
    _ = try state.receiveChallenge(b);
    _ = try state.receiveChallenge(c);

    var first_batch: [2]quic.Frame = undefined;
    const first_count = state.nextResponseFrames(&first_batch);
    try std.testing.expectEqual(@as(usize, 2), first_count);
    try std.testing.expectEqualSlices(u8, &a, &first_batch[0].path_response.data);
    try std.testing.expectEqualSlices(u8, &b, &first_batch[1].path_response.data);
    try std.testing.expectEqual(@as(usize, 1), state.pendingResponseCount());

    var second_batch: [4]quic.Frame = undefined;
    const second_count = state.nextResponseFrames(&second_batch);
    try std.testing.expectEqual(@as(usize, 1), second_count);
    try std.testing.expectEqualSlices(u8, &c, &second_batch[0].path_response.data);
    try std.testing.expectEqual(@as(usize, 0), state.nextResponseFrames(&second_batch));
}

test "QUIC path validation peeks responses without consuming" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const a = [_]u8{ 'a', 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 'b', 0, 0, 0, 0, 0, 0, 2 };
    _ = try state.receiveChallenge(a);
    _ = try state.receiveChallenge(b);

    var frames: [2]quic.Frame = undefined;
    try std.testing.expectEqual(@as(usize, 2), state.peekResponseFrames(&frames));
    try std.testing.expectEqual(@as(usize, 2), state.pendingResponseCount());
    try std.testing.expectEqualSlices(u8, &a, &frames[0].path_response.data);
    try std.testing.expectEqualSlices(u8, &b, &frames[1].path_response.data);

    state.discardResponses(1);
    try std.testing.expectEqual(@as(usize, 1), state.pendingResponseCount());
    try std.testing.expectEqualSlices(u8, &b, &(try state.nextResponseFrame()).path_response.data);
}

test "QUIC path validation drains challenge frames into caller storage" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const a = [_]u8{ 0x1a, 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 0x1b, 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 0x1c, 0, 0, 0, 0, 0, 0, 3 };
    try state.queueChallenge(a);
    try state.queueChallenge(b);
    try state.queueChallenge(c);

    var first_batch: [2]quic.Frame = undefined;
    const first_count = try state.nextChallengeFramesAt(&first_batch, 1_000, 250);
    try std.testing.expectEqual(@as(usize, 2), first_count);
    try std.testing.expectEqualSlices(u8, &a, &first_batch[0].path_challenge.data);
    try std.testing.expectEqualSlices(u8, &b, &first_batch[1].path_challenge.data);
    try std.testing.expectEqual(@as(usize, 1), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 2), state.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?u64, 1_250), state.earliestChallengeDeadline());

    var second_batch: [4]quic.Frame = undefined;
    const second_count = try state.nextChallengeFramesAt(&second_batch, 2_000, 500);
    try std.testing.expectEqual(@as(usize, 1), second_count);
    try std.testing.expectEqualSlices(u8, &c, &second_batch[0].path_challenge.data);
    try std.testing.expectEqual(@as(usize, 0), try state.nextChallengeFramesAt(&second_batch, null, null));
    try std.testing.expectEqual(@as(usize, 3), state.outstandingChallengeCount());
}

test "QUIC path validation retries and fails timed-out challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();
    state.max_challenge_transmissions = 2;

    const challenge = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    try state.queueChallenge(challenge);
    _ = try state.nextChallengeFrameAt(100, 50);
    try std.testing.expectEqual(@as(?u64, 150), state.earliestChallengeDeadline());
    try std.testing.expectEqual(@as(usize, 0), try state.checkTimeouts(149));
    try std.testing.expectEqual(@as(usize, 1), try state.checkTimeouts(150));
    try std.testing.expectEqual(@as(usize, 1), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), state.failedChallengeCount());

    _ = try state.nextChallengeFrameAt(200, 50);
    try std.testing.expectEqual(@as(usize, 1), try state.checkTimeouts(250));
    try std.testing.expectEqual(@as(usize, 0), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), state.failedChallengeCount());
}

test "QUIC path validation removes matched responses without preserving order" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const first = [_]u8{ '1', 0, 0, 0, 0, 0, 0, 1 };
    const second = [_]u8{ '2', 0, 0, 0, 0, 0, 0, 2 };
    const third = [_]u8{ '3', 0, 0, 0, 0, 0, 0, 3 };
    try state.queueChallenge(first);
    try state.queueChallenge(second);
    try state.queueChallenge(third);

    var frames: [3]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 3),
        try state.nextChallengeFramesAt(&frames, 10, 100),
    );
    try std.testing.expect(state.receiveResponseValidated(second));
    try std.testing.expectEqual(@as(usize, 2), state.outstandingChallengeCount());
    try std.testing.expect(!state.receiveResponseValidated(second));
    try std.testing.expect(state.receiveResponseValidated(first));
    try std.testing.expect(state.receiveResponseValidated(third));
    try std.testing.expectEqual(@as(usize, 0), state.outstandingChallengeCount());
}

test "QUIC path validation timeout scan handles swapped challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const due = [_]u8{ 'd', 0, 0, 0, 0, 0, 0, 1 };
    const later = [_]u8{ 'l', 0, 0, 0, 0, 0, 0, 2 };
    try state.queueChallenge(due);
    try state.queueChallenge(later);
    var frames: [2]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 2),
        try state.nextChallengeFramesAt(&frames, 100, 50),
    );
    // Make the second challenge expire later so removing the first with
    // swapRemove leaves a not-yet-due challenge at the scanned index.
    state.outstanding_challenges.items[1].deadline_ns = 1_000;

    try std.testing.expectEqual(@as(usize, 1), try state.checkTimeouts(150));
    try std.testing.expectEqual(@as(usize, 1), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), state.outstandingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), try state.checkTimeouts(999));
    try std.testing.expectEqual(@as(usize, 1), try state.checkTimeouts(1_000));
}

test "QUIC path validation suppresses duplicate pending and outstanding challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const challenge = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try state.queueChallenge(challenge);
    try state.queueChallenge(challenge);
    try std.testing.expectEqual(@as(usize, 1), state.pendingChallengeCount());

    _ = try state.nextChallengeFrame();
    try std.testing.expectEqual(@as(usize, 0), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), state.outstandingChallengeCount());

    try state.queueChallenge(challenge);
    try std.testing.expectEqual(@as(usize, 0), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), state.outstandingChallengeCount());
}

test "QUIC path validation indexes track queued outstanding and timed-out challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const first_response = [_]u8{ 'r', 0, 0, 0, 0, 0, 0, 1 };
    const second_response = [_]u8{ 'r', 0, 0, 0, 0, 0, 0, 2 };
    try std.testing.expect(try state.receiveChallenge(first_response));
    try std.testing.expect(try state.receiveChallenge(second_response));
    try std.testing.expectEqual(@as(usize, 2), state.pending_response_index.count());
    state.discardResponses(1);
    try std.testing.expect(!state.pending_response_index.contains(first_response));
    try std.testing.expect(state.pending_response_index.contains(second_response));
    _ = try state.nextResponseFrame();
    try std.testing.expectEqual(@as(usize, 0), state.pending_response_index.count());

    const first = [_]u8{ '1', 0, 0, 0, 0, 0, 0, 1 };
    const second = [_]u8{ '2', 0, 0, 0, 0, 0, 0, 2 };
    const third = [_]u8{ '3', 0, 0, 0, 0, 0, 0, 3 };
    try state.queueChallenge(first);
    try state.queueChallenge(second);
    try state.queueChallenge(third);
    try std.testing.expectEqual(@as(usize, 3), state.pending_challenge_index.count());

    var frames: [3]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 3),
        try state.nextChallengeFramesAt(&frames, 100, 50),
    );
    try std.testing.expectEqual(@as(usize, 0), state.pending_challenge_index.count());
    try std.testing.expectEqual(@as(usize, 3), state.outstanding_challenge_index.count());
    try std.testing.expectEqual(@as(?usize, 0), state.outstanding_challenge_index.get(first));
    try std.testing.expectEqual(@as(?usize, 1), state.outstanding_challenge_index.get(second));
    try std.testing.expectEqual(@as(?usize, 2), state.outstanding_challenge_index.get(third));
    try std.testing.expectEqual(@as(?u64, 150), state.earliestChallengeDeadline());

    // Removing the middle challenge swap-moves the last challenge into its
    // slot; the data->slot index must be repaired before another response or
    // timeout scan can use it.
    try std.testing.expect(state.receiveResponseValidated(second));
    try std.testing.expect(!state.outstanding_challenge_index.contains(second));
    try std.testing.expectEqual(@as(?usize, 0), state.outstanding_challenge_index.get(first));
    try std.testing.expectEqual(@as(?usize, 1), state.outstanding_challenge_index.get(third));
    try std.testing.expectEqual(@as(?u64, 150), state.earliestChallengeDeadline());

    try std.testing.expectEqual(@as(usize, 2), try state.checkTimeouts(150));
    try std.testing.expectEqual(@as(usize, 2), state.pending_challenge_index.count());
    try std.testing.expect(state.pending_challenge_index.contains(first));
    try std.testing.expect(state.pending_challenge_index.contains(third));
    try std.testing.expectEqual(@as(usize, 0), state.outstanding_challenge_index.count());
    try std.testing.expectEqual(@as(?u64, null), state.earliestChallengeDeadline());
}
