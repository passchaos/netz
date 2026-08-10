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
    max_challenge_transmissions: u8 = default_max_challenge_transmissions,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.pending_responses.deinit(self.allocator);
        self.pending_challenges.deinit(self.allocator);
        self.outstanding_challenges.deinit(self.allocator);
        self.failed_challenges.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clone(self: State, allocator: std.mem.Allocator) Error!State {
        var out = State.init(allocator);
        errdefer out.deinit();
        try out.pending_responses.appendSlice(allocator, self.pending_responses.activeConst());
        try out.pending_challenges.appendSlice(allocator, self.pending_challenges.activeConst());
        try out.outstanding_challenges.appendSlice(allocator, self.outstanding_challenges.items);
        try out.failed_challenges.appendSlice(allocator, self.failed_challenges.items);
        out.max_challenge_transmissions = self.max_challenge_transmissions;
        return out;
    }

    pub fn queueChallenge(self: *State, data: [8]u8) Error!void {
        for (self.pending_challenges.activeConst()) |challenge| {
            if (std.mem.eql(u8, &challenge.data, &data)) return;
        }
        for (self.outstanding_challenges.items) |challenge| {
            if (std.mem.eql(u8, &challenge.data, &data)) return;
        }
        try self.pending_challenges.append(self.allocator, .{ .data = data });
    }

    pub fn receiveChallenge(self: *State, data: [8]u8) Error!void {
        for (self.pending_responses.activeConst()) |existing| {
            if (std.mem.eql(u8, &existing, &data)) return;
        }
        try self.pending_responses.append(self.allocator, data);
    }

    pub fn nextResponseFrame(self: *State) Error!quic.Frame {
        const data = self.pending_responses.popFront() orelse return error.NoPendingPathResponse;
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
            _ = self.pending_responses.popFront() orelse return;
        }
    }

    pub fn nextResponseFrames(self: *State, out: []quic.Frame) usize {
        var written: usize = 0;
        while (written < out.len) : (written += 1) {
            const data = self.pending_responses.popFront() orelse break;
            out[written] = .{ .path_response = .{ .data = data } };
        }
        return written;
    }

    pub fn nextChallengeFrame(self: *State) Error!quic.Frame {
        return try self.nextChallengeFrameAt(null, null);
    }

    pub fn nextChallengeFrameAt(self: *State, now_ns: ?u64, timeout_ns: ?u64) Error!quic.Frame {
        var challenge = self.pending_challenges.popFront() orelse return error.NoPendingPathChallenge;
        challenge.transmissions +|= 1;
        challenge.sent_time_ns = now_ns;
        if (now_ns) |now| {
            if (timeout_ns) |timeout| challenge.deadline_ns = std.math.add(u64, now, timeout) catch std.math.maxInt(u64);
        }
        try self.outstanding_challenges.append(self.allocator, challenge);
        return .{ .path_challenge = .{ .data = challenge.data } };
    }

    pub fn nextChallengeFramesAt(self: *State, out: []quic.Frame, now_ns: ?u64, timeout_ns: ?u64) Error!usize {
        const count = @min(out.len, self.pendingChallengeCount());
        if (count == 0) return 0;
        try self.outstanding_challenges.ensureUnusedCapacity(self.allocator, count);

        var written: usize = 0;
        while (written < count) : (written += 1) {
            var challenge = self.pending_challenges.popFront().?;
            challenge.transmissions +|= 1;
            challenge.sent_time_ns = now_ns;
            if (now_ns) |now| {
                if (timeout_ns) |timeout| challenge.deadline_ns = std.math.add(u64, now, timeout) catch std.math.maxInt(u64);
            }
            self.outstanding_challenges.appendAssumeCapacity(challenge);
            out[written] = .{ .path_challenge = .{ .data = challenge.data } };
        }
        return written;
    }

    pub fn receiveResponse(self: *State, data: [8]u8) Error!void {
        if (!self.receiveResponseValidated(data)) return error.UnknownPathResponse;
    }

    pub fn receiveResponseValidated(self: *State, data: [8]u8) bool {
        for (self.outstanding_challenges.items, 0..) |challenge, i| {
            if (std.mem.eql(u8, &challenge.data, &data)) {
                _ = self.outstanding_challenges.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    pub fn pendingResponseCount(self: State) usize {
        return self.pending_responses.len();
    }

    pub fn pendingChallengeCount(self: State) usize {
        return self.pending_challenges.len();
    }

    pub fn outstandingChallengeCount(self: State) usize {
        return self.outstanding_challenges.items.len;
    }

    pub fn failedChallengeCount(self: State) usize {
        return self.failed_challenges.items.len;
    }

    pub fn earliestChallengeDeadline(self: State) ?u64 {
        var deadline: ?u64 = null;
        for (self.outstanding_challenges.items) |challenge| {
            const candidate = challenge.deadline_ns orelse continue;
            if (deadline == null or candidate < deadline.?) deadline = candidate;
        }
        return deadline;
    }

    pub fn checkTimeouts(self: *State, now_ns: u64) Error!usize {
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

            var challenge = self.outstanding_challenges.orderedRemove(i);
            challenge.sent_time_ns = null;
            challenge.deadline_ns = null;
            expired += 1;
            if (challenge.transmissions >= self.max_challenge_transmissions) {
                try self.failed_challenges.append(self.allocator, challenge);
            } else {
                try self.pending_challenges.append(self.allocator, challenge);
            }
        }
        return expired;
    }
};

test "QUIC path validation state queues responses and validates challenges" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const challenge = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    try state.receiveChallenge(challenge);
    try state.receiveChallenge(challenge);
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

    try state.receiveChallenge(a);
    try state.receiveChallenge(b);
    try std.testing.expectEqual(@as(usize, 2), state.pendingResponseCount());
    try std.testing.expectEqualSlices(u8, &a, &(try state.nextResponseFrame()).path_response.data);
    try state.receiveChallenge(c);
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
    try state.receiveChallenge(a);
    try state.receiveChallenge(b);
    try state.receiveChallenge(c);

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
    try state.receiveChallenge(a);
    try state.receiveChallenge(b);

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
