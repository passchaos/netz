const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    NoPendingPathResponse,
    NoPendingPathChallenge,
    UnknownPathResponse,
} || std.mem.Allocator.Error;

pub const Challenge = struct {
    data: [8]u8,
    transmissions: u8 = 0,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    pending_responses: std.ArrayList([8]u8) = .empty,
    pending_challenges: std.ArrayList(Challenge) = .empty,
    outstanding_challenges: std.ArrayList(Challenge) = .empty,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.pending_responses.deinit(self.allocator);
        self.pending_challenges.deinit(self.allocator);
        self.outstanding_challenges.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn queueChallenge(self: *State, data: [8]u8) Error!void {
        try self.pending_challenges.append(self.allocator, .{ .data = data });
    }

    pub fn receiveChallenge(self: *State, data: [8]u8) Error!void {
        for (self.pending_responses.items) |existing| {
            if (std.mem.eql(u8, &existing, &data)) return;
        }
        try self.pending_responses.append(self.allocator, data);
    }

    pub fn nextResponseFrame(self: *State) Error!quic.Frame {
        if (self.pending_responses.items.len == 0) return error.NoPendingPathResponse;
        const data = self.pending_responses.orderedRemove(0);
        return .{ .path_response = .{ .data = data } };
    }

    pub fn nextChallengeFrame(self: *State) Error!quic.Frame {
        if (self.pending_challenges.items.len == 0) return error.NoPendingPathChallenge;
        var challenge = self.pending_challenges.orderedRemove(0);
        challenge.transmissions +|= 1;
        try self.outstanding_challenges.append(self.allocator, challenge);
        return .{ .path_challenge = .{ .data = challenge.data } };
    }

    pub fn receiveResponse(self: *State, data: [8]u8) Error!void {
        for (self.outstanding_challenges.items, 0..) |challenge, i| {
            if (std.mem.eql(u8, &challenge.data, &data)) {
                _ = self.outstanding_challenges.orderedRemove(i);
                return;
            }
        }
        return error.UnknownPathResponse;
    }

    pub fn pendingResponseCount(self: State) usize {
        return self.pending_responses.items.len;
    }

    pub fn outstandingChallengeCount(self: State) usize {
        return self.outstanding_challenges.items.len;
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
