const std = @import("std");
const path_validation_root = @import("../path_validation.zig");

const quic = @import("../mod.zig");

const State = path_validation_root.State;

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
    try state.receiveResponse(challenge);
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

test "QUIC path validation bounds pending peer responses" {
    const allocator = std.testing.allocator;
    var state = State.initWithMaxPendingResponses(allocator, 2);
    defer state.deinit();

    const a = [_]u8{ 'a', 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 'b', 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 'c', 0, 0, 0, 0, 0, 0, 3 };
    try std.testing.expect(try state.receiveChallenge(a));
    try std.testing.expect(try state.receiveChallenge(b));
    try std.testing.expect(!try state.receiveChallenge(a));
    try std.testing.expect(!try state.receiveChallenge(c));
    try std.testing.expectEqual(@as(usize, 2), state.pendingResponseCount());
    try std.testing.expectEqual(@as(u64, 1), state.droppedChallengeCount());

    const first = try state.nextResponseFrame();
    try std.testing.expectEqualSlices(u8, &a, &first.path_response.data);
    try std.testing.expect(try state.receiveChallenge(c));
    try std.testing.expectEqual(@as(usize, 2), state.pendingResponseCount());
    try std.testing.expectEqualSlices(
        u8,
        &b,
        &(try state.nextResponseFrame()).path_response.data,
    );
    try std.testing.expectEqualSlices(
        u8,
        &c,
        &(try state.nextResponseFrame()).path_response.data,
    );
}

test "QUIC path receive preflight caps unique challenges per packet" {
    const allocator = std.testing.allocator;
    var state = State.initWithMaxPendingResponses(allocator, 2);
    defer state.deinit();

    const a = [_]u8{ 'a', 0, 0, 0, 0, 0, 0, 1 };
    const b = [_]u8{ 'b', 0, 0, 0, 0, 0, 0, 2 };
    const c = [_]u8{ 'c', 0, 0, 0, 0, 0, 0, 3 };
    try std.testing.expect(try state.receiveChallenge(a));
    var challenges: [3][8]u8 = undefined;
    var responses: [1][8]u8 = undefined;
    var preflight = State.ReceivePreflight.init(
        &state,
        &challenges,
        &responses,
    );
    try preflight.receiveChallenge(a);
    try preflight.receiveChallenge(b);
    try preflight.receiveChallenge(c);
    try std.testing.expectEqual(@as(usize, 1), preflight.pending_challenge_len);
    try std.testing.expectEqualSlices(u8, &b, &preflight.pending_challenges[0]);
    try preflight.prepare();
}

test "QUIC path receive preflight avoids allocation without path frames" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    state.allocator = no_alloc.allocator();
    var challenges: [1][8]u8 = undefined;
    var responses: [1][8]u8 = undefined;
    var preflight = State.ReceivePreflight.init(
        &state,
        &challenges,
        &responses,
    );

    try preflight.prepare();
    try std.testing.expectEqual(@as(usize, 0), no_alloc.alloc_index);
}

test "QUIC path receive preflight ignores duplicate response transactionally" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();
    const challenge = [_]u8{0xa5} ** 8;
    try state.queueChallenge(challenge);
    _ = try state.nextChallengeFrame();
    var challenges: [2][8]u8 = undefined;
    var responses: [2][8]u8 = undefined;
    var preflight = State.ReceivePreflight.init(
        &state,
        &challenges,
        &responses,
    );

    try preflight.recordResponse(challenge);
    try preflight.recordResponse(challenge);
    try std.testing.expectEqual(
        @as(usize, 1),
        state.outstandingChallengeCount(),
    );
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

test "QUIC path validation timeout allocation failure is transactional" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const superseded = [_]u8{ 'o', 0, 0, 0, 0, 0, 0, 1 };
    const current = [_]u8{ 'n', 0, 0, 0, 0, 0, 0, 2 };
    _ = try state.queueChallengeForPath(superseded, 1);
    _ = try state.queueChallengeForPath(current, 2);
    var frames: [2]quic.Frame = undefined;
    try std.testing.expectEqual(
        @as(usize, 2),
        try state.nextChallengeFramesAt(&frames, 100, 50),
    );

    // Force the retry transition to allocate even though the original queue
    // retained capacity after its items moved to outstanding storage.
    state.pending_challenges.items.deinit(allocator);
    state.pending_challenges.items = .empty;
    state.pending_challenge_index.deinit(allocator);
    state.pending_challenge_index = .empty;
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    state.allocator = failing.allocator();
    defer state.allocator = allocator;

    try std.testing.expectError(
        error.OutOfMemory,
        state.checkTimeoutsForPathEpoch(150, 2),
    );
    try std.testing.expectEqual(@as(usize, 0), state.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 2), state.outstandingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), state.failedChallengeCount());
    try std.testing.expectEqual(@as(?u64, 150), state.earliestChallengeDeadline());
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
    try std.testing.expect(!state.receiveResponseValidated(first_response));

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
