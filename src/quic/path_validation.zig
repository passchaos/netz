const std = @import("std");
const quic = @import("mod.zig");

pub const Error = error{
    NoPendingPathResponse,
    NoPendingPathChallenge,
    DuplicatePathChallenge,
} || std.mem.Allocator.Error;

pub const default_max_challenge_transmissions: u8 = 3;
/// Bound peer PATH_CHALLENGEs awaiting a PATH_RESPONSE. A peer can send many
/// unique challenge values while congestion or amplification limits prevent
/// replies; retaining every value would make connection memory unbounded.
pub const default_max_pending_responses: usize = 8;

pub const Challenge = struct {
    data: [8]u8,
    transmissions: u8 = 0,
    sent_time_ns: ?u64 = null,
    deadline_ns: ?u64 = null,
    path_epoch: u32 = 0,
};

pub const TimeoutResult = struct {
    expired: usize = 0,
    failed: usize = 0,
    failed_current_path: bool = false,
};

const RemovedChallenge = struct {
    challenge: Challenge,
    removed_cached_deadline: bool,
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
            try self.ensureUnusedCapacity(allocator, 1);
            self.items.appendAssumeCapacity(value);
        }

        fn appendSlice(self: *Self, allocator: std.mem.Allocator, values: []const T) std.mem.Allocator.Error!void {
            try self.ensureUnusedCapacity(allocator, values.len);
            self.items.appendSliceAssumeCapacity(values);
        }

        fn ensureUnusedCapacity(self: *Self, allocator: std.mem.Allocator, additional_count: usize) std.mem.Allocator.Error!void {
            self.compactIfEmpty();
            if (self.head != 0 and
                self.items.items.len + additional_count > self.items.capacity and
                self.len() + additional_count <= self.items.capacity)
            {
                const remaining = self.len();
                std.mem.copyForwards(
                    T,
                    self.items.items[0..remaining],
                    self.items.items[self.head..],
                );
                self.items.items.len = remaining;
                self.head = 0;
            }
            try self.items.ensureUnusedCapacity(allocator, additional_count);
        }

        fn appendAssumeCapacity(self: *Self, value: T) void {
            self.items.appendAssumeCapacity(value);
        }

        fn appendSliceAssumeCapacity(self: *Self, values: []const T) void {
            self.items.appendSliceAssumeCapacity(values);
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
    max_pending_responses: usize = default_max_pending_responses,
    pending_responses: Fifo([8]u8) = .{},
    pending_challenges: Fifo(Challenge) = .{},
    outstanding_challenges: std.ArrayList(Challenge) = .empty,
    failed_challenge_count: usize = 0,
    dropped_challenge_count: u64 = 0,
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

    pub fn initWithMaxPendingResponses(
        allocator: std.mem.Allocator,
        max_pending_responses: usize,
    ) State {
        return .{
            .allocator = allocator,
            .max_pending_responses = max_pending_responses,
        };
    }

    pub fn deinit(self: *State) void {
        self.pending_responses.deinit(self.allocator);
        self.pending_challenges.deinit(self.allocator);
        self.outstanding_challenges.deinit(self.allocator);
        self.pending_response_index.deinit(self.allocator);
        self.pending_challenge_index.deinit(self.allocator);
        self.outstanding_challenge_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clone(self: *const State, allocator: std.mem.Allocator) Error!State {
        var out = State.initWithMaxPendingResponses(
            allocator,
            self.max_pending_responses,
        );
        errdefer out.deinit();
        const pending_responses = self.pending_responses.activeConst();
        try out.pending_responses.ensureUnusedCapacity(allocator, pending_responses.len);
        out.pending_responses.appendSliceAssumeCapacity(pending_responses);
        const pending_challenges = self.pending_challenges.activeConst();
        try out.pending_challenges.ensureUnusedCapacity(allocator, pending_challenges.len);
        out.pending_challenges.appendSliceAssumeCapacity(pending_challenges);
        try out.outstanding_challenges.ensureUnusedCapacity(allocator, self.outstanding_challenges.items.len);
        out.outstanding_challenges.appendSliceAssumeCapacity(self.outstanding_challenges.items);
        out.failed_challenge_count = self.failed_challenge_count;
        out.dropped_challenge_count = self.dropped_challenge_count;
        try out.rebuildIndexes();
        out.max_challenge_transmissions = self.max_challenge_transmissions;
        return out;
    }

    /// Validate one PATH_CHALLENGE against a packet-local shadow queue.
    ///
    /// Receive preflight needs only duplicate suppression and queue-capacity
    /// checks; cloning every heap-backed queue and hash index for ordinary
    /// STREAM packets made transactional validation allocate even when a
    /// packet contained no path-validation frame. The fixed-size shadow holds
    /// at most one entry per QUIC frame in the packet and consults live state
    /// without mutating it.
    pub const ReceivePreflight = struct {
        state: *State,
        pending_challenges: [][8]u8,
        pending_challenge_len: usize = 0,
        received_responses: [][8]u8,
        received_response_len: usize = 0,

        pub fn init(
            state: *State,
            pending_challenges: [][8]u8,
            received_responses: [][8]u8,
        ) ReceivePreflight {
            return .{
                .state = state,
                .pending_challenges = pending_challenges,
                .received_responses = received_responses,
            };
        }

        pub fn receiveChallenge(
            self: *ReceivePreflight,
            data: [8]u8,
        ) Error!void {
            if (self.state.pending_response_index.contains(data)) return;
            for (self.pending_challenges[0..self.pending_challenge_len]) |queued| {
                if (std.mem.eql(u8, &queued, &data)) return;
            }
            if (self.state.pendingResponseCount() +
                self.pending_challenge_len >=
                self.state.max_pending_responses) return;
            if (self.pending_challenge_len == self.pending_challenges.len) {
                return error.OutOfMemory;
            }
            self.pending_challenges[self.pending_challenge_len] = data;
            self.pending_challenge_len += 1;
        }

        pub fn recordResponse(
            self: *ReceivePreflight,
            data: [8]u8,
        ) Error!void {
            // RFC 9000 defines a matching response as successful validation,
            // but assigns no connection error to an unmatched or duplicated
            // response. Ignore it while preserving other frames in the packet.
            for (self.received_responses[0..self.received_response_len]) |received| {
                if (std.mem.eql(u8, &received, &data)) {
                    return;
                }
            }
            if (!self.state.outstanding_challenge_index.contains(data)) {
                return;
            }
            if (self.received_response_len == self.received_responses.len) {
                return error.OutOfMemory;
            }
            self.received_responses[self.received_response_len] = data;
            self.received_response_len += 1;
        }

        /// Reserve the exact live-state growth proved necessary above. Only
        /// capacity may change here; the packet still has not committed any
        /// observable path-validation state.
        pub fn prepare(self: *ReceivePreflight) Error!void {
            if (self.pending_challenge_len == 0) return;
            try self.state.pending_responses.ensureUnusedCapacity(
                self.state.allocator,
                self.pending_challenge_len,
            );
            const additional = std.math.cast(
                @TypeOf(self.state.pending_response_index).Size,
                self.pending_challenge_len,
            ) orelse return error.OutOfMemory;
            try self.state.pending_response_index.ensureUnusedCapacity(
                self.state.allocator,
                additional,
            );
        }
    };

    pub fn queueChallenge(self: *State, data: [8]u8) Error!void {
        _ = try self.queueChallengeForPath(data, 0);
    }

    pub fn queueChallengeForPath(
        self: *State,
        data: [8]u8,
        path_epoch: u32,
    ) Error!bool {
        if (self.outstanding_challenge_index.count() != 0 and
            self.outstanding_challenge_index.contains(data)) return false;
        const slot = try self.pending_challenge_index.getOrPut(
            self.allocator,
            data,
        );
        if (slot.found_existing) return false;
        errdefer _ = self.pending_challenge_index.remove(data);

        try self.pending_challenges.ensureUnusedCapacity(self.allocator, 1);
        self.pending_challenges.appendAssumeCapacity(.{
            .data = data,
            .path_epoch = path_epoch,
        });
        slot.value_ptr.* = {};
        return true;
    }

    pub fn receiveChallenge(self: *State, data: [8]u8) Error!bool {
        if (self.pending_response_index.contains(data)) return false;
        if (self.pendingResponseCount() >= self.max_pending_responses) {
            self.dropped_challenge_count +|= 1;
            return false;
        }
        const slot = try self.pending_response_index.getOrPut(
            self.allocator,
            data,
        );
        std.debug.assert(!slot.found_existing);
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
        var frames: [1]quic.Frame = undefined;
        if (try self.prepareChallengeFrames(&frames) == 0) {
            return error.NoPendingPathChallenge;
        }
        self.commitChallengeFrames(1, now_ns, timeout_ns, 0);
        return frames[0];
    }

    pub fn nextChallengeFramesAt(self: *State, out: []quic.Frame, now_ns: ?u64, timeout_ns: ?u64) Error!usize {
        const count = try self.prepareChallengeFrames(out);
        self.commitChallengeFrames(count, now_ns, timeout_ns, 0);
        return count;
    }

    /// Reserve all state required to expose pending PATH_CHALLENGE frames
    /// without consuming them. Call `commitChallengeFrames` only after the
    /// corresponding packet has been accepted by the transport.
    pub fn prepareChallengeFrames(
        self: *State,
        out: []quic.Frame,
    ) Error!usize {
        const count = @min(out.len, self.pendingChallengeCount());
        if (count == 0) return 0;
        try self.outstanding_challenges.ensureUnusedCapacity(self.allocator, count);
        const outstanding_capacity = std.math.cast(
            @TypeOf(self.outstanding_challenge_index).Size,
            count,
        ) orelse return error.OutOfMemory;
        try self.outstanding_challenge_index.ensureUnusedCapacity(self.allocator, outstanding_capacity);

        const pending = self.pending_challenges.activeConst();
        for (pending[0..count], out[0..count]) |challenge, *frame| {
            frame.* = .{ .path_challenge = .{ .data = challenge.data } };
        }
        return count;
    }

    /// Commit a successfully sent prefix previously returned by
    /// `prepareChallengeFrames`. Capacity was reserved during prepare, so this
    /// transition cannot fail after bytes become visible on the network.
    pub fn commitChallengeFrames(
        self: *State,
        count: usize,
        now_ns: ?u64,
        timeout_ns: ?u64,
        path_epoch: u32,
    ) void {
        std.debug.assert(count <= self.pendingChallengeCount());
        for (0..count) |_| {
            const data = self.peekPendingChallengeData();
            const slot = self.outstanding_challenge_index
                .getOrPutAssumeCapacity(data);
            std.debug.assert(!slot.found_existing);
            _ = self.popPendingChallengeToOutstanding(
                now_ns,
                timeout_ns,
                path_epoch,
                slot.value_ptr,
            );
        }
    }

    pub fn receiveResponse(self: *State, data: [8]u8) Error!void {
        // A late or duplicate response can follow loss and probe retry.
        _ = self.receiveResponseValidated(data);
    }

    pub fn receiveResponseValidated(self: *State, data: [8]u8) bool {
        return self.takeResponseValidated(data) != null;
    }

    /// Consume a matching response and return the challenge metadata needed
    /// by connection-level path ownership checks.
    pub fn takeResponseValidated(self: *State, data: [8]u8) ?Challenge {
        if (self.outstanding_challenge_index.count() == 0) return null;
        const index = self.outstanding_challenge_index.get(data) orelse
            return null;
        return self.removeOutstandingChallenge(index);
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
        return self.failed_challenge_count;
    }

    pub fn droppedChallengeCount(self: *const State) u64 {
        return self.dropped_challenge_count;
    }

    pub fn hasChallengeForPathEpoch(
        self: *const State,
        path_epoch: u32,
    ) bool {
        for (self.pending_challenges.activeConst()) |challenge| {
            if (challenge.path_epoch == path_epoch) return true;
        }
        for (self.outstanding_challenges.items) |challenge| {
            if (challenge.path_epoch == path_epoch) return true;
        }
        return false;
    }

    pub fn earliestChallengeDeadline(self: *const State) ?u64 {
        return self.earliest_outstanding_deadline_ns;
    }

    pub fn checkTimeouts(self: *State, now_ns: u64) Error!usize {
        return (try self.checkTimeoutsForPathEpoch(now_ns, null)).expired;
    }

    /// Expire validation work while retaining enough path ownership
    /// information for a single-active-path connection to decide whether it
    /// must fall back. Challenges from a superseded path are abandoned rather
    /// than rebound to the current path when retransmitted.
    pub fn checkTimeoutsForPathEpoch(
        self: *State,
        now_ns: u64,
        current_path_epoch: ?u32,
    ) Error!TimeoutResult {
        const earliest_deadline = self.earliest_outstanding_deadline_ns orelse
            return .{};
        if (now_ns < earliest_deadline) return .{};

        var result: TimeoutResult = .{};
        var retry_count: usize = 0;
        for (self.outstanding_challenges.items) |challenge| {
            const deadline = challenge.deadline_ns orelse continue;
            if (now_ns < deadline) continue;
            if (current_path_epoch) |current| {
                if (challenge.path_epoch != 0 and
                    challenge.path_epoch != current) continue;
            }
            if (challenge.transmissions < self.max_challenge_transmissions) {
                retry_count += 1;
            }
        }
        // Reserve the entire retry transition before removing any expired
        // challenge. An allocator failure must leave timeout state unchanged.
        try self.pending_challenges.ensureUnusedCapacity(
            self.allocator,
            retry_count,
        );
        const retry_capacity = std.math.cast(
            @TypeOf(self.pending_challenge_index).Size,
            retry_count,
        ) orelse return error.OutOfMemory;
        try self.pending_challenge_index.ensureUnusedCapacity(
            self.allocator,
            retry_capacity,
        );
        // Multiple PATH_CHALLENGEs often share a retransmission deadline.  Do
        // not rebuild the cached minimum after every swapRemove; the scan works
        // from per-challenge deadlines, so one recompute at the end preserves
        // correctness while avoiding repeated O(n) passes in timeout bursts.
        var deadline_recompute_needed = false;
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

            if (current_path_epoch) |current| {
                const challenge_epoch =
                    self.outstanding_challenges.items[i].path_epoch;
                if (challenge_epoch != 0 and challenge_epoch != current) {
                    const removed = self
                        .removeOutstandingChallengeDeferredDeadline(i);
                    deadline_recompute_needed = deadline_recompute_needed or
                        removed.removed_cached_deadline;
                    result.expired += 1;
                    continue;
                }
            }

            const will_fail = self.outstanding_challenges.items[i].transmissions >=
                self.max_challenge_transmissions;
            if (will_fail) {
                const removed = self
                    .removeOutstandingChallengeDeferredDeadline(i);
                deadline_recompute_needed = deadline_recompute_needed or
                    removed.removed_cached_deadline;
                result.expired += 1;
                result.failed += 1;
                if (current_path_epoch) |current| {
                    result.failed_current_path =
                        result.failed_current_path or
                        removed.challenge.path_epoch == current;
                }
                self.failed_challenge_count +|= 1;
            } else {
                const data = self.outstanding_challenges.items[i].data;
                const slot = self.pending_challenge_index
                    .getOrPutAssumeCapacity(data);
                std.debug.assert(!slot.found_existing);
                const removed = self.removeOutstandingChallengeDeferredDeadline(i);
                deadline_recompute_needed = deadline_recompute_needed or
                    removed.removed_cached_deadline;
                var challenge = removed.challenge;
                challenge.sent_time_ns = null;
                challenge.deadline_ns = null;
                result.expired += 1;
                self.pending_challenges.appendAssumeCapacity(challenge);
                slot.value_ptr.* = {};
            }
        }
        if (deadline_recompute_needed) self.recomputeOutstandingDeadline();
        return result;
    }

    /// Drop validation attempts owned by superseded paths without disturbing
    /// queued PATH_RESPONSE frames. Storage and indexes are retained for reuse.
    pub fn abandonAllChallenges(self: *State) void {
        self.pending_challenges.items.clearRetainingCapacity();
        self.pending_challenges.head = 0;
        self.pending_challenge_index.clearRetainingCapacity();
        self.outstanding_challenges.clearRetainingCapacity();
        self.outstanding_challenge_index.clearRetainingCapacity();
        self.earliest_outstanding_deadline_ns = null;
    }

    pub fn abandonPendingChallengesExceptPathEpoch(
        self: *State,
        path_epoch: u32,
    ) void {
        var write: usize = 0;
        for (self.pending_challenges.activeConst()) |challenge| {
            if (challenge.path_epoch != path_epoch) continue;
            self.pending_challenges.items.items[write] = challenge;
            write += 1;
        }
        self.pending_challenges.items.items.len = write;
        self.pending_challenges.head = 0;
        self.pending_challenge_index.clearRetainingCapacity();
        for (self.pending_challenges.items.items) |challenge| {
            self.pending_challenge_index.putAssumeCapacityNoClobber(
                challenge.data,
                {},
            );
        }
    }

    fn popPendingChallengeToOutstanding(
        self: *State,
        now_ns: ?u64,
        timeout_ns: ?u64,
        path_epoch: u32,
        index_slot: *usize,
    ) Challenge {
        var challenge = self.pending_challenges.popFront().?;
        _ = self.pending_challenge_index.remove(challenge.data);
        challenge.transmissions +|= 1;
        challenge.sent_time_ns = now_ns;
        if (challenge.path_epoch == 0) challenge.path_epoch = path_epoch;
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
        index_slot.* = index;
        self.considerOutstandingDeadline(challenge.deadline_ns);
        return challenge;
    }

    fn peekPendingChallengeData(self: State) [8]u8 {
        return self.pending_challenges.items.items[self.pending_challenges.head].data;
    }

    fn removeOutstandingChallenge(self: *State, index: usize) Challenge {
        const removed = self.removeOutstandingChallengeDeferredDeadline(index);
        if (removed.removed_cached_deadline) self.recomputeOutstandingDeadline();
        return removed.challenge;
    }

    fn removeOutstandingChallengeDeferredDeadline(self: *State, index: usize) RemovedChallenge {
        const old_len = self.outstanding_challenges.items.len;
        const removed = self.outstanding_challenges.swapRemove(index);
        _ = self.outstanding_challenge_index.remove(removed.data);
        if (index != old_len - 1) {
            const moved = self.outstanding_challenges.items[index];
            self.outstanding_challenge_index.getPtr(moved.data).?.* = index;
        }
        return .{
            .challenge = removed,
            .removed_cached_deadline = removed.deadline_ns != null and
                removed.deadline_ns == self.earliest_outstanding_deadline_ns,
        };
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

test {
    _ = @import("path_validation/tests.zig");
}
