//! RFC 9218 response selection for flow-controlled HTTP/3 DATA packets.
//!
//! Eligibility includes the immediately usable QUIC connection, stream, and
//! congestion credit supplied by the runtime. Among eligible responses, lower
//! urgency wins. Non-incremental responses of the selected urgency run one at
//! a time in ascending stream-ID order; when no non-incremental response is
//! eligible, all incremental responses at that urgency share the pass.

const std = @import("std");
const http3 = @import("../../mod.zig");
const body_batch = @import("../body_batch.zig");

/// Common response counts stay entirely on the caller's stack. Larger sets
/// allocate one candidate array plus a temporary stream-ID set used only for
/// duplicate validation. Packet staging remains fixed-size in either case.
pub const stack_response_capacity: usize = 16;

pub const Candidate = struct {
    stream_id: u62,
    offset: usize = 0,
    remaining: usize,
    send_capacity: usize,
    priority: http3.Priority,

    fn eligible(self: Candidate) bool {
        return self.remaining != 0 and self.send_capacity != 0;
    }
};

/// Per-call response scheduler storage.
///
/// Keeping the committed body offset beside selection metadata removes the
/// separate offsets allocation. Each staged packet also retains the response
/// index that selected it, so socket-visible progress never has to recover the
/// index with a linear scan or hash lookup.
pub fn Workspace(comptime max_batch_packets: usize) type {
    if (max_batch_packets == 0) {
        @compileError("HTTP/3 response scheduler batch capacity must be non-zero");
    }
    return struct {
        const Self = @This();

        candidate_stack: [stack_response_capacity]Candidate = undefined,
        candidate_storage: []Candidate = &.{},
        candidate_storage_is_heap: bool = false,
        indexed_stream_ids: bool = false,
        stream_ids: std.AutoHashMapUnmanaged(u62, void) = .empty,
        registered_count: usize = 0,
        batch_chunks: [max_batch_packets]body_batch.Chunk = undefined,
        batch_response_indices: [max_batch_packets]usize = undefined,
        batch_len: usize = 0,

        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            response_count: usize,
        ) (std.mem.Allocator.Error || error{ExcessiveLoad})!void {
            self.* = .{};
            if (response_count <= stack_response_capacity) {
                self.candidate_storage =
                    self.candidate_stack[0..response_count];
                return;
            }

            const hash_capacity = std.math.cast(
                u32,
                response_count,
            ) orelse return error.ExcessiveLoad;
            self.candidate_storage = try allocator.alloc(
                Candidate,
                response_count,
            );
            self.candidate_storage_is_heap = true;
            errdefer self.deinit(allocator);
            try self.stream_ids.ensureTotalCapacity(
                allocator,
                hash_capacity,
            );
            self.indexed_stream_ids = true;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.stream_ids.deinit(allocator);
            if (self.candidate_storage_is_heap) {
                allocator.free(self.candidate_storage);
            }
            self.* = undefined;
        }

        pub fn candidates(self: *Self) []Candidate {
            return self.candidate_storage;
        }

        /// Register in caller order and reject duplicate stream IDs. Small
        /// sets use bounded stack scanning; larger sets use the preallocated
        /// temporary hash set and never allocate during registration.
        pub fn registerResponse(
            self: *Self,
            index: usize,
            stream_id: u62,
        ) bool {
            std.debug.assert(index < self.candidate_storage.len);
            std.debug.assert(index == self.registered_count);
            if (self.indexed_stream_ids) {
                const slot = self.stream_ids.getOrPutAssumeCapacity(stream_id);
                if (slot.found_existing) return false;
            } else {
                for (self.candidate_storage[0..index]) |candidate| {
                    if (candidate.stream_id == stream_id) return false;
                }
            }
            self.candidate_storage[index] = .{
                .stream_id = stream_id,
                .remaining = 0,
                .send_capacity = 0,
                .priority = .{},
            };
            self.registered_count += 1;
            return true;
        }

        pub fn beginBatch(self: *Self) void {
            self.batch_len = 0;
        }

        /// Stage one priority-selected pass and remember each chunk's source
        /// response index.
        pub fn stageSelected(
            self: *Self,
            responses: []const body_batch.ResponseBody,
            selection: Selection,
            next_response: usize,
            chunk_limit: usize,
            batch_limit: usize,
        ) void {
            std.debug.assert(responses.len == self.candidate_storage.len);
            std.debug.assert(chunk_limit != 0);
            std.debug.assert(batch_limit != 0);
            std.debug.assert(batch_limit <= max_batch_packets);
            self.beginBatch();
            var iterator = Iterator.init(
                self.candidate_storage,
                selection,
                next_response,
            );
            while (iterator.next()) |index| {
                const candidate = self.candidate_storage[index];
                const count = @min(
                    candidate.remaining,
                    candidate.send_capacity,
                    chunk_limit,
                );
                if (count == 0) continue;
                const end = candidate.offset + count;
                const response = responses[index];
                self.append(index, .{
                    .stream_id = response.stream_id,
                    .data = response.data[candidate.offset..end],
                    .fin = end == response.data.len,
                });
                if (self.batch_len == batch_limit) break;
            }
        }

        pub fn append(
            self: *Self,
            response_index: usize,
            chunk: body_batch.Chunk,
        ) void {
            std.debug.assert(self.batch_len < max_batch_packets);
            std.debug.assert(response_index < self.candidate_storage.len);
            self.batch_chunks[self.batch_len] = chunk;
            self.batch_response_indices[self.batch_len] = response_index;
            self.batch_len += 1;
        }

        pub fn chunks(self: *const Self) []const body_batch.Chunk {
            return self.batch_chunks[0..self.batch_len];
        }

        pub fn responseIndex(self: *const Self, batch_index: usize) usize {
            std.debug.assert(batch_index < self.batch_len);
            return self.batch_response_indices[batch_index];
        }

        pub const Commit = struct {
            body_bytes: usize = 0,
            completed_responses: usize = 0,
            last_response_index: ?usize = null,
        };

        /// Commit only the socket-visible prefix reported by the transport.
        /// Staged suffix entries retain their old offsets and are eligible for
        /// the next scheduler pass without rollback.
        pub fn commitSentPrefix(
            self: *Self,
            sent_count: usize,
        ) Commit {
            std.debug.assert(sent_count <= self.batch_len);
            var result: Commit = .{};
            for (0..sent_count) |batch_index| {
                const index = self.responseIndex(batch_index);
                const chunk = self.batch_chunks[batch_index];
                self.candidate_storage[index].offset += chunk.data.len;
                result.body_bytes +|= chunk.data.len;
                result.completed_responses += @intFromBool(chunk.fin);
                result.last_response_index = index;
            }
            return result;
        }
    };
}

pub const Selection = struct {
    urgency: u3,
    /// When present, only this non-incremental response may contribute.
    exclusive_index: ?usize,

    pub fn includes(
        self: Selection,
        candidates: []const Candidate,
        index: usize,
    ) bool {
        const candidate = candidates[index];
        if (!candidate.eligible() or
            candidate.priority.urgency != self.urgency)
        {
            return false;
        }
        if (self.exclusive_index) |exclusive| {
            return index == exclusive;
        }
        return candidate.priority.incremental;
    }
};

/// Incremental form of `select` for callers that are already refreshing the
/// candidate array. This avoids a second full pass solely to choose urgency
/// and the lowest-stream-ID non-incremental winner.
pub const SelectionAccumulator = struct {
    urgency: ?u3 = null,
    exclusive_index: ?usize = null,
    exclusive_stream_id: ?u62 = null,

    pub fn consider(
        self: *SelectionAccumulator,
        candidate: Candidate,
        index: usize,
    ) void {
        if (!candidate.eligible()) return;
        if (self.urgency == null or candidate.priority.urgency < self.urgency.?) {
            self.urgency = candidate.priority.urgency;
            self.exclusive_index = if (candidate.priority.incremental)
                null
            else
                index;
            self.exclusive_stream_id = if (candidate.priority.incremental)
                null
            else
                candidate.stream_id;
            return;
        }
        if (candidate.priority.urgency != self.urgency.? or
            candidate.priority.incremental)
        {
            return;
        }
        if (self.exclusive_stream_id == null or
            candidate.stream_id < self.exclusive_stream_id.?)
        {
            self.exclusive_index = index;
            self.exclusive_stream_id = candidate.stream_id;
        }
    }

    pub fn result(self: SelectionAccumulator) ?Selection {
        return .{
            .urgency = self.urgency orelse return null,
            .exclusive_index = self.exclusive_index,
        };
    }
};

/// Iterate selected candidates in circular response order.
///
/// The caller owns the cursor so it can commit only socket-visible progress;
/// merely staging a packet must not consume an incremental stream's turn.
pub const Iterator = struct {
    candidates: []const Candidate,
    selection: Selection,
    start: usize,
    scanned: usize = 0,

    pub fn init(
        candidates: []const Candidate,
        selection: Selection,
        start: usize,
    ) Iterator {
        return .{
            .candidates = candidates,
            .selection = selection,
            .start = if (candidates.len == 0)
                0
            else
                start % candidates.len,
        };
    }

    pub fn next(self: *Iterator) ?usize {
        while (self.scanned < self.candidates.len) {
            const index = (self.start + self.scanned) %
                self.candidates.len;
            self.scanned += 1;
            if (self.selection.includes(self.candidates, index)) {
                return index;
            }
        }
        return null;
    }
};

/// Socket-visible progress accumulated toward an optional cooperative yield.
///
/// Keeping both dimensions lets applications retain a byte-oriented policy
/// while benchmarks use packet cadence that is independent of DATA chunk size.
pub const DelayBudget = struct {
    bytes: usize = 0,
    packets: usize = 0,

    pub fn record(
        self: *DelayBudget,
        body_bytes: usize,
        packet_count: usize,
    ) void {
        self.bytes +|= body_bytes;
        self.packets +|= packet_count;
    }

    pub fn due(
        self: DelayBudget,
        byte_limit: usize,
        packet_limit: usize,
    ) bool {
        return (byte_limit != 0 and self.bytes >= byte_limit) or
            (packet_limit != 0 and self.packets >= packet_limit);
    }

    pub fn reset(self: *DelayBudget) void {
        self.* = .{};
    }
};

/// Clamp an application batch preference to the transport's fixed packet
/// scratch capacity. A zero preference means sequential submission rather
/// than disabling response progress.
pub fn batchPacketLimit(preferred: usize, transport_limit: usize) usize {
    std.debug.assert(transport_limit != 0);
    return @max(@as(usize, 1), @min(preferred, transport_limit));
}

pub fn select(candidates: []const Candidate) ?Selection {
    var accumulator: SelectionAccumulator = .{};
    for (candidates, 0..) |candidate, index| {
        accumulator.consider(candidate, index);
    }
    return accumulator.result();
}

test "HTTP/3 scheduler selects lowest sendable urgency" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 0,
            .remaining = 10,
            .send_capacity = 0,
            .priority = .{ .urgency = 0 },
        },
        .{
            .stream_id = 4,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 2, .incremental = true },
        },
        .{
            .stream_id = 8,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 5 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(u3, 2), selection.urgency);
    try std.testing.expect(selection.exclusive_index == null);
    try std.testing.expect(!selection.includes(&candidates, 0));
    try std.testing.expect(selection.includes(&candidates, 1));
    try std.testing.expect(!selection.includes(&candidates, 2));
}

test "HTTP/3 scheduler serializes non-incremental responses by stream ID" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 8,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1 },
        },
        .{
            .stream_id = 4,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1, .incremental = true },
        },
        .{
            .stream_id = 0,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(?usize, 2), selection.exclusive_index);
    try std.testing.expect(!selection.includes(&candidates, 0));
    try std.testing.expect(!selection.includes(&candidates, 1));
    try std.testing.expect(selection.includes(&candidates, 2));
}

test "HTTP/3 scheduler shares incremental responses" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 0,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .stream_id = 4,
            .remaining = 0,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .stream_id = 8,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expect(selection.exclusive_index == null);
    try std.testing.expect(selection.includes(&candidates, 0));
    try std.testing.expect(!selection.includes(&candidates, 1));
    try std.testing.expect(selection.includes(&candidates, 2));
}

test "HTTP/3 scheduler returns null without a sendable response" {
    try std.testing.expect(select(&.{
        .{
            .stream_id = 0,
            .remaining = 0,
            .send_capacity = 10,
            .priority = .{},
        },
        .{
            .stream_id = 4,
            .remaining = 10,
            .send_capacity = 0,
            .priority = .{},
        },
    }) == null);
}

test "HTTP/3 scheduler clamps response batch packet preference" {
    try std.testing.expectEqual(@as(usize, 1), batchPacketLimit(0, 16));
    try std.testing.expectEqual(@as(usize, 4), batchPacketLimit(4, 16));
    try std.testing.expectEqual(@as(usize, 16), batchPacketLimit(32, 16));
}

test "HTTP/3 scheduler iterator visits selected responses circularly" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 0,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .stream_id = 4,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 6, .incremental = true },
        },
        .{
            .stream_id = 8,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
    };
    var iterator = Iterator.init(&candidates, select(&candidates).?, 2);
    try std.testing.expectEqual(@as(?usize, 2), iterator.next());
    try std.testing.expectEqual(@as(?usize, 0), iterator.next());
    try std.testing.expectEqual(@as(?usize, null), iterator.next());
}

test "HTTP/3 scheduler single pass replaces exclusive urgency" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 8,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 6 },
        },
        .{
            .stream_id = 4,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
        .{
            .stream_id = 0,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(u3, 1), selection.urgency);
    try std.testing.expectEqual(@as(?usize, 2), selection.exclusive_index);
}

test "HTTP/3 scheduler incremental selection matches array selection" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 20,
            .remaining = 1,
            .send_capacity = 0,
            .priority = .{ .urgency = 0 },
        },
        .{
            .stream_id = 12,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 4 },
        },
        .{
            .stream_id = 8,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1, .incremental = true },
        },
        .{
            .stream_id = 4,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
        .{
            .stream_id = 0,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
    };
    var accumulator: SelectionAccumulator = .{};
    for (candidates, 0..) |candidate, index| {
        accumulator.consider(candidate, index);
    }
    const expected = select(&candidates).?;
    const actual = accumulator.result().?;
    try std.testing.expectEqual(expected.urgency, actual.urgency);
    try std.testing.expectEqual(
        expected.exclusive_index,
        actual.exclusive_index,
    );
}

test "HTTP/3 scheduler delay budget supports bytes or packets" {
    var budget = DelayBudget{};
    budget.record(3000, 1);
    try std.testing.expect(!budget.due(6000, 3));
    budget.record(3000, 1);
    try std.testing.expect(budget.due(6000, 3));
    try std.testing.expect(!budget.due(0, 3));
    budget.record(3000, 1);
    try std.testing.expect(budget.due(0, 3));
    budget.reset();
    try std.testing.expect(!budget.due(1, 1));
}

test "HTTP/3 scheduler common workspace is allocation free" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var workspace: Workspace(4) = .{};
    try workspace.init(
        failing.allocator(),
        stack_response_capacity,
    );
    defer workspace.deinit(failing.allocator());

    for (0..stack_response_capacity) |index| {
        try std.testing.expect(workspace.registerResponse(
            index,
            @intCast(index * 4),
        ));
    }
    try std.testing.expect(!failing.has_induced_failure);
}

test "HTTP/3 scheduler large workspace cleans up every allocation failure" {
    const Context = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var workspace: Workspace(4) = .{};
            try workspace.init(
                allocator,
                stack_response_capacity + 1,
            );
            defer workspace.deinit(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Context.run,
        .{},
    );
}

test "HTTP/3 scheduler large workspace uses at most two allocations" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 2 },
    );
    var workspace: Workspace(4) = .{};
    try workspace.init(
        failing.allocator(),
        stack_response_capacity + 1,
    );
    defer workspace.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
}

test "HTTP/3 scheduler large workspace rejects duplicates" {
    const response_count = stack_response_capacity + 1;
    var workspace: Workspace(4) = .{};
    try workspace.init(std.testing.allocator, response_count);
    defer workspace.deinit(std.testing.allocator);

    for (0..response_count - 1) |index| {
        try std.testing.expect(workspace.registerResponse(
            index,
            @intCast((response_count - index) * 4),
        ));
    }
    try std.testing.expect(!workspace.registerResponse(
        response_count - 1,
        @intCast(response_count * 4),
    ));
}

test "HTTP/3 scheduler staged packets retain response indices" {
    var workspace: Workspace(3) = .{};
    try workspace.init(std.testing.allocator, 3);
    defer workspace.deinit(std.testing.allocator);
    inline for (.{ @as(u62, 12), @as(u62, 0), @as(u62, 8) }, 0..) |stream_id, index| {
        try std.testing.expect(workspace.registerResponse(index, stream_id));
    }

    workspace.append(2, .{ .stream_id = 8, .data = "eight" });
    workspace.append(0, .{ .stream_id = 12, .data = "twelve" });
    try std.testing.expectEqual(@as(usize, 2), workspace.chunks().len);
    try std.testing.expectEqual(@as(usize, 2), workspace.responseIndex(0));
    try std.testing.expectEqual(@as(usize, 0), workspace.responseIndex(1));
    try std.testing.expectEqualStrings("eight", workspace.chunks()[0].data);

    // A partial socket-visible prefix commits only its parallel index prefix.
    const commit = workspace.commitSentPrefix(1);
    try std.testing.expectEqual(@as(usize, 5), commit.body_bytes);
    try std.testing.expectEqual(@as(usize, 0), commit.completed_responses);
    try std.testing.expectEqual(@as(?usize, 2), commit.last_response_index);
    try std.testing.expectEqual(
        @as(usize, 5),
        workspace.candidates()[2].offset,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        workspace.candidates()[0].offset,
    );

    workspace.beginBatch();
    try std.testing.expectEqual(@as(usize, 0), workspace.chunks().len);
}

test "HTTP/3 scheduler commit counts only sent final chunks" {
    var workspace: Workspace(3) = .{};
    try workspace.init(std.testing.allocator, 3);
    defer workspace.deinit(std.testing.allocator);
    for (0..3) |index| {
        try std.testing.expect(workspace.registerResponse(
            index,
            @intCast(index * 4),
        ));
    }
    workspace.append(1, .{ .stream_id = 4, .data = "abcd", .fin = true });
    workspace.append(2, .{ .stream_id = 8, .data = "ef", .fin = false });
    workspace.append(0, .{ .stream_id = 0, .data = "ghi", .fin = true });

    const partial = workspace.commitSentPrefix(2);
    try std.testing.expectEqual(@as(usize, 6), partial.body_bytes);
    try std.testing.expectEqual(@as(usize, 1), partial.completed_responses);
    try std.testing.expectEqual(@as(?usize, 2), partial.last_response_index);
    try std.testing.expectEqual(@as(usize, 0), workspace.candidates()[0].offset);
    try std.testing.expectEqual(@as(usize, 4), workspace.candidates()[1].offset);
    try std.testing.expectEqual(@as(usize, 2), workspace.candidates()[2].offset);
}

test "HTTP/3 scheduler stages a bounded circular selected pass" {
    const responses = [_]body_batch.ResponseBody{
        .{ .stream_id = 12, .data = "abcdefghijkl" },
        .{ .stream_id = 0, .data = "zero" },
        .{ .stream_id = 8, .data = "12345678" },
    };
    var workspace: Workspace(3) = .{};
    try workspace.init(std.testing.allocator, responses.len);
    defer workspace.deinit(std.testing.allocator);
    for (responses, 0..) |response, index| {
        try std.testing.expect(workspace.registerResponse(
            index,
            response.stream_id,
        ));
    }
    for (workspace.candidates()) |*candidate| {
        candidate.remaining = responses[0].data.len;
        candidate.send_capacity = 8;
        candidate.priority = .{ .urgency = 2, .incremental = true };
    }
    workspace.candidates()[0].offset = 2;
    workspace.candidates()[0].remaining = 10;
    workspace.candidates()[1].remaining = responses[1].data.len;
    workspace.candidates()[2].remaining = responses[2].data.len;

    const selection = select(workspace.candidates()).?;
    workspace.stageSelected(
        &responses,
        selection,
        2,
        4,
        2,
    );
    try std.testing.expectEqual(@as(usize, 2), workspace.chunks().len);
    try std.testing.expectEqual(@as(usize, 2), workspace.responseIndex(0));
    try std.testing.expectEqual(@as(usize, 0), workspace.responseIndex(1));
    try std.testing.expectEqualStrings("1234", workspace.chunks()[0].data);
    try std.testing.expectEqualStrings("cdef", workspace.chunks()[1].data);
}
