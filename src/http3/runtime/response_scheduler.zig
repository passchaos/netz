//! RFC 9218 response selection for flow-controlled HTTP/3 DATA packets.
//!
//! Eligibility includes the immediately usable QUIC connection, stream, and
//! congestion credit supplied by the runtime. Among eligible responses, lower
//! urgency wins. Non-incremental responses of the selected urgency run one at
//! a time in ascending stream-ID order; when no non-incremental response is
//! eligible, all incremental responses at that urgency share the pass.

const std = @import("std");
const http3 = @import("../mod.zig");

pub const Candidate = struct {
    stream_id: u62,
    remaining: usize,
    send_capacity: usize,
    priority: http3.Priority,

    fn eligible(self: Candidate) bool {
        return self.remaining != 0 and self.send_capacity != 0;
    }
};

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
    var selected_urgency: ?u3 = null;
    for (candidates) |candidate| {
        if (!candidate.eligible()) continue;
        if (selected_urgency == null or
            candidate.priority.urgency < selected_urgency.?)
        {
            selected_urgency = candidate.priority.urgency;
        }
    }
    const urgency = selected_urgency orelse return null;

    var exclusive_index: ?usize = null;
    for (candidates, 0..) |candidate, index| {
        if (!candidate.eligible() or
            candidate.priority.urgency != urgency or
            candidate.priority.incremental)
        {
            continue;
        }
        if (exclusive_index == null or
            candidate.stream_id <
                candidates[exclusive_index.?].stream_id)
        {
            exclusive_index = index;
        }
    }
    return .{
        .urgency = urgency,
        .exclusive_index = exclusive_index,
    };
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
