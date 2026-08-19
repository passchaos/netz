//! RFC 9218 response selection for flow-controlled HTTP/2 DATA batches.
//!
//! The scheduler chooses only streams that can currently use connection and
//! stream credit. Among those, lower urgency wins. Non-incremental responses
//! of the selected urgency run one at a time in ascending stream-ID order;
//! when only incremental responses remain, every eligible stream shares the
//! pass and the runtime rotates the pass start for fairness.

const std = @import("std");
const http2 = @import("../mod.zig");

pub const Candidate = struct {
    stream_id: u31,
    remaining: usize,
    send_capacity: usize,
    priority: http2.ExtensiblePriority,

    fn eligible(self: Candidate) bool {
        return self.remaining != 0 and self.send_capacity != 0;
    }
};

pub const Selection = struct {
    urgency: u3,
    /// When present, only this non-incremental stream may contribute.
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

pub fn select(candidates: []const Candidate) ?Selection {
    var selected_urgency: ?u3 = null;
    var exclusive_index: ?usize = null;
    for (candidates, 0..) |candidate, index| {
        if (!candidate.eligible()) continue;
        if (selected_urgency == null or
            candidate.priority.urgency < selected_urgency.?)
        {
            selected_urgency = candidate.priority.urgency;
            exclusive_index = if (candidate.priority.incremental)
                null
            else
                index;
            continue;
        }
        if (candidate.priority.urgency != selected_urgency.? or
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
    const urgency = selected_urgency orelse return null;
    return .{
        .urgency = urgency,
        .exclusive_index = exclusive_index,
    };
}

test "scheduler selects lowest urgency and skips blocked streams" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 1,
            .remaining = 10,
            .send_capacity = 0,
            .priority = .{ .urgency = 0 },
        },
        .{
            .stream_id = 3,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 2, .incremental = true },
        },
        .{
            .stream_id = 5,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 4 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(u3, 2), selection.urgency);
    try std.testing.expect(selection.exclusive_index == null);
    try std.testing.expect(selection.includes(&candidates, 1));
    try std.testing.expect(!selection.includes(&candidates, 0));
    try std.testing.expect(!selection.includes(&candidates, 2));
}

test "scheduler serializes non-incremental streams by stream ID" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 5,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1 },
        },
        .{
            .stream_id = 3,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1, .incremental = true },
        },
        .{
            .stream_id = 1,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 1 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(?usize, 2), selection.exclusive_index);
    try std.testing.expect(selection.includes(&candidates, 2));
    try std.testing.expect(!selection.includes(&candidates, 0));
    try std.testing.expect(!selection.includes(&candidates, 1));
}

test "scheduler shares one urgency across incremental streams" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 1,
            .remaining = 10,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .stream_id = 3,
            .remaining = 0,
            .send_capacity = 10,
            .priority = .{ .urgency = 3, .incremental = true },
        },
        .{
            .stream_id = 5,
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

test "scheduler returns null without a sendable stream" {
    try std.testing.expect(select(&.{
        .{
            .stream_id = 1,
            .remaining = 0,
            .send_capacity = 10,
            .priority = .{},
        },
        .{
            .stream_id = 3,
            .remaining = 10,
            .send_capacity = 0,
            .priority = .{},
        },
    }) == null);
}

test "scheduler single pass replaces exclusive stream on lower urgency" {
    const candidates = [_]Candidate{
        .{
            .stream_id = 9,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 5 },
        },
        .{
            .stream_id = 7,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
        .{
            .stream_id = 3,
            .remaining = 1,
            .send_capacity = 1,
            .priority = .{ .urgency = 1 },
        },
    };
    const selection = select(&candidates).?;
    try std.testing.expectEqual(@as(u3, 1), selection.urgency);
    try std.testing.expectEqual(@as(?usize, 2), selection.exclusive_index);
}
