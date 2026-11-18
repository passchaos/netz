const std = @import("std");
const scheduler_core_root = @import("../core.zig");

const body_batch = @import("../../body_batch.zig");

const Candidate = scheduler_core_root.Candidate;
const DelayBudget = scheduler_core_root.DelayBudget;
const Iterator = scheduler_core_root.Iterator;
const SelectionAccumulator = scheduler_core_root.SelectionAccumulator;
const Workspace = scheduler_core_root.Workspace;
const batchPacketLimit = scheduler_core_root.batchPacketLimit;
const select = scheduler_core_root.select;
const stack_response_capacity = scheduler_core_root.stack_response_capacity;

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
