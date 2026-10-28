const std = @import("std");
const Queue = @import("../pool_returns.zig").Queue(usize);

test "connection return queue deadline close preserves published storage until publisher retires" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var node = Queue.Node{ .allocator = std.testing.allocator, .value = 1 };
    try std.testing.expect(queue.publish(&node, io));
    queue.publishers.store(1, .release);
    try std.testing.expectError(error.Timeout, queue.closeBefore(io, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(10) })));
    try std.testing.expect(queue.head.load(.acquire) == &node);
    try std.testing.expect(!queue.publish(&node, io));
    _ = queue.publishers.fetchSub(1, .release);
    try std.testing.expect((try queue.closeBefore(io, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }))) == &node);
    try std.testing.expect(queue.close(io) == null);
}

test "connection return queue restores unfinished collectors before later publications and close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var nodes: [3]Queue.Node = undefined;
    for (&nodes, 0..) |*node, index| node.* = .{ .allocator = std.testing.allocator, .value = index };
    try std.testing.expect(queue.publish(&nodes[0], io));
    try std.testing.expect(queue.publish(&nodes[1], io));
    const first_batch = queue.take();
    queue.restore(first_batch);
    try std.testing.expect(queue.publish(&nodes[2], io));
    var current = queue.take();
    for (0..3) |index| {
        try std.testing.expect(current == &nodes[index]);
        current = current.?.next;
    }
    try std.testing.expect(current == null);
    queue.restore(&nodes[0]);
    current = queue.close(io);
    for (0..3) |index| {
        try std.testing.expect(current == &nodes[index]);
        current = current.?.next;
    }
    try std.testing.expect(current == null);
    try std.testing.expect(queue.deferred == null);
    try std.testing.expect(!queue.publish(&nodes[0], io));
}

test "connection return queue reuses preallocated nodes and preserves publication order" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    const first = try Queue.Node.create(std.testing.allocator);
    defer first.destroy();
    const second = try Queue.Node.create(std.testing.allocator);
    defer second.destroy();
    first.value = 1;
    second.value = 2;
    try std.testing.expect(queue.publish(first, io));
    try std.testing.expect(queue.publish(second, io));
    const head = queue.take().?;
    try std.testing.expect(head == first);
    try std.testing.expect(head.next == second);
    try std.testing.expect(second.next == null);
    first.value = 3;
    try std.testing.expect(queue.publish(first, io));
    try std.testing.expect(queue.take() == first);
    try std.testing.expectEqual(@as(usize, 3), first.value);
    try std.testing.expect(queue.close(io) == null);
    try std.testing.expect(!queue.publish(second, io));
}

test "connection return queue detaches every concurrent publisher before close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var nodes: [128]Queue.Node = undefined;
    for (&nodes, 0..) |*node, index| node.* = .{ .allocator = std.testing.allocator, .value = index };
    const Publisher = struct {
        fn run(target: *Queue, value: std.Io, part: []Queue.Node) void {
            for (part) |*node| std.debug.assert(target.publish(node, value));
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Publisher.run, .{ &queue, io, nodes[index * 32 ..][0..32] });
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    var seen = [_]bool{false} ** 128;
    var current = queue.close(io);
    var count: usize = 0;
    while (current) |node| {
        try std.testing.expect(!seen[node.value]);
        seen[node.value] = true;
        count += 1;
        current = node.next;
    }
    try std.testing.expectEqual(@as(usize, 128), count);
    try std.testing.expect(queue.take() == null);
    try std.testing.expect(!queue.publish(&nodes[0], io));
}

test "connection return queue close races publishers without losing accepted ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue: Queue = .{};
    var nodes: [256]Queue.Node = undefined;
    for (&nodes, 0..) |*node, index| node.* = .{ .allocator = std.testing.allocator, .value = index };
    var accepted = [_]bool{false} ** 256;
    const Publisher = struct {
        fn run(target: *Queue, value: std.Io, part: []Queue.Node, result: []bool) void {
            for (part, result) |*node, *published| published.* = target.publish(node, value);
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Publisher.run, .{ &queue, io, nodes[index * 64 ..][0..64], accepted[index * 64 ..][0..64] });
        started += 1;
    }
    var current = queue.close(io);
    var seen = [_]bool{false} ** 256;
    while (current) |node| {
        try std.testing.expect(!seen[node.value]);
        seen[node.value] = true;
        current = node.next;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try std.testing.expectEqualSlices(bool, &accepted, &seen);
    try std.testing.expect(queue.close(io) == null);
}
