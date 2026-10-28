//! Preallocated connection returns with explicit ownership during Pool close.
const std = @import("std");

test {
    _ = @import("pool_returns/queue_tests.zig");
}

pub fn Queue(comptime Payload: type) type {
    return struct {
        head: std.atomic.Value(?*Node) = .init(null),
        publishers: std.atomic.Value(u32) = .init(0),
        const Self = @This();
        const closed_bit: u32 = 1 << 31;

        pub const Node = struct {
            allocator: std.mem.Allocator,
            next: ?*Node = null,
            value: Payload = undefined,

            pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*Node {
                const node = try allocator.create(Node);
                node.* = .{ .allocator = allocator };
                return node;
            }

            pub fn destroy(self: *Node) void {
                self.allocator.destroy(self);
            }
        };

        /// On success the queue owns node; closed queues leave it with caller.
        /// The publishing permit contains no allocation, I/O or owner locking.
        pub fn publish(self: *Self, node: *Node, io: std.Io) bool {
            var state = self.publishers.load(.acquire);
            while (true) {
                if (state & closed_bit != 0) return false;
                std.debug.assert(state < closed_bit - 1);
                if (self.publishers.cmpxchgWeak(state, state + 1, .acquire, .monotonic)) |actual| {
                    state = actual;
                } else break;
            }
            var current = self.head.load(.acquire);
            while (true) {
                node.next = current;
                if (self.head.cmpxchgWeak(current, node, .release, .acquire)) |actual| {
                    current = actual;
                } else break;
            }
            const previous = self.publishers.fetchSub(1, .release);
            if (previous == closed_bit + 1) io.futexWake(u32, &self.publishers.raw, std.math.maxInt(u32));
            return true;
        }

        /// Owner-only detachment. Reverse the stack into publication order.
        pub fn take(self: *Self) ?*Node {
            var current = self.head.swap(null, .acq_rel);
            var reversed: ?*Node = null;
            while (current) |node| {
                current = node.next;
                node.next = reversed;
                reversed = node;
            }
            return reversed;
        }

        /// Explicit Pool close waits only for already admitted publications.
        /// Every later publisher retains and destroys its own connection.
        pub fn close(self: *Self, io: std.Io) ?*Node {
            _ = self.publishers.fetchOr(closed_bit, .acq_rel);
            while (true) {
                const state = self.publishers.load(.acquire);
                if (state == closed_bit) return self.take();
                io.futexWaitUncancelable(u32, &self.publishers.raw, state);
            }
        }
    };
}
