//! Allocation-explicit indexed binary min-heap.
//!
//! Entries live in their owning store. The two comptime callbacks compare
//! entry indexes and keep each entry's reverse heap position synchronized,
//! allowing arbitrary removal and deadline updates in O(log n).

const std = @import("std");

pub fn IndexedMinHeap(
    comptime Context: type,
    comptime lessEntry: fn (Context, usize, usize) bool,
    comptime setPosition: fn (Context, usize, ?usize) void,
) type {
    return struct {
        const Self = @This();

        items: std.ArrayList(usize) = .empty,

        pub fn deinit(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.items.deinit(allocator);
            self.* = undefined;
        }

        pub fn ensureTotalCapacity(
            self: *Self,
            allocator: std.mem.Allocator,
            new_capacity: usize,
        ) std.mem.Allocator.Error!void {
            return self.items.ensureTotalCapacity(allocator, new_capacity);
        }

        pub fn count(self: Self) usize {
            return self.items.items.len;
        }

        pub fn capacity(self: Self) usize {
            return self.items.capacity;
        }

        pub fn entries(self: Self) []const usize {
            return self.items.items;
        }

        pub fn root(self: Self) ?usize {
            if (self.items.items.len == 0) return null;
            return self.items.items[0];
        }

        /// Append without allocating. The owner must reserve capacity before
        /// the lifecycle transition that makes an entry heap-resident.
        pub fn appendAssumeCapacity(
            self: *Self,
            context: Context,
            entry_index: usize,
        ) void {
            const heap_index = self.items.items.len;
            self.items.appendAssumeCapacity(entry_index);
            setPosition(context, entry_index, heap_index);
            self.siftUp(context, heap_index);
        }

        pub fn popRoot(
            self: *Self,
            context: Context,
        ) usize {
            std.debug.assert(self.items.items.len != 0);
            return self.remove(context, 0);
        }

        pub fn remove(
            self: *Self,
            context: Context,
            heap_index: usize,
        ) usize {
            const removed_entry = self.items.items[heap_index];
            const last = self.items.pop().?;
            setPosition(context, removed_entry, null);
            if (heap_index == self.items.items.len) return removed_entry;

            self.items.items[heap_index] = last;
            setPosition(context, last, heap_index);
            self.fix(context, heap_index);
            return removed_entry;
        }

        pub fn fix(
            self: *Self,
            context: Context,
            heap_index: usize,
        ) void {
            if (heap_index != 0) {
                const parent = (heap_index - 1) / 2;
                if (self.less(context, heap_index, parent)) {
                    self.siftUp(context, heap_index);
                    return;
                }
            }
            self.siftDown(context, heap_index);
        }

        fn siftUp(
            self: *Self,
            context: Context,
            start: usize,
        ) void {
            var index = start;
            while (index != 0) {
                const parent = (index - 1) / 2;
                if (!self.less(context, index, parent)) break;
                self.swap(context, index, parent);
                index = parent;
            }
        }

        fn siftDown(
            self: *Self,
            context: Context,
            start: usize,
        ) void {
            var index = start;
            while (true) {
                const left = index * 2 + 1;
                if (left >= self.items.items.len) return;
                const right = left + 1;
                const smallest = if (right < self.items.items.len and
                    self.less(context, right, left)) right else left;
                if (!self.less(context, smallest, index)) return;
                self.swap(context, index, smallest);
                index = smallest;
            }
        }

        fn less(
            self: Self,
            context: Context,
            a: usize,
            b: usize,
        ) bool {
            return lessEntry(
                context,
                self.items.items[a],
                self.items.items[b],
            );
        }

        fn swap(
            self: *Self,
            context: Context,
            a: usize,
            b: usize,
        ) void {
            std.mem.swap(
                usize,
                &self.items.items[a],
                &self.items.items[b],
            );
            setPosition(context, self.items.items[a], a);
            setPosition(context, self.items.items[b], b);
        }
    };
}
