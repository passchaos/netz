//! Stagger timer for one pending shared-endpoint address race.
//!
//! The timer owns its concurrent task so pending-acquire teardown always joins
//! it before the parent state or completion event can move out of scope.

const std = @import("std");

pub fn Timer(comptime Owner: type) type {
    return struct {
        owner: *Owner,
        deadline: std.Io.Clock.Timestamp,
        future: std.Io.Future(void) = undefined,
        future_active: bool = false,
        done: std.Io.Event = .unset,

        const Self = @This();

        pub fn init(
            owner: *Owner,
            deadline: std.Io.Clock.Timestamp,
        ) !*Self {
            const pool = owner.pool;
            const self = try pool.allocator.create(Self);
            errdefer pool.allocator.destroy(self);
            self.* = .{ .owner = owner, .deadline = deadline };
            self.future = try std.Io.concurrent(
                pool.io,
                Self.run,
                .{self},
            );
            self.future_active = true;
            return self;
        }

        fn run(self: *Self) void {
            self.deadline.wait(self.owner.pool.io) catch {};
            self.done.set(self.owner.pool.io);
            self.owner.completion_event.set(self.owner.pool.io);
        }

        pub fn completed(self: *Self) bool {
            if (!self.done.isSet()) return false;
            if (self.future_active) {
                self.future.await(self.owner.pool.io);
                self.future_active = false;
            }
            return true;
        }

        pub fn deinit(self: *Self) void {
            const pool = self.owner.pool;
            if (self.future_active) {
                self.future.cancel(pool.io);
                self.future_active = false;
            }
            pool.allocator.destroy(self);
        }
    };
}
