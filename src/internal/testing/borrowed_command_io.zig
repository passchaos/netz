//! Observe actual waits while an independent owner retains a borrowed command.
const std = @import("std");
const forwarded = @import("forwarded_io.zig");

pub const Outcome = enum {
    canceled_before_execution,
    completed_during_cancel,
    timed_out_before_execution,
    expired_before_execution,
};

pub fn Probe(comptime Engine: type) type {
    return struct {
        const Self = @This();
        delegate: std.Io,
        table: std.Io.VTable = undefined,
        engine: *Engine,
        outcome: Outcome,
        deadline: std.Io.Clock.Timestamp,
        waiting: std.Io.Event = .unset,
        owner_begin: std.Io.Event = .unset,
        owner_done: std.Io.Event = .unset,
        shutdown: std.Io.Event = .unset,
        joins: std.atomic.Value(usize) = .init(0),
        canceled_waits: std.atomic.Value(usize) = .init(0),
        command_done: std.atomic.Value(?*const u32) = .init(null),

        fn from(context: ?*anyopaque) *Self {
            return @ptrCast(@alignCast(context.?));
        }
        fn base(self: *Self) std.Io {
            return self.delegate;
        }
        fn timeout(_: *Self, value: std.Io.Timeout) std.Io.Timeout {
            return value;
        }
        pub fn io(self: *Self) std.Io {
            self.table = forwarded.table(from, base, timeout);
            self.table.futexWait = wait;
            self.table.futexWaitUncancelable = join;
            return .{ .userdata = self, .vtable = &self.table };
        }
        fn isCommand(self: *Self, pointer: *const u32) bool {
            if (self.command_done.load(.acquire)) |done| return pointer == done;
            // Owner dispatch is gated until this first command wait is entered.
            // Capture its identity once; later callbacks never scan a live queue
            // or acquire an owner mutex recursively from a futex callback.
            for (self.engine.commands.slice()) |command| {
                if (pointer == @as(*const u32, @ptrCast(&command.done))) {
                    self.command_done.store(pointer, .release);
                    return true;
                }
            }
            return false;
        }
        fn wait(context: ?*anyopaque, pointer: *const u32, expected: u32, until: std.Io.Timeout) std.Io.Cancelable!void {
            const self = from(context);
            const io_base = self.delegate;
            if (!self.isCommand(pointer)) return io_base.vtable.futexWait(io_base.userdata, pointer, expected, until);
            self.waiting.set(io_base);
            io_base.vtable.futexWait(io_base.userdata, pointer, expected, until) catch |err| {
                if (err == error.Canceled) {
                    _ = self.canceled_waits.fetchAdd(1, .monotonic);
                    if (self.outcome == .completed_during_cancel) {
                        // A separate, uncanceled owner commits real protocol output
                        // before this actual canceled wait returns to the caller.
                        self.owner_begin.set(io_base);
                        self.owner_done.waitUncancelable(io_base);
                    }
                }
                return err;
            };
            if (self.outcome == .expired_before_execution and
                self.deadline.durationFromNow(io_base).raw.nanoseconds <= 0)
            {
                // The native timer has expired, but the caller has not marked
                // abandonment. Owner-side admission must reject this queued work.
                self.owner_begin.set(io_base);
                self.owner_done.waitUncancelable(io_base);
            }
        }
        fn join(context: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = from(context);
            const io_base = self.delegate;
            if (self.isCommand(pointer)) {
                _ = self.joins.fetchAdd(1, .monotonic);
                self.owner_begin.set(io_base);
            }
            io_base.vtable.futexWaitUncancelable(io_base.userdata, pointer, expected);
        }
        pub fn own(self: *Self) !void {
            try self.owner_begin.wait(self.delegate);
            defer self.owner_done.set(self.delegate);
            self.shutdown.set(self.delegate);
            const Handler = struct {
                fn run(_: *void, _: *Engine.Stream) !void {
                    return error.UnexpectedHandler;
                }
            };
            var context: void = {};
            _ = try self.engine.serve(void, &context, Handler.run);
        }
    };
}
