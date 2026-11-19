//! Persistent target writer. The endpoint owner lends one immutable byte range
//! until it collects completion or stops this actor; target I/O never runs on
//! the endpoint pump.

const std = @import("std");

pub fn Writer(comptime Context: type, comptime WriteError: type, comptime writeSome: anytype) type {
    return struct {
        const Self = @This();
        const Command = struct { bytes: []const u8, deadline: std.Io.Clock.Timestamp };

        pub const Completion = struct {
            reserved_bytes: usize,
            committed_bytes: usize,
            failure: ?WriteError = null,
        };

        pub const Options = struct {
            maximum_bytes: usize,
            notify_context: ?*anyopaque = null,
            notify: ?*const fn (?*anyopaque) void = null,
        };

        io: std.Io,
        context: Context,
        options: Options,
        storage: [1]Command = undefined,
        commands: std.Io.Queue(Command) = undefined,
        future: ?std.Io.Future(void) = null,
        closed: std.atomic.Value(bool) = .init(false),
        completed: std.atomic.Value(bool) = .init(false),
        completion: Completion = undefined,
        in_flight: bool = false,
        loan_bytes: usize = 0,

        /// The initialized value must retain its address until stop completes.
        pub fn init(self: *Self, io: std.Io, context: Context, options: Options) !void {
            if (options.maximum_bytes == 0) return error.InvalidWriteLimit;
            self.* = .{ .io = io, .context = context, .options = options };
            self.commands = .init(&self.storage);
            self.future = try io.concurrent(run, .{self});
        }

        pub fn submit(self: *Self, bytes: []const u8, deadline: std.Io.Clock.Timestamp) !bool {
            try self.io.checkCancel();
            if (deadline.clock != .awake) return error.InvalidDeadlineClock;
            if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
            if (bytes.len > self.options.maximum_bytes) return error.WriteLimitExceeded;
            if (bytes.len == 0 or self.in_flight or self.closed.load(.acquire)) return false;
            const count = self.commands.put(self.io, &.{.{ .bytes = bytes, .deadline = deadline }}, 0) catch |err| switch (err) {
                error.Closed => return false,
                else => return err,
            };
            if (count == 0) return false;
            self.loan_bytes = bytes.len;
            self.in_flight = true;
            return true;
        }

        /// Collection releases the loan and tells the rate owner which part of
        /// its reservation to keep charged and which part to refund.
        pub fn take(self: *Self) ?Completion {
            if (!self.in_flight or !self.completed.load(.acquire)) return null;
            const result = self.completion;
            self.completed.store(false, .release);
            self.in_flight = false;
            return result;
        }

        pub fn stop(self: *Self) ?Completion {
            self.closed.store(true, .release);
            self.commands.close(self.io);
            if (self.future) |*future| future.cancel(self.io);
            self.future = null;
            if (self.take()) |result| return result;
            if (self.in_flight) {
                self.in_flight = false;
                return .{ .reserved_bytes = self.loan_bytes, .committed_bytes = 0, .failure = error.Canceled };
            }
            return null;
        }

        fn run(self: *Self) void {
            while (!self.closed.load(.acquire)) {
                const command = self.commands.getOne(self.io) catch return;
                var result: Completion = .{ .reserved_bytes = command.bytes.len, .committed_bytes = 0 };
                if (self.closed.load(.acquire)) {
                    result.failure = error.Canceled;
                } else {
                    if (writeSome(self.io, self.context, command.bytes, command.deadline)) |count| {
                        std.debug.assert(count <= command.bytes.len);
                        result.committed_bytes = count;
                    } else |err| result.failure = err;
                }
                self.completion = result;
                self.completed.store(true, .release);
                if (self.options.notify) |notify| notify(self.options.notify_context);
                if (result.failure) |err| {
                    if (err != error.Timeout) {
                        self.closed.store(true, .release);
                        return;
                    }
                }
            }
        }
    };
}

test {
    _ = @import("inbound_actor_tests.zig");
}
