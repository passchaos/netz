//! Owned-result connection competition over caller-ordered targets.
const std = @import("std");
const stack_target_capacity: usize = 8;

pub const Error = std.mem.Allocator.Error || std.Io.ConcurrentError || error{
    InvalidAddressConnectPolicy,
    NoAddressReturned,
};
pub const Options = struct {
    attempt_delay: std.Io.Duration,
    max_in_flight: usize,
    cancel_event: ?*std.Io.Event = null,
};

/// Reject settled admission before planning, task entry or transport work.
/// The caller retains its phase's timeout error and original awake deadline.
pub fn checkAdmission(comptime ConnectError: type, io: std.Io, deadline: ?std.Io.Clock.Timestamp, deadline_error: ?ConnectError, canceled: ?*std.Io.Event) ConnectError!void {
    std.debug.assert((deadline == null) == (deadline_error == null));
    if (canceled) |event| if (event.isSet()) return error.Canceled;
    if (deadline) |absolute| {
        if (absolute.clock != .awake or absolute.durationFromNow(io).raw.nanoseconds <= 0) return deadline_error.?;
    }
}

/// Workers publish into stable slots before waking the selector. Cancellation
/// joins every admitted worker before closing unselected successful results.
/// Explicit concurrency prevents a blocked connect from running inline when
/// an executor's async budget is exhausted.
pub fn race(
    comptime ConnectError: type,
    comptime Connected: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    targets: anytype,
    options: Options,
    deadline: ?std.Io.Clock.Timestamp,
    deadline_error: ?ConnectError,
    context: anytype,
    comptime connect_one: anytype,
    comptime deinit_connected: anytype,
    comptime should_try_next: anytype,
) (ConnectError || Error)!Connected {
    if (targets.len == 0) return error.NoAddressReturned;
    if (options.attempt_delay.nanoseconds <= 0 or options.max_in_flight == 0) return error.InvalidAddressConnectPolicy;
    try checkAdmission(ConnectError, io, deadline, deadline_error, options.cancel_event);
    const Result = ConnectError!Connected;
    const Context = @TypeOf(context);
    const Shared = struct {
        io: std.Io,
        context: Context,
        deadline: ?std.Io.Clock.Timestamp,
        deadline_error: ?ConnectError,
        cancel_event: ?*std.Io.Event,
    };
    // Parameters remain alive through selector draining and result cleanup.
    // Only the admitted callback takes its own context value; waiting
    // candidates never duplicate the transport's handshake configuration.
    const shared: Shared = .{
        .io = io,
        .context = context,
        .deadline = deadline,
        .deadline_error = deadline_error,
        .cancel_event = options.cancel_event,
    };
    const Slot = struct {
        shared: *const Shared,
        target: std.meta.Elem(@TypeOf(targets)),
        index: usize,
        result: ?Result = null,

        fn run(self: *@This()) usize {
            const parameters = self.shared;
            checkAdmission(ConnectError, parameters.io, parameters.deadline, parameters.deadline_error, parameters.cancel_event) catch |err| {
                self.result = err;
                return self.index;
            };
            self.result = connect_one(
                parameters.context,
                parameters.io,
                self.target,
                self.index,
            );
            return self.index;
        }

        fn take(self: *@This()) Result {
            const result = self.result orelse unreachable;
            self.result = null;
            return result;
        }

        fn deinit(self: *@This()) void {
            const result = self.result orelse return;
            self.result = null;
            if (result) |value| {
                var owned = value;
                deinit_connected(self.shared.context, &owned);
            } else |_| {}
        }
    };
    const Wake = union(enum) {
        attempt: usize,
        launch: std.Io.Cancelable!void,
        deadline: std.Io.Cancelable!void,
        canceled: std.Io.Cancelable!void,
    };

    var slot_stack: [stack_target_capacity]Slot = undefined;
    const slot_heap: ?[]Slot = if (targets.len > slot_stack.len)
        try allocator.alloc(Slot, targets.len)
    else
        null;
    defer if (slot_heap) |storage| allocator.free(storage);
    const slots = slot_heap orelse slot_stack[0..targets.len];
    for (slots, targets, 0..) |*slot, target, index| {
        slot.* = .{
            .shared = &shared,
            .target = target,
            .index = index,
        };
    }
    defer for (slots) |*slot| slot.deinit();

    const wake_capacity = std.math.add(usize, targets.len, if (options.cancel_event != null) 3 else 2) catch
        return error.OutOfMemory;
    var wake_stack: [stack_target_capacity + 3]Wake = undefined;
    const wake_heap: ?[]Wake = if (wake_capacity > wake_stack.len)
        try allocator.alloc(Wake, wake_capacity)
    else
        null;
    defer if (wake_heap) |storage| allocator.free(storage);
    const wake_storage = wake_heap orelse wake_stack[0..wake_capacity];
    var select: std.Io.Select(Wake) = .init(io, wake_storage);
    defer while (select.cancel()) |_| {};
    try checkAdmission(ConnectError, io, deadline, deadline_error, options.cancel_event);
    if (deadline) |absolute| {
        try select.concurrent(.deadline, waitUntil, .{ io, absolute });
    }

    if (options.cancel_event) |event| {
        try select.concurrent(.canceled, waitForCancellation, .{ io, event });
    }

    var next_index: usize = 1;
    var active: usize = 1;
    var timer_pending = false;
    var next_launch_at = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = options.attempt_delay,
        .clock = .awake,
    });
    var last_error: ?ConnectError = null;
    try select.concurrent(.attempt, Slot.run, .{&slots[0]});
    if (next_index < slots.len and active < options.max_in_flight) {
        try select.concurrent(.launch, waitUntil, .{ io, next_launch_at });
        timer_pending = true;
    }

    while (true) {
        try checkAdmission(ConnectError, io, deadline, deadline_error, options.cancel_event);
        const wake = select.await() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
        switch (wake) {
            .attempt => |index| {
                std.debug.assert(active != 0);
                active -= 1;
                const connected = slots[index].take() catch |err| {
                    if (!should_try_next(err)) return err;
                    last_error = err;
                    if (active == 0 and next_index < slots.len) {
                        try select.concurrent(
                            .attempt,
                            Slot.run,
                            .{&slots[next_index]},
                        );
                        next_index += 1;
                        active += 1;
                        next_launch_at = .fromNow(io, .{
                            .raw = options.attempt_delay,
                            .clock = .awake,
                        });
                    }
                    if (next_index == slots.len and active == 0) {
                        return last_error.?;
                    }
                    if (next_index < slots.len and
                        active < options.max_in_flight and
                        !timer_pending)
                    {
                        if (active == 0 or
                            next_launch_at.durationFromNow(io)
                                .raw.nanoseconds <= 0)
                        {
                            try select.concurrent(
                                .attempt,
                                Slot.run,
                                .{&slots[next_index]},
                            );
                            next_index += 1;
                            active += 1;
                            next_launch_at = .fromNow(io, .{
                                .raw = options.attempt_delay,
                                .clock = .awake,
                            });
                        }
                        if (next_index < slots.len and
                            active < options.max_in_flight)
                        {
                            try select.concurrent(
                                .launch,
                                waitUntil,
                                .{ io, next_launch_at },
                            );
                            timer_pending = true;
                        }
                    }
                    continue;
                };
                return connected;
            },
            .launch => |result| {
                result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                timer_pending = false;
                if (next_index >= slots.len or
                    active >= options.max_in_flight)
                {
                    continue;
                }
                if (active != 0 and
                    next_launch_at.durationFromNow(io).raw.nanoseconds > 0)
                {
                    try select.concurrent(
                        .launch,
                        waitUntil,
                        .{ io, next_launch_at },
                    );
                    timer_pending = true;
                    continue;
                }
                try select.concurrent(.attempt, Slot.run, .{&slots[next_index]});
                next_index += 1;
                active += 1;
                next_launch_at = .fromNow(io, .{
                    .raw = options.attempt_delay,
                    .clock = .awake,
                });
                if (next_index < slots.len and
                    active < options.max_in_flight)
                {
                    try select.concurrent(
                        .launch,
                        waitUntil,
                        .{ io, next_launch_at },
                    );
                    timer_pending = true;
                }
            },
            .canceled => |result| {
                result catch |err| return err;
                return error.Canceled;
            },
            .deadline => |result| {
                result catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                };
                return deadline_error.?;
            },
        }
    }
}

fn waitUntil(io: std.Io, deadline: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
    try deadline.wait(io);
}
fn waitForCancellation(io: std.Io, event: *std.Io.Event) std.Io.Cancelable!void {
    try event.wait(io);
}
