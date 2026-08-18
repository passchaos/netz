//! Concurrent deadline driver for the broker Will scheduler.
//!
//! A generation futex makes deadline changes and broker shutdown wake the
//! single timer task immediately. The scheduler itself remains protected by
//! the broker state mutex; this driver only owns wait/wake coordination.

const std = @import("std");

pub const Driver = struct {
    generation: std.atomic.Value(u32) = .init(1),
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn start(self: *Driver) void {
        self.stopping.store(false, .release);
    }

    pub fn notify(self: *Driver, io: std.Io) void {
        _ = self.generation.fetchAdd(1, .release);
        io.futexWake(u32, &self.generation.raw, 1);
    }

    pub fn stop(self: *Driver, io: std.Io) void {
        self.stopping.store(true, .release);
        self.notify(io);
    }

    pub fn stopped(self: Driver) bool {
        return self.stopping.load(.acquire);
    }

    pub fn wait(
        self: *Driver,
        io: std.Io,
        observed_generation: u32,
        deadline: ?std.Io.Timestamp,
    ) std.Io.Cancelable!void {
        if (self.stopped() or
            self.generation.load(.acquire) != observed_generation)
        {
            return;
        }
        const timeout: std.Io.Timeout = if (deadline) |value|
            .{ .deadline = value.withClock(.awake) }
        else
            .none;
        const result = io.futexWaitTimeout(
            u32,
            &self.generation.raw,
            observed_generation,
            timeout,
        );
        result catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
    }

    pub fn currentGeneration(self: Driver) u32 {
        return self.generation.load(.acquire);
    }
};
