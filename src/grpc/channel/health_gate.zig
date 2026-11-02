//! Opt-in client Health Watch gate for ordinary Channel calls.
//!
//! The Watch owns a dedicated connection so it never competes with an
//! application RPC reader. SharedChannel keeps its same-connection health
//! owner; this gate is an ordinary-Channel compatibility path.
const std = @import("std");
const channel = @import("../channel.zig");
const health = @import("../health/reconnecting.zig");

pub const unknown: u8 = 0;
pub const serving: u8 = 1;
pub const not_serving: u8 = 2;

/// Optional channel-level observation points. `state_out` lets a Channel
/// publish the per-subchannel state into the owning Slot without reading the
/// Gate pointer from selection callbacks. `generation_out` and `signal` wake
/// a single-owner caller waiting for any subchannel to become serving.
pub const Wiring = struct {
    state_out: ?*std.atomic.Value(u8) = null,
    generation_out: ?*std.atomic.Value(u64) = null,
    signal: ?*std.Io.Event = null,
};

pub const Gate = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    watch: health.ReconnectingWatch,
    task: ?std.Io.Future(void) = null,
    state: std.atomic.Value(u8) = .init(unknown),
    changed: std.Io.Event = .unset,
    stopped: std.atomic.Value(bool) = .init(false),
    wiring: Wiring = .{},

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: channel.Target,
        service: []const u8,
        channel_options: channel.Options,
        wiring: Wiring,
    ) health.Error!*Gate {
        const gate = try allocator.create(Gate);
        errdefer allocator.destroy(gate);
        const watch = try health.ReconnectingWatch.init(
            allocator,
            io,
            target,
            .{
                .service_override = service,
                .channel_options = channel_options,
            },
        );
        gate.* = .{
            .allocator = allocator,
            .io = io,
            .watch = watch,
            .wiring = wiring,
        };
        // A new Gate has no status yet. Publish UNKNOWN before the watcher
        // task can report its first result.
        gate.publish(unknown);
        gate.task = io.async(Gate.run, .{gate});
        return gate;
    }

    pub fn deinit(self: *Gate) void {
        self.stopped.store(true, .release);
        if (self.task) |*task| {
            _ = task.cancel(self.io);
            _ = task.await(self.io);
        }
        self.task = null;
        self.watch.deinit();
        self.allocator.destroy(self);
    }

    pub fn isKnown(self: *const Gate) bool {
        return self.state.load(.acquire) != unknown;
    }

    pub fn isServing(self: *const Gate) bool {
        return self.state.load(.acquire) != not_serving;
    }

    /// Null while the Watch has not reported a status yet; otherwise the last
    /// known serving state.
    pub fn status(self: *const Gate) ?bool {
        return switch (self.state.load(.acquire)) {
            unknown => null,
            serving => true,
            not_serving => false,
            else => unreachable,
        };
    }

    pub fn waitForKnown(self: *Gate, deadline: ?std.Io.Clock.Timestamp) !void {
        return self.waitUntil(deadline, unknown);
    }

    pub fn waitForServing(self: *Gate, deadline: ?std.Io.Clock.Timestamp) !void {
        return self.waitUntil(deadline, not_serving);
    }

    fn waitUntil(self: *Gate, deadline: ?std.Io.Clock.Timestamp, blocked: u8) !void {
        while (self.state.load(.acquire) == blocked) {
            if (deadline) |until| {
                self.changed.waitTimeout(
                    self.io,
                    .{ .deadline = until },
                ) catch |err| switch (err) {
                    error.Timeout => {
                        if (self.state.load(.acquire) == blocked) return error.Timeout;
                        continue;
                    },
                    else => return @errorCast(err),
                };
            } else {
                try self.changed.wait(self.io);
            }
        }
    }

    fn run(self: *Gate) void {
        while (!self.stopped.load(.acquire)) {
            const until = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            });
            const event = self.watch.nextWithDeadline(until) catch |err| switch (err) {
                error.Canceled => break,
                error.Timeout => continue,
                else => {
                    self.setUnknown();
                    continue;
                },
            };
            switch (event) {
                .status => |response| self.setState(
                    if (response.status == .serving) serving else not_serving,
                ),
                .disabled => self.setState(serving),
                .retrying => self.setUnknown(),
            }
        }
    }

    fn setState(self: *Gate, value: u8) void {
        self.publish(value);
        self.changed.set(self.io);
    }

    fn setUnknown(self: *Gate) void {
        self.publish(unknown);
        self.changed.set(self.io);
    }

    fn publish(self: *Gate, value: u8) void {
        self.state.store(value, .release);
        if (self.wiring.state_out) |out| out.store(value, .release);
        if (self.wiring.generation_out) |generation| {
            _ = generation.fetchAdd(1, .acq_rel);
        }
        if (self.wiring.signal) |signal| signal.set(self.io);
    }
};
