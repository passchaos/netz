//! Opt-in client Health Watch gate for ordinary Channel calls.
//!
//! The Watch owns a dedicated connection so it never competes with an
//! application RPC reader. SharedChannel keeps its same-connection health
//! owner; this gate is an ordinary-Channel compatibility path.
const std = @import("std");
const channel = @import("../channel.zig");
const health = @import("../health/reconnecting.zig");
pub const Sync = @import("health_gate/sync.zig");
pub const waitForReady = @import("health_gate/admission.zig").wait;

pub const unknown: u8 = 0;
pub const serving: u8 = 1;
pub const not_serving: u8 = 2;

/// Optional channel-level observation points. `state_out` lets a Channel
/// publish the per-subchannel state into the owning Slot without reading the
/// Gate pointer from selection callbacks. `sync` wakes a single-owner caller
/// waiting for any subchannel to become serving.
pub const Wiring = struct {
    state_out: ?*std.atomic.Value(u8) = null,
    sync: ?*Sync = null,
};

pub const Gate = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    watch: ?health.ReconnectingWatch,
    task: ?std.Io.Future(void) = null,
    state: std.atomic.Value(u8) = .init(unknown),
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
        self.allocator.destroy(self);
    }

    fn run(self: *Gate) void {
        const watch = &self.watch.?;
        // The worker is the sole Watch owner. Termination releases its
        // connection and allocation even while the Channel remains alive.
        defer {
            watch.deinit();
            self.watch = null;
        }
        var local_failures: usize = 0;
        while (!self.stopped.load(.acquire)) {
            const until = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            });
            const event = watch.nextWithDeadlineObserved(until, .{
                .context = self,
                .started = watchStarted,
            }) catch |err| switch (err) {
                error.Canceled => break,
                error.Timeout => continue,
                error.HealthWatchStopped => {
                    self.publish(not_serving);
                    return;
                },
                error.HealthWatchDisabled => {
                    self.publish(serving);
                    return;
                },
                else => {
                    // ReconnectingWatch returns local resource failures to
                    // its caller instead of scheduling a transport retry.
                    // This background owner must pause rather than spin.
                    // A retained Watch has not reported a backend failure.
                    // Preserve its last health observation while backing off
                    // the local read, so silence cannot permanently reject a
                    // backend that was already known to be serving.
                    self.publish(if (watch.watch != null and watch.last_status != null)
                        (if (watch.last_status.? == .serving) serving else not_serving)
                    else
                        not_serving);
                    local_failures +|= 1;
                    var sample: u64 = undefined;
                    self.io.random(std.mem.asBytes(&sample));
                    const retry_at: std.Io.Clock.Timestamp = .fromNow(self.io, .{
                        .clock = .awake,
                        .raw = watch.options.backoff.delay(local_failures, sample),
                    });
                    (std.Io.Timeout{ .deadline = retry_at }).sleep(self.io) catch break;
                    continue;
                },
            };
            local_failures = 0;
            switch (event) {
                .status => |response| self.setState(
                    if (response.status == .serving) serving else not_serving,
                ),
                .disabled => {
                    // UNIMPLEMENTED is terminal for this Watch. Polling it
                    // again returns HealthWatchDisabled without doing I/O.
                    self.setState(serving);
                    return;
                },
                // A failed Watch is a known admission failure. Fail-fast
                // calls reject it while wait-for-ready calls await recovery.
                .retrying => self.setState(not_serving),
            }
        }
    }

    fn setState(self: *Gate, value: u8) void {
        self.publish(value);
    }

    fn watchStarted(context: *anyopaque) void {
        const self: *Gate = @ptrCast(@alignCast(context));
        // A fresh Watch is CONNECTING rather than the preceding attempt's
        // TRANSIENT_FAILURE. Both RPC modes await its first health result.
        self.publish(unknown);
    }

    fn publish(self: *Gate, value: u8) void {
        self.state.store(value, .release);
        if (self.wiring.state_out) |out| out.store(value, .release);
        if (self.wiring.sync) |sync| sync.notify(self.io);
    }
};

test {
    _ = @import("health_gate/disabled_tests.zig");
    _ = @import("health_gate/retry_tests.zig");
    _ = @import("health_gate/cancellation_tests.zig");
    _ = @import("health_gate/restart_tests.zig");
    _ = @import("health_gate/resource_tests.zig");
    _ = @import("health_gate/read_interruption_tests.zig");
}
