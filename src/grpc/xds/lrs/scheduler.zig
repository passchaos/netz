//! Foreground LRS report loop driven by response intervals.
const std = @import("std");
const channel = @import("../../channel/shared.zig");
const Client = @import("client.zig").Client;
const Reporter = @import("reporter.zig").Reporter;
const ControlPlane = @import("../control_plane.zig").ControlPlane;
pub const Error = @import("reporter.zig").Error || error{LrsTerminal};
pub const ResilientError = Error || @import("../control_plane.zig").Error;

pub const Options = @import("reporter.zig").Options;

/// `client` and `source` are borrowed; keep them alive for the scheduler's
/// lifetime. Run the loop with `io.concurrent` and cancel it with the caller's
/// task/deadline when the application stops discovery.
pub const Scheduler = struct {
    reporter: Reporter,
    client: *Client,

    pub fn init(allocator: std.mem.Allocator, client: *Client, source: channel.SharedChannel, options: Options) Scheduler {
        var reporter = Reporter.init(allocator, client, source, options);
        // Start with a full interval before the first report instead of emitting
        // an empty report as soon as the scheduler starts.
        reporter.last_report_ns = std.Io.Clock.Timestamp.now(client.sender.state.io, .awake).raw.nanoseconds;
        return .{ .client = client, .reporter = reporter };
    }
    pub fn deinit(self: *Scheduler) void {
        self.reporter.deinit();
        self.* = undefined;
    }
    /// Read responses and emit reports at their requested interval. Returns
    /// `error.LrsTerminal` on a terminal stream or `error.Timeout` when the
    /// overall deadline expires.
    pub fn run(self: *Scheduler, deadline: std.Io.Clock.Timestamp) Error!void {
        const io = self.client.sender.state.io;
        while (true) {
            const now = std.Io.Clock.Timestamp.now(io, .awake);
            if (deadline.raw.nanoseconds <= now.raw.nanoseconds) return error.Timeout;
            const report_at = self.reporter.nextDeadline();
            const wait_until = if (report_at.raw.nanoseconds <= now.raw.nanoseconds) now else report_at;
            var event = self.client.nextWithDeadline(wait_until) catch |err| switch (err) {
                error.Timeout => {
                    const after = std.Io.Clock.Timestamp.now(io, .awake);
                    if (report_at.raw.nanoseconds <= after.raw.nanoseconds) {
                        _ = try self.reporter.reportIfDueWithDeadline(deadline);
                    }
                    continue;
                },
                else => return err,
            };
            defer event.deinit();
            switch (event) {
                .response => |response| try self.reporter.onResponse(response.value),
                .terminal => return error.LrsTerminal,
            }
        }
    }
    pub fn runWithTimeout(self: *Scheduler, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.run(.fromNow(self.client.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Run the report loop across control-plane failover. A terminal stream
    /// triggers `ControlPlane.failoverLrsWithDeadline`, which moves the shared
    /// control channel to the next usable server, rebinds this client and
    /// reconnects with the retained node. Reporting resumes after one interval
    /// on the new stream. The loop keeps retrying usable servers until the
    /// overall deadline expires; it returns the last failover error when no
    /// server accepts the new stream and `error.Timeout` at the deadline.
    pub fn runWithControlPlane(self: *Scheduler, control_plane: *ControlPlane, deadline: std.Io.Clock.Timestamp) ResilientError!void {
        const io = self.client.sender.state.io;
        while (true) {
            self.run(deadline) catch |err| switch (err) {
                error.LrsTerminal => {
                    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
                    try control_plane.failoverLrsWithDeadline(self.client, self.client.request, deadline);
                    self.reporter.last_report_ns = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
                    continue;
                },
                else => return err,
            };
        }
    }
    pub fn runWithControlPlaneTimeout(self: *Scheduler, control_plane: *ControlPlane, timeout: std.Io.Duration) ResilientError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.runWithControlPlane(control_plane, .fromNow(self.client.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
};
