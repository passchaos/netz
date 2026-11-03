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
    /// First delay after a failed reconnect. Doubles after each failure up to
    /// `retry_max_ns`.
    retry_initial_ns: u64 = 100 * std.time.ns_per_ms,
    retry_max_ns: u64 = 10 * std.time.ns_per_s,

    pub fn init(allocator: std.mem.Allocator, client: *Client, source: channel.SharedChannel, options: Options) Scheduler {
        return .{ .client = client, .reporter = Reporter.init(allocator, client, source, options) };
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
    /// Run the report loop across control-plane failures. A terminal stream
    /// first reconnects on the current server; if that fails, the scheduler
    /// moves the shared control channel to the next usable server, rebinds
    /// this client and reconnects with the retained node. Failed reconnects are
    /// retried with exponential backoff until the overall deadline. Reporting
    /// resumes one interval after a successful reconnect.
    pub fn runWithControlPlane(self: *Scheduler, control_plane: *ControlPlane, deadline: std.Io.Clock.Timestamp) ResilientError!void {
        const io = self.client.sender.state.io;
        var delay_ns = self.retry_initial_ns;
        while (true) {
            self.run(deadline) catch |err| switch (err) {
                error.LrsTerminal => {
                    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
                    while (true) {
                        control_plane.reconnectLrsWithDeadline(self.client, deadline) catch |reconnect_err| {
                            if (permanentFailure(reconnect_err)) return reconnect_err;
                            control_plane.failoverLrsWithDeadline(self.client, self.client.request, deadline) catch |failover_err| {
                                if (permanentFailure(failover_err)) return failover_err;
                                const remaining = deadline.durationFromNow(io).raw.nanoseconds;
                                if (remaining <= 0) return error.Timeout;
                                try std.Io.sleep(io, .fromNanoseconds(@min(@as(i96, @intCast(delay_ns)), remaining)), .awake);
                                delay_ns = @min(delay_ns * 2, self.retry_max_ns);
                                continue;
                            };
                        };
                        delay_ns = self.retry_initial_ns;
                        self.reporter.last_report_ns = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
                        break;
                    }
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

fn permanentFailure(err: anyerror) bool {
    return switch (err) {
        error.OutOfMemory,
        error.InvalidLrsOptions,
        error.InvalidLoadReport,
        error.LoadReportLimitExceeded,
        error.InvalidControlPlaneOptions,
        error.NoUsableXdsServer,
        error.InvalidBootstrap,
        error.InvalidBootstrapNode,
        error.InvalidBootstrapTls,
        error.InvalidServerUri,
        error.UnsupportedBootstrapCreds,
        error.UnsupportedBootstrapFeature,
        => true,
        else => false,
    };
}
