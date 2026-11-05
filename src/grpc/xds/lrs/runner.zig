//! Owned background LRS scheduler.
//!
//! The runner borrows the caller's control plane and source channel. The source
//! channel must outlive the runner, and its LRS statistics must be enabled.
const std = @import("std");
const shared = @import("../../channel/shared.zig");
const ControlPlane = @import("../control_plane.zig").ControlPlane;
const client_mod = @import("client.zig");
const scheduler_mod = @import("scheduler.zig");
const Client = client_mod.Client;
const Scheduler = scheduler_mod.Scheduler;

pub const Error = client_mod.Error || std.Io.ConcurrentError || error{ InvalidRunnerOptions, RunnerAlreadyStarted };

pub const Options = struct {
    client: client_mod.Options,
    reporter: scheduler_mod.Options = .{},
    /// Shutdown and deadline polling granularity for the background task.
    poll_interval: std.Io.Duration = .fromSeconds(1),
    /// Initial LRS stream establishment budget.
    connect_timeout: std.Io.Duration = .fromSeconds(5),
};

pub const Runner = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    client: Client,
    control_plane: *ControlPlane,
    scheduler: Scheduler,
    poll_interval: std.Io.Duration,
    connect_timeout: std.Io.Duration,
    shutdown: std.Io.Event = .unset,
    task: ?std.Io.Future(void) = null,
    failure: ?anyerror = null,

    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        sender: shared.Sender,
        control_plane: *ControlPlane,
        source: shared.SharedChannel,
        options: Options,
    ) Error!*Runner {
        if (options.poll_interval.nanoseconds <= 0 or
            options.connect_timeout.nanoseconds <= 0)
        {
            return error.InvalidRunnerOptions;
        }
        const self = try gpa.create(Runner);
        errdefer gpa.destroy(self);
        self.* = .{
            .allocator = gpa,
            .io = io,
            .client = undefined,
            .control_plane = control_plane,
            .scheduler = undefined,
            .poll_interval = options.poll_interval,
            .connect_timeout = options.connect_timeout,
        };
        self.client = try Client.init(gpa, sender, options.client);
        errdefer self.client.deinit();
        self.scheduler = Scheduler.init(
            gpa,
            &self.client,
            source,
            options.reporter,
        );
        return self;
    }

    pub fn deinit(self: *Runner) void {
        self.stop();
        self.scheduler.deinit();
        self.client.deinit();
        self.allocator.destroy(self);
    }

    /// Start the background report loop. The runner must not be started twice
    /// without an intervening `stop`.
    pub fn start(self: *Runner) Error!void {
        if (self.task != null) return error.RunnerAlreadyStarted;
        self.shutdown = .unset;
        self.failure = null;
        try self.client.connectWithTimeout(self.connect_timeout);
        self.task = try self.io.concurrent(run, .{self});
    }

    /// Stop and join the background loop. Safe to call more than once.
    pub fn stop(self: *Runner) void {
        self.shutdown.set(self.io);
        if (self.task) |*task| {
            task.cancel(self.io);
            self.task = null;
        }
    }

    /// Last terminal failure observed by the background loop, if any.
    pub fn failureReason(self: *const Runner) ?anyerror {
        return self.failure;
    }

    fn run(self: *Runner) void {
        while (!self.shutdown.isSet()) {
            self.scheduler.runWithControlPlaneTimeout(
                self.control_plane,
                self.poll_interval,
            ) catch |err| switch (err) {
                error.Timeout, error.Canceled => continue,
                else => {
                    self.failure = err;
                    return;
                },
            };
        }
    }
};
