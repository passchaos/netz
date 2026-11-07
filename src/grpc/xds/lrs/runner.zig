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
const ErrorCode = std.meta.Int(.unsigned, @bitSizeOf(anyerror));

pub const Error = client_mod.Error || std.Io.ConcurrentError || error{ InvalidRunnerOptions, RunnerAlreadyStarted };

pub const Options = struct {
    client: client_mod.Options,
    reporter: scheduler_mod.Options = .{},
    /// Shutdown and deadline polling granularity for the background task.
    poll_interval: std.Io.Duration = .fromSeconds(1),
    /// Initial LRS stream establishment budget.
    connect_timeout: std.Io.Duration = .fromSeconds(5),
    stop_when_idle: bool = false,
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
    failure: std.atomic.Value(ErrorCode) = .init(0),
    activation: std.Io.Event = .unset,
    finished: std.atomic.Value(bool) = .init(false),
    stop_when_idle: bool = false,
    retirement_mutex: std.Io.Mutex = .init,
    publication_pins: usize = 0,

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
            .stop_when_idle = options.stop_when_idle,
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
        self.failure.store(0, .release);
        self.finished.store(false, .release);
        try self.client.connectWithTimeout(self.connect_timeout);
        self.task = try self.io.concurrent(run, .{self});
    }

    /// Reserve the task before publication; network opening waits for activation.
    pub fn prepareStart(self: *Runner) Error!void {
        if (self.task != null) return error.RunnerAlreadyStarted;
        self.shutdown = .unset;
        self.activation = .unset;
        self.failure.store(0, .release);
        self.finished.store(false, .release);
        self.task = try self.io.concurrent(runPrepared, .{self});
    }

    pub fn activate(self: *Runner) void {
        self.activation.set(self.io);
    }

    /// Prevent idle retirement while a publication stages reuse of this owner.
    pub fn pinPublication(self: *Runner) bool {
        self.retirement_mutex.lockUncancelable(self.io);
        defer self.retirement_mutex.unlock(self.io);
        if (self.finished.load(.acquire)) return false;
        self.publication_pins += 1;
        return true;
    }

    pub fn unpinPublication(self: *Runner) void {
        self.retirement_mutex.lockUncancelable(self.io);
        defer self.retirement_mutex.unlock(self.io);
        std.debug.assert(self.publication_pins != 0);
        self.publication_pins -= 1;
    }

    fn runPrepared(self: *Runner) void {
        self.activation.wait(self.io) catch {
            self.finished.store(true, .release);
            return;
        };
        self.run();
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
        const code = self.failure.load(.acquire);
        return if (code == 0) null else @errorFromInt(code);
    }

    fn run(self: *Runner) void {
        defer self.finished.store(true, .release);
        while (!self.shutdown.isSet()) {
            if (self.stop_when_idle) if (self.scheduler.reporter.source_key) |key| {
                self.retirement_mutex.lockUncancelable(self.io);
                const idle = self.publication_pins == 0 and !self.scheduler.reporter.source.state.lrs_stats.sourceActive(self.io, key);
                if (idle) self.finished.store(true, .release);
                self.retirement_mutex.unlock(self.io);
                if (idle) return;
            };
            if (self.client.stream == null) {
                self.client.connectWithTimeout(self.connect_timeout) catch |err| {
                    if (!self.stop_when_idle) {
                        self.failure.store(@intFromError(err), .release);
                        return;
                    }
                    std.Io.sleep(self.io, self.poll_interval, .awake) catch return;
                    continue;
                };
            }
            self.scheduler.runWithControlPlaneTimeout(
                self.control_plane,
                self.poll_interval,
            ) catch |err| switch (err) {
                error.Timeout, error.Canceled => continue,
                else => {
                    if (self.stop_when_idle) {
                        self.client.disconnect();
                        std.Io.sleep(self.io, self.poll_interval, .awake) catch return;
                        continue;
                    }
                    self.failure.store(@intFromError(err), .release);
                    return;
                },
            };
        }
    }
};
