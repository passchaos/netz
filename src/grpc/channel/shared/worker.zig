//! One task owns an endpoint's connection, health stream, and application RPCs.
const std = @import("std");
const netz_runtime = @import("../../../runtime.zig");
const channel = @import("../../channel.zig");
const http2 = @import("../../../http2/mod.zig");
const duplex = @import("../../stream/duplex.zig");
const streaming = @import("../../stream/runtime.zig");
const health = @import("../../health.zig");
const orca_oob = @import("../../orca/oob.zig");
const orca_report = @import("../../orca.zig");
const connectivity = @import("../connectivity.zig");
const Active = @import("active.zig").Active;
const Wake = @import("wake.zig").Wake;
const keepalive = @import("keepalive.zig");
const weighted_round_robin = @import("../weighted_round_robin.zig");
const outlier_detection = @import("../outlier_detection.zig");
const Settings = @import("worker_settings.zig").Settings;
const lrs_stats = @import("lrs_stats.zig");

pub fn Worker(comptime State: type) type {
    return struct {
        parent: *State,
        source_index: usize,
        source: *State.Source,
        activation: std.Io.Event = .unset,
        settings: *Settings,
        pending_settings: ?*Settings = null,
        address: ?std.Io.net.IpAddress = null,
        eligible: bool = false,
        retired: bool = false,
        owner: channel.Channel,
        tracker: *connectivity.Tracker,
        orca_tracker: *State.OrcaTracker,
        wake: *Wake,
        published: connectivity.State = .idle,
        capacity: usize = 0,
        /// RPCs picked for this endpoint, including work claimed but not yet
        /// materialized as an HTTP/2 stream. This is policy-instance-local as
        /// required by gRFC A48.
        outstanding_requests: usize = 0,
        local_state: connectivity.State = .idle,
        connection: ?*http2.runtime.Connection = null,
        active: std.ArrayList(Active) = .empty,
        streams: std.ArrayList(StreamOwner.Active) = .empty,
        watch: ?health.ClientWatch = null,
        orca: ?orca_oob.ClientStream = null,
        orca_disabled: bool = false,
        orca_seen: bool = false,
        orca_failures: usize = 0,
        orca_at: ?std.Io.Clock.Timestamp = null,
        health_disabled: bool = false,
        health_seen: bool = false,
        health_failures: usize = 0,
        connect_failures: usize = 0,
        connect_at: ?std.Io.Clock.Timestamp = null,
        /// Deadline at which an inactive lower-priority transport closes.
        deactivation_deadline: ?std.Io.Clock.Timestamp = null,
        backoff_reset_requested: std.atomic.Value(bool) = .init(false),
        health_at: ?std.Io.Clock.Timestamp = null,
        keep_alive: keepalive.Driver = .{},
        goaway_keepalive_applied: bool = false,
        connection_keepalive_interval: ?std.Io.Duration = null,
        wrr_weight: weighted_round_robin.Weight = .{},
        outlier: outlier_detection.Endpoint = .{},
        weighted_outliers: []outlier_detection.Endpoint = &.{},

        const Self = @This();
        const StreamOwner = @import("stream/owner.zig").Owner(State);
        pub fn run(self: *Self) std.Io.Cancelable!void {
            const parent = self.parent;
            defer {
                self.disconnect(error.SharedChannelClosed);
                self.active.deinit(self.parent.allocator);
                self.streams.deinit(self.parent.allocator);
                self.parent.publish(self, .shutdown, 0);
                self.owner.deinit();
                parent.workerStopped(self);
                self.tracker.release();
                self.orca_tracker.shutdown();
                self.orca_tracker.release();
                self.wake.release();
                parent.allocator.free(self.weighted_outliers);
                self.settings.destroy();
                if (self.pending_settings) |settings| settings.destroy();
                self.source.release();
                parent.allocator.destroy(self);
            }
            try self.activation.wait(parent.io);
            while (!self.parent.shouldStop(self, self.active.items.len == 0 and self.streams.items.len == 0)) {
                self.tick() catch |err| {
                    if (err == error.Canceled and (self.parent.isClosed() or self.parent.isRetired(self))) return error.Canceled;
                    self.disconnect(err);
                    self.scheduleConnect();
                };
            }
        }

        fn outputDeadline(self: *Self) std.Io.Clock.Timestamp {
            // Match grpc-core's Party/ExecCtx scoped time cache: one event-loop
            // scan shares its awake-clock snapshot, while any intervening I/O
            // poll refreshes the value before the next operation deadline.
            return netz_runtime.cachedAwakeTimestamp(self.parent.io)
                .addDuration(.{
                .raw = self.parent.options.operation_timeout,
                .clock = .awake,
            });
        }
        fn expired(self: *Self, time: ?std.Io.Clock.Timestamp) bool {
            return if (time) |value| std.Io.Clock.Timestamp.compare(
                value,
                .lte,
                netz_runtime.cachedAwakeTimestamp(self.parent.io),
            ) else false;
        }
        fn minimum(a: ?std.Io.Clock.Timestamp, b: ?std.Io.Clock.Timestamp) ?std.Io.Clock.Timestamp {
            if (a == null) return b;
            if (b == null) return a;
            return if (std.Io.Clock.Timestamp.compare(a.?, .lt, b.?)) a else b;
        }
        fn sleepUntilWake(self: *Self, until: ?std.Io.Clock.Timestamp) !void {
            const combined = minimum(until, self.deactivation_deadline);
            if (combined) |time| self.wake.waitTimeout(self.parent.io, .{ .deadline = time }) catch |err| {
                if (err != error.Timeout) return err;
            } else try self.wake.wait(self.parent.io);
        }
        fn scheduleConnect(self: *Self) void {
            self.connect_failures +|= 1;
            var sample: u64 = undefined;
            self.parent.io.random(std.mem.asBytes(&sample));
            self.connect_at = .fromNow(self.parent.io, .{
                .raw = self.parent.options.channel.backoff.delay(self.connect_failures, sample),
                .clock = .awake,
            });
        }
        fn dropWatch(self: *Self) void {
            if (self.watch) |*watch| watch.deinit();
            self.watch = null;
        }
        fn dropOrca(self: *Self) void {
            if (self.orca) |*stream| stream.deinit();
            self.orca = null;
        }
        fn disconnect(self: *Self, err: anyerror) void {
            self.dropWatch();
            self.dropOrca();
            if (self.parent.orcaConfigFor(self) != null) {
                self.orca_tracker.setStatus(.unavailable);
            }
            while (self.active.items.len != 0) self.failActive(0, err);
            while (self.streams.items.len != 0) StreamOwner.fail(self, 0, err);
            self.owner.disconnect() catch {};
            self.connection = null;
            self.keep_alive.disconnected();
            self.goaway_keepalive_applied = false;
            self.connection_keepalive_interval = null;
            self.parent.disconnectWrr(self);
            self.health_disabled = false;
            self.health_at = null;
            self.health_seen = false;
            self.orca_disabled = false;
            self.orca_at = null;
            self.orca_seen = false;
            self.local_state = .transient_failure;
            self.parent.publish(self, .transient_failure, 0);
            self.parent.connectionFailed(self);
        }
        /// Close the transport for a deactivated lower-priority child without
        /// reporting a connection failure or requesting re-resolution.
        fn deactivate(self: *Self) void {
            self.dropWatch();
            self.dropOrca();
            if (self.parent.orcaConfigFor(self) != null) {
                self.orca_tracker.setStatus(.unavailable);
            }
            self.owner.disconnect() catch {};
            self.connection = null;
            self.keep_alive.disconnected();
            self.goaway_keepalive_applied = false;
            self.connection_keepalive_interval = null;
            self.parent.disconnectWrr(self);
            self.health_disabled = false;
            self.health_at = null;
            self.health_seen = false;
            self.orca_disabled = false;
            self.orca_at = null;
            self.orca_seen = false;
            self.deactivation_deadline = null;
            self.local_state = .idle;
            self.parent.publish(self, .idle, 0);
        }
        fn failActive(self: *Self, index: usize, err: anyerror) void {
            const job = self.active.items[index].job;
            self.active.items[index].stream.cancel() catch {};
            self.active.items[index].deinit();
            _ = self.active.swapRemove(index);
            self.parent.finishAttempt(self, job, null, err);
        }
        fn publish(self: *Self) void {
            const connection = self.connection orelse {
                self.parent.publish(self, self.local_state, 0);
                return;
            };
            const room = self.parent.options.max_active_calls_per_endpoint - self.active.items.len - self.streams.items.len;
            const capacity = @min(room, connection.availableLocalStreamCapacity() orelse room);
            self.parent.publish(self, self.local_state, if (self.local_state == .ready) capacity else 0);
        }

        fn tick(self: *Self) !void {
            const policy = self.parent.connectionPolicy(self);
            self.parent.lock();
            const updated = self.pending_settings;
            self.pending_settings = null;
            var previous: ?*Settings = null;
            if (updated) |settings| {
                if (self.settings.equivalent(settings)) settings.destroy() else {
                    previous = self.settings;
                    self.settings = settings;
                }
            }
            self.parent.unlock();
            if (previous) |settings| {
                self.dropWatch();
                self.dropOrca();
                settings.destroy();
                self.health_disabled = false;
                self.health_at = null;
                self.health_seen = false;
                self.orca_disabled = false;
                self.orca_at = null;
                self.orca_seen = false;
                if (self.connection != null) {
                    self.local_state = if (self.settings.health_service == null) .ready else .connecting;
                }
            }
            const retiring = self.parent.isRetired(self);
            if (!retiring and self.backoff_reset_requested.swap(false, .acq_rel)) {
                self.connect_at = null;
                self.connect_failures = 0;
                self.owner.resetConnectionBackoff();
            }
            if (retiring) {
                self.dropWatch();
                self.dropOrca();
            }
            self.parent.expireQueued();
            if (policy.deactivate_now and self.connection != null and
                self.active.items.len == 0 and self.streams.items.len == 0)
            {
                self.deactivate();
                return self.sleepUntilWake(null);
            }
            self.deactivation_deadline = if (self.connection != null and
                policy.deactivate_at != null)
                std.Io.Clock.Timestamp{
                    .raw = .{ .nanoseconds = policy.deactivate_at.? },
                    .clock = .awake,
                }
            else
                null;
            if (!policy.active and self.connection == null and
                self.active.items.len == 0 and self.streams.items.len == 0)
            {
                const until: ?std.Io.Clock.Timestamp = if (policy.wake_at) |nanoseconds|
                    .{ .raw = .{ .nanoseconds = nanoseconds }, .clock = .awake }
                else
                    null;
                return self.sleepUntilWake(until);
            }
            if (self.connection == null) {
                if (retiring) return;
                if (self.connect_at != null) {
                    if (!self.expired(self.connect_at)) {
                        return self.sleepUntilWake(minimum(
                            self.connect_at,
                            self.parent.nextQueuedDeadline(),
                        ));
                    }
                    // grpc-core reports IDLE once reconnect backoff elapses;
                    // the following CONNECTING then restarts the priority
                    // failover timer. Re-evaluate the policy here so the
                    // runtime observes IDLE before this task publishes
                    // CONNECTING in the same turn.
                    self.local_state = .idle;
                    self.publish();
                    _ = self.parent.connectionPolicy(self);
                }
                self.local_state = .connecting;
                self.publish();
                self.owner.resetConnectionBackoff();
                self.connection = try self.owner.connectWithDeadline(.fromNow(self.parent.io, .{ .raw = self.parent.options.channel.backoff.min_connect_timeout, .clock = .awake }));
                self.keep_alive.connected(self.parent.io);
                self.goaway_keepalive_applied = false;
                self.connection_keepalive_interval = if (self.parent.keepAliveOptions()) |options|
                    options.interval
                else
                    null;
                self.connect_at = null;
                self.connect_failures = 0;
                self.health_failures = 0;
                self.orca_failures = 0;
                self.local_state = if (self.settings.health_service == null) .ready else .connecting;
            }
            const connection = self.connection.?;
            self.keep_alive.observeAcknowledgement(
                self.parent.io,
                connection,
                &self.parent.keepalive_counters,
            );
            if (connection.peer_goaway_last_stream_id != null) {
                if (!self.goaway_keepalive_applied and
                    connection.peerGoAwayTooManyPings())
                {
                    self.goaway_keepalive_applied = true;
                    if (self.connection_keepalive_interval) |interval| {
                        _ = self.parent.applyKeepAliveThrottle(interval);
                    }
                }
                self.dropWatch();
                self.dropOrca();
                if (self.parent.orcaConfigFor(self) != null) {
                    self.orca_tracker.setStatus(.unavailable);
                }
                self.local_state = .transient_failure;
                self.publish();
                if (self.active.items.len == 0 and self.streams.items.len == 0) {
                    self.disconnect(error.ConnectionGoAway);
                    self.connect_at = null;
                    return;
                }
            } else if (!retiring and self.settings.health_service != null and !self.health_disabled and self.watch == null and (self.health_at == null or self.expired(self.health_at))) {
                var options = self.parent.options.health_metadata;
                options.service = self.settings.health_service.?;
                self.watch = try health.startWatchWithDeadline(connection, self.parent.allocator, options, self.outputDeadline());
                self.health_at = null;
                self.health_seen = false;
                self.local_state = .connecting;
            }
            if (connection.peer_goaway_last_stream_id == null and
                !retiring and self.parent.orcaConfigFor(self) != null and
                !self.orca_disabled and self.orca == null and
                (self.orca_at == null or self.expired(self.orca_at)))
            {
                const config = self.parent.orcaConfigFor(self).?;
                const opened: ?orca_oob.ClientStream = orca_oob.startPreparedWithDeadline(
                    connection,
                    self.parent.allocator,
                    config.options,
                    config.request,
                    self.outputDeadline(),
                ) catch |err| blk: {
                    if (connection.aggregate_timeout_unusable) return err;
                    self.retryOrca();
                    break :blk null;
                };
                if (opened) |stream| {
                    self.orca = stream;
                    self.orca_at = null;
                    self.orca_seen = false;
                }
            }
            var progress = try self.pollHealth();
            progress = try self.pollOrca() or progress;
            self.publish();
            var i: usize = 0;
            while (i < self.active.items.len) {
                const item = &self.active.items[i];
                const timed_out = self.expired(item.job.deadline);
                if (self.parent.canceled(item.job) or timed_out) {
                    self.failActive(
                        i,
                        if (timed_out) error.Timeout else error.Canceled,
                    );
                    progress = true;
                    continue;
                }
                const input = item.stream.pollResponseEventWithDeadline(self.outputDeadline(), item, Active.consume) catch |err| {
                    self.failActive(i, err);
                    progress = true;
                    continue;
                };
                if (input) |ready| {
                    var event = ready;
                    switch (event) {
                        .terminal => |terminal| {
                            if (self.parent.wantsWrr(self, false)) {
                                const headers = if (terminal.head) |head| head.headers else &.{};
                                if (orca_report.fromMetadataAlloc(
                                    self.parent.allocator,
                                    headers,
                                    terminal.trailers orelse &.{},
                                )) |owned_optional| {
                                    if (owned_optional) |owned_value| {
                                        var owned = owned_value;
                                        defer owned.deinit();
                                        self.parent.updateWrr(
                                            self,
                                            owned.report,
                                            false,
                                        );
                                    }
                                } else |_| {}
                            }
                            const result = item.finish(terminal) catch |err| {
                                var abandoned = terminal;
                                abandoned.deinit();
                                self.failActive(i, err);
                                progress = true;
                                continue;
                            };
                            const job = item.job;
                            item.deinit();
                            _ = self.active.swapRemove(i);
                            self.parent.finishAttempt(self, job, result, null);
                            progress = true;
                            continue;
                        },
                        .initial_metadata, .informational => item.observed_head = true,
                        .messages => {},
                    }
                    event.deinit(self.parent.allocator);
                    progress = true;
                }
                if (!item.stream.requestFinished()) {
                    const before = item.stream.transport.requestCommittedBytes();
                    _ = item.stream.pollResumeMessageWithDeadline(self.outputDeadline(), self.parent.options.max_write_bytes_per_turn) catch |err| {
                        self.failActive(i, err);
                        progress = true;
                        continue;
                    };
                    if (before != item.stream.transport.requestCommittedBytes()) progress = true;
                }
                i += 1;
            }
            if (connection.aggregate_timeout_unusable) return error.ConnectionClosed;
            progress = try StreamOwner.tick(self, self.outputDeadline()) or progress;
            self.publish();
            while (self.parent.claim(self)) |job| {
                progress = true;
                if (job.stream != null) {
                    StreamOwner.open(self, job, self.outputDeadline()) catch |err| {
                        self.parent.finishAttempt(self, job, null, err);
                        if (connection.aggregate_timeout_unusable) return err;
                    };
                    self.publish();
                    continue;
                }
                self.active.ensureUnusedCapacity(self.parent.allocator, 1) catch |err| {
                    self.parent.finishAttempt(self, job, null, err);
                    continue;
                };
                const options: streaming.RequestOptions = .{
                    .path = job.options.path,
                    .authority = job.options.authority,
                    .scheme = job.options.scheme,
                    .compression = job.options.compression,
                    .compression_level = job.options.compression_level,
                    .accepted_encodings = job.options.accepted_encodings,
                    .timeout = job.options.timeout,
                    .metadata = job.options.metadata,
                    .binary_metadata = job.options.binary_metadata,
                    .max_message_size = job.options.max_message_size,
                    .max_request_message_size = job.options.max_request_message_size,
                    .max_response_message_size = job.options.max_response_message_size,
                    .previous_attempts = job.previous_attempts,
                };
                var stream = duplex.startDuplexWithRetryDeadlines(
                    connection,
                    self.parent.allocator,
                    options,
                    job.rpc_deadline,
                    job.deadline,
                    minimum(job.deadline, self.outputDeadline()).?,
                ) catch |err| {
                    self.parent.finishAttempt(self, job, null, err);
                    if (connection.aggregate_timeout_unusable) return err;
                    continue;
                };
                job.lrs_started = true;
                if (lrs_stats.clusterName(self.source.endpoint)) |cluster| self.parent.lrs_stats.recordStarted(self.parent.io, cluster, lrs_stats.endpointAddress(self.source.endpoint));
                const storage = job.owned_message orelse {
                    stream.deinit();
                    self.parent.finishAttempt(self, job, null, error.InvalidStreamState);
                    continue;
                };
                const transferred = stream.stageOwnedMessageStorage(
                    storage,
                    .{},
                    true,
                ) catch |err| {
                    stream.deinit();
                    self.parent.finishAttempt(self, job, null, err);
                    continue;
                };
                if (transferred) {
                    job.owned_message = null;
                    job.options.message = &.{};
                } else {
                    job.releaseMessage();
                }
                self.active.appendAssumeCapacity(.{ .job = job, .stream = stream });
                self.publish();
            }
            if (progress) return;
            var until = minimum(
                self.deactivation_deadline,
                minimum(
                    self.parent.nextQueuedDeadline(),
                    minimum(
                        self.parent.nextOutlierDeadline(),
                        minimum(self.health_at, self.orca_at),
                    ),
                ),
            );
            for (self.active.items) |item| until = minimum(until, item.job.deadline);
            for (self.streams.items) |item| {
                until = minimum(until, item.call.deadline);
                self.parent.lock();
                if (item.call.write) |write| until = minimum(until, write.deadline);
                self.parent.unlock();
            }
            const keep_alive_options = self.parent.keepAliveOptions();
            self.connection_keepalive_interval = if (keep_alive_options) |options|
                options.interval
            else
                null;
            const keep_alive_until = self.keep_alive.nextDeadline(
                keep_alive_options,
                self.hasActiveCalls(),
            );
            const keep_alive_first = if (keep_alive_until) |probe|
                until == null or std.Io.Clock.Timestamp.compare(probe, .lt, until.?)
            else
                false;
            const read_until = if (keep_alive_first) keep_alive_until else until;
            const event = connection.pumpClientUntilOrWake(
                read_until,
                self.parent.options.operation_timeout,
                &self.wake.event,
            ) catch |err| {
                if (err == error.Timeout and !connection.aggregate_timeout_unusable) {
                    if (keep_alive_first) {
                        try self.keep_alive.handleDeadline(
                            self.parent.io,
                            connection,
                            keep_alive_options,
                            self.hasActiveCalls(),
                            self.outputDeadline(),
                            &self.parent.keepalive_counters,
                        );
                    }
                    return;
                }
                return err;
            };
            self.keep_alive.observePump(
                self.parent.io,
                connection,
                event,
                &self.parent.keepalive_counters,
            );
        }

        fn hasActiveCalls(self: *const Self) bool {
            return self.active.items.len != 0 or
                self.streams.items.len != 0 or self.watch != null or
                self.orca != null;
        }

        fn pollHealth(self: *Self) !bool {
            const watch = if (self.watch) |*value| value else return false;
            var progress = false;
            while (true) {
                const next = watch.pollNextWithDeadline(self.outputDeadline()) catch |err| {
                    if (err == error.Canceled) return err;
                    if (self.connection.?.aggregate_timeout_unusable) return err;
                    self.retryHealth();
                    return true;
                };
                if (next) |ready| {
                    var event = ready;
                    switch (event) {
                        .status => |status| {
                            self.health_seen = true;
                            self.local_state = if (status.status == .serving) .ready else .transient_failure;
                            progress = true;
                        },
                        .terminal => |terminal| {
                            if (terminal.status == .unimplemented) {
                                self.dropWatch();
                                self.health_disabled = true;
                                self.local_state = .ready;
                            } else self.retryHealth();
                            event.deinit();
                            return true;
                        },
                    }
                    event.deinit();
                } else break;
            }
            if (watch.request_pending) {
                const before = watch.stream.transport.requestCommittedBytes();
                if (try watch.stream.pollResumeMessageWithDeadline(self.outputDeadline(), self.parent.options.max_write_bytes_per_turn) == .complete) watch.request_pending = false;
                if (before != watch.stream.transport.requestCommittedBytes()) progress = true;
            }
            return progress;
        }
        fn retryHealth(self: *Self) void {
            self.dropWatch();
            self.local_state = .transient_failure;
            var delay: std.Io.Duration = .zero;
            if (self.health_seen) self.health_failures = 0 else {
                self.health_failures +|= 1;
                var sample: u64 = undefined;
                self.parent.io.random(std.mem.asBytes(&sample));
                delay = self.parent.options.channel.backoff.delay(self.health_failures, sample);
            }
            self.health_seen = false;
            self.health_at = .fromNow(self.parent.io, .{ .raw = delay, .clock = .awake });
        }
        fn pollOrca(self: *Self) !bool {
            const stream = if (self.orca) |*value| value else return false;
            var progress = false;
            while (true) {
                const next = stream.pollNextWithDeadline(
                    self.outputDeadline(),
                ) catch |err| {
                    if (err == error.Canceled) return err;
                    if (self.connection.?.aggregate_timeout_unusable) return err;
                    self.retryOrca();
                    return true;
                };
                if (next) |ready| {
                    var event = ready;
                    switch (event) {
                        .report => |*report| {
                            self.orca_seen = true;
                            self.parent.updateWrr(self, report.report, true);
                            self.orca_tracker.publish(report);
                            event = undefined;
                            progress = true;
                        },
                        .terminal => |terminal| {
                            if (terminal.status == .unimplemented) {
                                self.dropOrca();
                                self.orca_disabled = true;
                                self.orca_tracker.setStatus(.unimplemented);
                            } else self.retryOrca();
                            event.deinit();
                            return true;
                        },
                    }
                } else break;
            }
            if (stream.request_pending) {
                const before = stream.stream.transport.requestCommittedBytes();
                try stream.resumeRequestWithDeadline(self.outputDeadline());
                if (before != stream.stream.transport.requestCommittedBytes()) {
                    progress = true;
                }
            }
            return progress;
        }
        fn retryOrca(self: *Self) void {
            self.dropOrca();
            self.orca_tracker.setStatus(.unavailable);
            var delay: std.Io.Duration = .zero;
            if (self.orca_seen) {
                self.orca_failures = 0;
            } else {
                self.orca_failures +|= 1;
                var sample: u64 = undefined;
                self.parent.io.random(std.mem.asBytes(&sample));
                delay = self.parent.options.channel.backoff.delay(
                    self.orca_failures,
                    sample,
                );
            }
            self.orca_seen = false;
            self.orca_at = .fromNow(self.parent.io, .{
                .raw = delay,
                .clock = .awake,
            });
        }
    };
}
