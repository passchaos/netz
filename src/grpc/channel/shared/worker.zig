//! One task owns an endpoint's connection, health stream, and application RPCs.
const std = @import("std");
const channel = @import("../../channel.zig");
const http2 = @import("../../../http2/mod.zig");
const duplex = @import("../../stream/duplex.zig");
const streaming = @import("../../stream/runtime.zig");
const health = @import("../../health.zig");
const connectivity = @import("../connectivity.zig");
const Active = @import("active.zig").Active;
const Wake = @import("wake.zig").Wake;
const keepalive = @import("keepalive.zig");

pub fn Worker(comptime State: type) type {
    return struct {
        parent: *State,
        source_index: usize,
        address: ?std.Io.net.IpAddress = null,
        eligible: bool = false,
        retired: bool = false,
        owner: channel.Channel,
        tracker: *connectivity.Tracker,
        wake: *Wake,
        published: connectivity.State = .idle,
        capacity: usize = 0,
        local_state: connectivity.State = .idle,
        connection: ?*http2.runtime.Connection = null,
        active: std.ArrayList(Active) = .empty,
        streams: std.ArrayList(StreamOwner.Active) = .empty,
        watch: ?health.ClientWatch = null,
        health_disabled: bool = false,
        health_seen: bool = false,
        health_failures: usize = 0,
        connect_failures: usize = 0,
        connect_at: ?std.Io.Clock.Timestamp = null,
        health_at: ?std.Io.Clock.Timestamp = null,
        keep_alive: keepalive.Driver = .{},

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
                self.wake.release();
                parent.allocator.destroy(self);
            }
            while (!self.parent.shouldStop(self, self.active.items.len == 0 and self.streams.items.len == 0)) {
                self.tick() catch |err| {
                    if (err == error.Canceled and (self.parent.isClosed() or self.parent.isRetired(self))) return error.Canceled;
                    self.disconnect(err);
                    self.scheduleConnect();
                };
            }
        }

        fn outputDeadline(self: *Self) std.Io.Clock.Timestamp {
            return .fromNow(self.parent.io, .{ .raw = self.parent.options.operation_timeout, .clock = .awake });
        }
        fn expired(self: *Self, time: ?std.Io.Clock.Timestamp) bool {
            return if (time) |value| value.durationFromNow(self.parent.io).raw.nanoseconds <= 0 else false;
        }
        fn minimum(a: ?std.Io.Clock.Timestamp, b: ?std.Io.Clock.Timestamp) ?std.Io.Clock.Timestamp {
            if (a == null) return b;
            if (b == null) return a;
            return if (std.Io.Clock.Timestamp.compare(a.?, .lt, b.?)) a else b;
        }
        fn sleepUntilWake(self: *Self, until: ?std.Io.Clock.Timestamp) !void {
            if (until) |time| self.wake.waitTimeout(self.parent.io, .{ .deadline = time }) catch |err| {
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
        fn disconnect(self: *Self, err: anyerror) void {
            self.dropWatch();
            while (self.active.items.len != 0) self.failActive(0, err);
            while (self.streams.items.len != 0) StreamOwner.fail(self, 0, err);
            self.owner.disconnect() catch {};
            self.connection = null;
            self.keep_alive.disconnected();
            self.health_disabled = false;
            self.health_at = null;
            self.health_seen = false;
            self.local_state = .transient_failure;
            self.parent.publish(self, .transient_failure, 0);
            self.parent.connectionFailed(self);
        }
        fn failActive(self: *Self, index: usize, err: anyerror) void {
            const job = self.active.items[index].job;
            self.active.items[index].stream.cancel() catch {};
            self.active.items[index].deinit();
            _ = self.active.swapRemove(index);
            self.parent.finish(job, null, err);
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
            const demand = self.parent.needsConnection(self);
            const retiring = self.parent.isRetired(self);
            if (retiring) self.dropWatch();
            self.parent.expireQueued();
            if (!demand and self.active.items.len == 0 and self.streams.items.len == 0) return self.sleepUntilWake(null);
            if (self.connection == null) {
                if (retiring) return;
                if (self.connect_at != null and !self.expired(self.connect_at)) return self.sleepUntilWake(minimum(self.connect_at, self.parent.nextQueuedDeadline()));
                self.local_state = .connecting;
                self.publish();
                self.owner.resetConnectionBackoff();
                self.connection = try self.owner.connectWithDeadline(.fromNow(self.parent.io, .{ .raw = self.parent.options.channel.backoff.min_connect_timeout, .clock = .awake }));
                self.keep_alive.connected(self.parent.io);
                self.connect_at = null;
                self.connect_failures = 0;
                self.health_failures = 0;
                self.local_state = if (self.parent.health_service == null) .ready else .connecting;
            }
            const connection = self.connection.?;
            self.keep_alive.observeAcknowledgement(
                self.parent.io,
                connection,
                &self.parent.keepalive_counters,
            );
            if (connection.peer_goaway_last_stream_id != null) {
                self.dropWatch();
                self.local_state = .transient_failure;
                self.publish();
                if (self.active.items.len == 0 and self.streams.items.len == 0) {
                    self.disconnect(error.ConnectionGoAway);
                    self.connect_at = null;
                    return;
                }
            } else if (!retiring and self.parent.health_service != null and !self.health_disabled and self.watch == null and (self.health_at == null or self.expired(self.health_at))) {
                var options = self.parent.options.health_metadata;
                options.service = self.parent.health_service.?;
                self.watch = try health.startWatchWithDeadline(connection, self.parent.allocator, options, self.outputDeadline());
                self.health_at = null;
                self.health_seen = false;
                self.local_state = .connecting;
            }
            var progress = try self.pollHealth();
            self.publish();
            var i: usize = 0;
            while (i < self.active.items.len) {
                const item = &self.active.items[i];
                if (self.parent.canceled(item.job) or self.expired(item.job.deadline)) {
                    self.failActive(i, if (self.expired(item.job.deadline)) error.Timeout else error.Canceled);
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
                            self.parent.finish(job, result, null);
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
                        self.parent.finish(job, null, err);
                        if (connection.aggregate_timeout_unusable) return err;
                    };
                    self.publish();
                    continue;
                }
                self.active.ensureUnusedCapacity(self.parent.allocator, 1) catch |err| {
                    self.parent.finish(job, null, err);
                    continue;
                };
                const options: streaming.RequestOptions = .{
                    .path = job.options.path,
                    .authority = job.options.authority,
                    .scheme = job.options.scheme,
                    .compression = job.options.compression,
                    .compression_level = job.options.compression_level,
                    .accepted_encodings = job.options.accepted_encodings,
                    .metadata = job.options.metadata,
                    .binary_metadata = job.options.binary_metadata,
                    .max_message_size = job.options.max_message_size,
                    .max_request_message_size = job.options.max_request_message_size,
                    .max_response_message_size = job.options.max_response_message_size,
                    .previous_attempts = job.previous_attempts,
                };
                var stream = duplex.startDuplexWithDeadlines(connection, self.parent.allocator, options, job.deadline, minimum(job.deadline, self.outputDeadline()).?) catch |err| {
                    self.parent.finish(job, null, err);
                    if (connection.aggregate_timeout_unusable) return err;
                    continue;
                };
                stream.stageFinalMessage(job.options.message, .{}) catch |err| {
                    stream.deinit();
                    self.parent.finish(job, null, err);
                    continue;
                };
                job.releaseMessage();
                self.active.appendAssumeCapacity(.{ .job = job, .stream = stream });
                self.publish();
            }
            if (progress) return;
            var until = minimum(self.parent.nextQueuedDeadline(), self.health_at);
            for (self.active.items) |item| until = minimum(until, item.job.deadline);
            for (self.streams.items) |item| {
                until = minimum(until, item.call.deadline);
                self.parent.lock();
                if (item.call.write) |write| until = minimum(until, write.deadline);
                self.parent.unlock();
            }
            const keep_alive_until = self.keep_alive.nextDeadline(
                self.parent.options.keepalive,
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
                            self.parent.options.keepalive,
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
                self.streams.items.len != 0 or self.watch != null;
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
    };
}
