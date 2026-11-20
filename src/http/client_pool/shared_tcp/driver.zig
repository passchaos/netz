//! One connection owner admits late requests and serializes all H2 frame I/O.
const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const Exchange = @import("exchange.zig").Exchange;

pub fn Driver(comptime State: type, comptime Pool: type, comptime Lease: type) type {
    return struct {
        const Self = @This();
        owner: *State,
        pool: *Pool,
        uri: []u8,
        key: http3.OriginKey,
        isolate_origin: bool,
        commands: std.ArrayList(*State.Command) = .empty,
        wake: std.Io.Event = .unset,
        lease: ?Lease = null,
        retired: bool = false,
        discard_connection: bool = false,

        pub fn create(owner: *State, pool: *Pool, uri: []const u8, key: http3.OriginKey, isolate_origin: bool) !*Self {
            const self = try owner.allocator.create(Self);
            errdefer owner.allocator.destroy(self);
            self.* = .{ .owner = owner, .pool = pool, .uri = try owner.allocator.dupe(u8, uri), .key = key, .isolate_origin = isolate_origin };
            return self;
        }

        pub fn destroy(self: *Self) void {
            const allocator = self.owner.allocator;
            self.commands.deinit(allocator);
            self.key.deinit();
            allocator.free(self.uri);
            allocator.destroy(self);
        }

        pub fn releaseLease(self: *Self) void {
            if (self.lease) |*lease| {
                if (self.discard_connection) lease.discard() else lease.release();
                self.lease = null;
            }
        }

        pub fn run(self: *Self) void {
            defer self.destroy();
            self.drive() catch |err| {
                self.discard_connection = true;
                self.failAll(err);
            };
        }

        fn snapshot(self: *Self, storage: []*State.Command, reset_wake: bool) []*State.Command {
            self.owner.mutex.lockUncancelable(self.owner.io);
            defer self.owner.mutex.unlock(self.owner.io);
            const values = storage[0..self.commands.items.len];
            @memcpy(values, self.commands.items);
            if (reset_wake) self.wake.reset();
            return values;
        }

        fn finish(self: *Self, command: *State.Command, result: State.Result) void {
            if (command.exchange) |*exchange| exchange.deinit(self.owner.allocator);
            command.exchange = null;
            self.owner.finish(self, command, result);
        }

        fn failure(self: *Self, command: *State.Command, err: anyerror) void {
            const reused = if (self.lease) |lease| lease.was_reused else false;
            self.finish(command, .{ .failure = .{ .err = err, .was_reused = reused } });
        }

        fn failAll(self: *Self, err: anyerror) void {
            while (!self.retired) {
                self.owner.mutex.lockUncancelable(self.owner.io);
                const command = self.commands.items[0];
                self.owner.mutex.unlock(self.owner.io);
                self.failure(command, err);
            }
        }

        fn expire(self: *Self, storage: []*State.Command) void {
            for (self.snapshot(storage, true)) |command| {
                if (self.owner.interrupted(command)) |err| self.failure(command, err);
            }
        }

        fn until(self: *Self, command: *State.Command) std.Io.Clock.Timestamp {
            const output: std.Io.Clock.Timestamp = .fromNow(self.owner.io, .{
                .clock = .awake,
                .raw = self.owner.options.output_timeout,
            });
            return if (command.deadline) |deadline|
                if (std.Io.Clock.Timestamp.compare(deadline, .lt, output)) deadline else output
            else
                output;
        }

        fn acquisitionDeadline(self: *Self) ?std.Io.Clock.Timestamp {
            self.owner.mutex.lockUncancelable(self.owner.io);
            defer self.owner.mutex.unlock(self.owner.io);
            var latest: ?std.Io.Clock.Timestamp = null;
            for (self.commands.items) |command| {
                const deadline = command.deadline orelse return null;
                if (latest == null or std.Io.Clock.Timestamp.compare(deadline, .gt, latest.?)) latest = deadline;
            }
            return latest;
        }

        fn readDeadline(self: *Self) ?std.Io.Clock.Timestamp {
            self.owner.mutex.lockUncancelable(self.owner.io);
            defer self.owner.mutex.unlock(self.owner.io);
            var earliest: ?std.Io.Clock.Timestamp = null;
            for (self.commands.items) |command| if (command.deadline) |deadline| {
                if (earliest == null or std.Io.Clock.Timestamp.compare(deadline, .lt, earliest.?)) earliest = deadline;
            };
            return earliest;
        }

        fn acquire(self: *Self) !?Lease {
            const Outcome = union(enum) { connection: anyerror!Lease, wake: std.Io.Cancelable!void };
            const Task = struct {
                fn connect(driver: *Self, deadline: ?std.Io.Clock.Timestamp) anyerror!Lease {
                    return Pool.Internal.acquireRequestBefore(driver.pool, driver.uri, deadline, driver.isolate_origin);
                }
                fn wait(io: std.Io, wake: *std.Io.Event) std.Io.Cancelable!void {
                    return wake.wait(io);
                }
            };
            var storage: [2]Outcome = undefined;
            var select: std.Io.Select(Outcome) = .init(self.owner.io, &storage);
            var selected: ?Lease = null;
            var failure_value: ?anyerror = null;
            defer while (select.cancel()) |late| {
                if (late == .connection) if (late.connection) |value| {
                    var lease = value;
                    lease.release();
                } else |_| {};
            };
            try select.concurrent(.connection, Task.connect, .{ self, self.acquisitionDeadline() });
            try select.concurrent(.wake, Task.wait, .{ self.owner.io, &self.wake });
            const outcome = try select.await();
            if (outcome == .connection) {
                if (outcome.connection) |value| selected = value else |err| failure_value = err;
            } else try outcome.wake;
            while (select.cancel()) |late| {
                if (late == .connection) {
                    if (late.connection) |value| selected = value else |err| {
                        if (err != error.Canceled) failure_value = err;
                    }
                } else late.wake catch |err| {
                    if (err != error.Canceled) return err;
                };
            }
            if (selected) |value| return value;
            if (failure_value) |err| return err;
            return null;
        }

        fn drive(self: *Self) !void {
            const storage = try self.owner.allocator.alloc(*State.Command, self.owner.options.max_requests);
            defer self.owner.allocator.free(storage);
            while (!self.retired) {
                self.expire(storage);
                if (self.retired) return;
                if (self.lease == null) {
                    self.lease = try self.acquire();
                    if (self.lease == null) continue;
                    self.expire(storage);
                    if (self.retired) return;
                }
                if (self.lease.?.protocol() == .http1) {
                    // Hand H1 back to the established exclusive path. Further
                    // requests may use other sockets under ordinary admission.
                    const values = self.snapshot(storage, false);
                    const lease = self.lease.?;
                    self.lease = null;
                    self.finish(values[0], .{ .fallback = lease });
                    for (values[1..]) |command| self.finish(command, .{ .fallback = null });
                    return;
                }
                const connection = &self.lease.?.connection().value.http2;
                var progress = false;
                for (self.snapshot(storage, false)) |command| {
                    if (self.owner.interrupted(command)) |err| {
                        self.failure(command, err);
                        continue;
                    }
                    if (command.exchange == null) {
                        if (connection.peer_goaway_last_stream_id != null or
                            connection.activeLocalStreamCount() >= self.owner.options.max_streams_per_connection or
                            (connection.availableLocalStreamCapacity() orelse 1) == 0) continue;
                        self.owner.start(command) catch |err| {
                            self.failure(command, err);
                            continue;
                        };
                        command.exchange = Exchange.init(connection, command.target, command.request, self.until(command), &self.wake, self.owner.options.write_chunk_bytes) catch |err| {
                            self.failure(command, err);
                            continue;
                        };
                        progress = true;
                    }
                    const until_value = self.until(command);
                    const response = command.exchange.?.poll(until_value) catch |err| {
                        self.failure(command, err);
                        continue;
                    };
                    if (response) |value| {
                        // A successful traditional CONNECT turns the stream
                        // into a tunnel. The aggregate caller owns only the
                        // response head, so the connection must not return to
                        // the idle pool for ordinary requests.
                        if (std.mem.eql(u8, command.request.method, "CONNECT") and
                            value.status >= 200 and value.status < 300)
                        {
                            self.discard_connection = true;
                        }
                        self.finish(command, .{ .response = .{ .allocator = self.owner.allocator, .value = .{ .http2 = value } } });
                        progress = true;
                        continue;
                    }
                    const written = command.exchange.?.write(self.owner.options.write_chunk_bytes, until_value) catch |err| {
                        self.failure(command, err);
                        continue;
                    };
                    progress = progress or written;
                }
                if (self.retired) return;
                if (connection.aggregate_timeout_unusable or connection.terminal_write_failed) return error.ConnectionClosed;
                if (connection.peer_goaway_last_stream_id != null and connection.activeLocalStreamCount() == 0) {
                    self.releaseLease();
                    continue;
                }
                if (progress) continue;
                // A command wake joins the old read and preserves any partial
                // frame/HPACK state before admission or cancellation runs.
                _ = connection.pumpClientUntilOrWake(self.readDeadline(), self.owner.options.output_timeout, &self.wake) catch |err| {
                    if (err == error.Timeout) continue;
                    return err;
                };
            }
        }
    };
}
