//! Stack-owned commands and bounded per-origin connection-owner admission.
const std = @import("std");
const client = @import("../../client.zig");
const http3 = @import("../../../http3/mod.zig");
const Guard = @import("../../../internal/mutex_guard.zig").Guard;
const settings = @import("../shared_tcp.zig");
const exchange = @import("exchange.zig");

pub fn State(comptime PoolType: type, comptime LeaseType: type) type {
    return struct {
        const Self = @This();
        pub const Driver = @import("driver.zig").Driver(Self, PoolType, LeaseType);
        pub const Result = union(enum) {
            response: client.OwnedResponse,
            /// A negotiated H1 lease, or null for another ordinary H1 request.
            fallback: ?LeaseType,
            failure: struct { err: anyerror, was_reused: bool },
        };
        pub const Command = struct {
            request: client.RequestOptions,
            target: []const u8,
            deadline: ?std.Io.Clock.Timestamp,
            canceled: bool = false,
            pool_closed: bool = false,
            completed: bool = false,
            started: bool = false,
            exchange: ?exchange.Exchange = null,
            result: ?Result = null,
            done: std.Io.Event = .unset,
        };
        allocator: std.mem.Allocator,
        io: std.Io,
        options: settings.Options,
        mutex: std.Io.Mutex = .init,
        drivers: std.ArrayList(*Driver) = .empty,
        tasks: std.Io.Group = .init,
        requests: usize = 0,
        closed: bool = false,

        pub fn create(allocator: std.mem.Allocator, io: std.Io, options: settings.Options) !*Self {
            if (options.max_requests == 0 or options.max_streams_per_connection == 0 or
                options.write_chunk_bytes == 0 or options.output_timeout.nanoseconds <= 0)
                return error.InvalidSharedRequestOptions;
            const self = try allocator.create(Self);
            self.* = .{ .allocator = allocator, .io = io, .options = options };
            return self;
        }

        pub fn closeBefore(self: *Self, deadline: ?std.Io.Clock.Timestamp) !void {
            var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
            defer guard.unlock();
            self.closed = true;
            for (self.drivers.items) |driver| {
                for (driver.commands.items) |command| if (!command.started) {
                    command.pool_closed = true;
                };
                driver.wake.set(self.io);
            }
        }

        pub fn deinit(self: *Self) void {
            self.closeBefore(null) catch unreachable;
            // Pool destruction requires all request calls to have finished.
            // Joining also retires an owner that just delivered its last result.
            self.tasks.cancel(self.io);
            std.debug.assert(self.requests == 0 and self.drivers.items.len == 0);
            self.drivers.deinit(self.allocator);
            self.allocator.destroy(self);
        }

        pub fn request(self: *Self, pool: *PoolType, uri: []const u8, target: []const u8, options: client.RequestOptions, deadline: ?std.Io.Clock.Timestamp, isolate_origin: bool) !Result {
            if (pool.options.client.protocol_policy == .http1_only or
                pool.options.client.http2_limits.enable_push or
                std.mem.eql(u8, options.method, "CONNECT") or
                (std.mem.startsWith(u8, uri, "http:") and pool.options.client.cleartext_protocol == .http1))
                return .{ .fallback = null };
            var command = Command{ .request = options, .target = target, .deadline = deadline };
            var key = try PoolType.Internal.requestOriginKey(pool.allocator, uri);
            var key_owned = true;
            defer if (key_owned) key.deinit();
            var guard = if (deadline == null) blk: {
                try self.mutex.lock(self.io);
                break :blk Guard{ .mutex = &self.mutex, .io = self.io };
            } else try Guard.initBefore(&self.mutex, self.io, deadline);
            defer guard.unlock();
            if (self.closed) return error.PoolClosed;
            if (self.requests >= self.options.max_requests) return error.SharedRequestQueueFull;
            const existing = for (self.drivers.items) |driver| {
                if (driver.isolate_origin == isolate_origin and sameOrigin(driver.key, key)) break driver;
            } else null;
            const driver = existing orelse blk: {
                const value = try Driver.create(self, pool, uri, key, isolate_origin);
                key_owned = false;
                var registered = false;
                var started = false;
                defer if (!started) {
                    if (registered) _ = self.drivers.pop();
                    value.destroy();
                };
                try self.drivers.append(self.allocator, value);
                registered = true;
                try value.commands.append(self.allocator, &command);
                self.tasks.concurrent(self.io, Driver.run, .{value}) catch |err| {
                    // An executor without a spare owner slot retains the
                    // existing synchronous request behavior.
                    if (err == error.ConcurrencyUnavailable) return .{ .fallback = null };
                    return err;
                };
                started = true;
                break :blk value;
            };
            if (existing != null) try driver.commands.append(self.allocator, &command);
            self.requests += 1;
            driver.wake.set(self.io);
            guard.unlock();
            const wait_error = self.wait(&command, deadline);
            if (wait_error) |err| {
                self.mutex.lockUncancelable(self.io);
                command.canceled = true;
                if (!command.completed) driver.wake.set(self.io);
                self.mutex.unlock(self.io);
                command.done.waitUncancelable(self.io);
                discard(self.allocator, command.result.?);
                return err;
            }
            return command.result.?;
        }

        fn wait(self: *Self, command: *Command, deadline: ?std.Io.Clock.Timestamp) ?anyerror {
            const absolute = deadline orelse {
                command.done.wait(self.io) catch |err| return err;
                return null;
            };
            while (!command.done.isSet()) {
                command.done.waitTimeout(self.io, .{ .deadline = absolute }) catch |err| switch (err) {
                    error.Timeout => {
                        if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
                        continue;
                    },
                    error.Canceled => return error.Canceled,
                };
            }
            return null;
        }

        pub fn interrupted(self: *Self, command: *Command) ?anyerror {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (command.canceled) return error.Canceled;
            if (command.pool_closed) return error.PoolClosed;
            if (command.deadline) |until| if (until.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
            return null;
        }

        pub fn start(self: *Self, command: *Command) !void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (command.canceled) return error.Canceled;
            if (command.pool_closed) return error.PoolClosed;
            if (command.deadline) |until| if (until.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
            command.started = true;
        }

        pub fn finish(self: *Self, driver: *Driver, command: *Command, result: Result) void {
            self.mutex.lockUncancelable(self.io);
            const index = for (driver.commands.items, 0..) |value, index| {
                if (value == command) break index;
            } else unreachable;
            _ = driver.commands.orderedRemove(index);
            const last = driver.commands.items.len == 0;
            if (last) {
                const driver_index = for (self.drivers.items, 0..) |value, driver_index| {
                    if (value == driver) break driver_index;
                } else unreachable;
                _ = self.drivers.orderedRemove(driver_index);
                driver.retired = true;
            }
            self.mutex.unlock(self.io);
            // Return the last lease before exposing a terminal result, so
            // immediate lifecycle counters and sequential reuse stay exact.
            if (last) driver.releaseLease();
            self.mutex.lockUncancelable(self.io);
            self.requests -= 1;
            command.result = result;
            command.completed = true;
            command.done.set(self.io);
            self.mutex.unlock(self.io);
        }
    };
}

fn sameOrigin(a: http3.OriginKey, b: http3.OriginKey) bool {
    return a.port == b.port and std.mem.eql(u8, a.scheme, b.scheme) and std.mem.eql(u8, a.host, b.host);
}

fn discard(allocator: std.mem.Allocator, result: anytype) void {
    switch (result) {
        .response => |response| {
            var owned = response;
            owned.deinit();
        },
        .fallback => |lease| if (lease) |value| {
            var owned = value;
            owned.discard();
        },
        .failure => {},
    }
    _ = allocator;
}
