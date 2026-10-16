//! Cloneable HTTP/3 request sender backed by one exclusive-pool driver.
//!
//! Producers enqueue stack-owned commands and wait on per-command events. The
//! sole driver groups compatible origins/routes, invokes the H3 per-stream
//! deadline/cancellation batch core, and remains the only pool/connection
//! reader. Borrowed request storage therefore remains valid until completion.

const std = @import("std");
const http3 = @import("../../mod.zig");

pub const Error = error{
    SharedDriverClosed,
    SharedDriverAlreadyRunning,
    SharedQueueFull,
    InvalidSharedOptions,
};

pub const Options = struct {
    max_queued_requests: usize = 256,
    max_batch_requests: usize = 16,
};

pub const Stats = struct {
    queued: usize,
    batches: u64,
    coalesced_requests: u64,
};

const max_batch_limit: usize = 64;

pub fn Dispatcher(comptime PoolType: type, comptime Runtime: type) type {
    return struct {
        state: *State,

        const Self = @This();
        const CommandState = enum { idle, queued, in_flight, completed };

        const Command = struct {
            uri: []const u8,
            request: Runtime.UriRequestOptions,
            alt_svc: ?http3.AltSvcTarget,
            deadline: ?std.Io.Clock.Timestamp,
            previous: ?*Command = null,
            next: ?*Command = null,
            state: CommandState = .idle,
            abandoned: bool = false,
            cancel_requested: bool = false,
            response: ?Runtime.OwnedHandshakeResponse = null,
            err: ?anyerror = null,
            done: std.Io.Event = .unset,
        };

        const State = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *PoolType,
            options: Options,
            mutex: std.Io.Mutex = .init,
            ready: std.Io.Condition = .init,
            cancel_wake: std.Io.Event = .unset,
            head: ?*Command = null,
            tail: ?*Command = null,
            queued: usize = 0,
            closed: bool = false,
            running: std.atomic.Value(bool) = .init(false),
            batches: u64 = 0,
            coalesced_requests: u64 = 0,
        };

        pub const Sender = struct {
            state: *State,

            pub fn clone(self: Sender) Sender {
                return self;
            }

            pub fn isReady(self: Sender) bool {
                const state = self.state;
                state.mutex.lockUncancelable(state.io);
                defer state.mutex.unlock(state.io);
                return !state.closed and
                    state.queued < state.options.max_queued_requests;
            }

            pub fn request(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
            ) !Runtime.OwnedHandshakeResponse {
                return self.requestBefore(uri, request_options, null, null);
            }

            pub fn requestWithTimeout(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) !Runtime.OwnedHandshakeResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    null,
                    .fromNow(self.state.io, .{
                        .raw = timeout,
                        .clock = .awake,
                    }),
                );
            }

            pub fn requestWithDeadline(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) !Runtime.OwnedHandshakeResponse {
                if (deadline.clock != .awake or
                    deadline.durationFromNow(self.state.io).raw.nanoseconds <= 0)
                {
                    return error.Timeout;
                }
                return self.requestBefore(
                    uri,
                    request_options,
                    null,
                    deadline,
                );
            }

            pub fn requestAltSvc(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
            ) !Runtime.OwnedHandshakeResponse {
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    null,
                );
            }

            pub fn requestAltSvcWithTimeout(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) !Runtime.OwnedHandshakeResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    .fromNow(self.state.io, .{
                        .raw = timeout,
                        .clock = .awake,
                    }),
                );
            }

            pub fn requestAltSvcWithDeadline(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) !Runtime.OwnedHandshakeResponse {
                if (deadline.clock != .awake or
                    deadline.durationFromNow(self.state.io).raw.nanoseconds <= 0)
                {
                    return error.Timeout;
                }
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    deadline,
                );
            }

            fn requestBefore(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                alt_svc: ?http3.AltSvcTarget,
                deadline: ?std.Io.Clock.Timestamp,
            ) !Runtime.OwnedHandshakeResponse {
                var command: Command = .{
                    .uri = uri,
                    .request = request_options,
                    .alt_svc = alt_svc,
                    .deadline = deadline,
                };
                try enqueue(self.state, &command);
                const wait_err = waitForCompletion(
                    self.state,
                    &command,
                    deadline,
                );
                if (wait_err) |err| {
                    if (cancelQueued(self.state, &command)) return err;
                    abandonInFlight(self.state, &command);
                    command.done.waitUncancelable(self.state.io);
                    discardResult(self.state, &command);
                    return err;
                }
                return takeResult(self.state, &command);
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *PoolType,
            options: Options,
        ) (std.mem.Allocator.Error || Error)!Self {
            if (options.max_queued_requests == 0 or
                options.max_batch_requests == 0 or
                options.max_batch_requests > max_batch_limit)
            {
                return error.InvalidSharedOptions;
            }
            const state = try allocator.create(State);
            state.* = .{
                .allocator = allocator,
                .io = io,
                .pool = pool,
                .options = options,
            };
            return .{ .state = state };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            std.debug.assert(!self.state.running.load(.acquire));
            std.debug.assert(self.state.head == null);
            std.debug.assert(self.state.queued == 0);
            const allocator = self.state.allocator;
            allocator.destroy(self.state);
            self.* = undefined;
        }

        pub fn sender(self: *Self) Sender {
            return .{ .state = self.state };
        }

        pub fn close(self: *Self) void {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            if (state.closed) {
                state.mutex.unlock(state.io);
                return;
            }
            state.closed = true;
            var current = state.head;
            state.head = null;
            state.tail = null;
            state.queued = 0;
            state.ready.broadcast(state.io);
            while (current) |command| {
                const next = command.next;
                command.previous = null;
                command.next = null;
                command.state = .completed;
                command.err = error.SharedDriverClosed;
                command.done.set(state.io);
                current = next;
            }
            state.mutex.unlock(state.io);
        }

        pub fn run(self: *Self) (Error || std.Io.Cancelable)!void {
            const state = self.state;
            if (state.running.swap(true, .acq_rel)) {
                return error.SharedDriverAlreadyRunning;
            }
            defer state.running.store(false, .release);
            while (true) {
                var commands: [max_batch_limit]*Command = undefined;
                const count = takeBatch(state, &commands) catch |err| switch (err) {
                    error.Canceled => {
                        self.close();
                        return error.Canceled;
                    },
                };
                if (count == 0) return;
                executeBatch(state, commands[0..count]);
            }
        }

        pub fn queuedCount(self: *Self) usize {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            return state.queued;
        }

        pub fn stats(self: *Self) Stats {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            return .{
                .queued = state.queued,
                .batches = state.batches,
                .coalesced_requests = state.coalesced_requests,
            };
        }

        fn enqueue(state: *State, command: *Command) Error!void {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (state.closed) return error.SharedDriverClosed;
            if (state.queued >= state.options.max_queued_requests) {
                return error.SharedQueueFull;
            }
            command.state = .queued;
            command.previous = state.tail;
            if (state.tail) |tail| {
                tail.next = command;
            } else {
                state.head = command;
            }
            state.tail = command;
            state.queued += 1;
            state.ready.signal(state.io);
        }

        fn cancelQueued(state: *State, command: *Command) bool {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (command.state != .queued) return false;
            detach(state, command);
            command.state = .completed;
            return true;
        }

        fn abandonInFlight(state: *State, command: *Command) void {
            var wake_driver = false;
            state.mutex.lockUncancelable(state.io);
            command.abandoned = true;
            if (command.state == .in_flight and
                !command.cancel_requested)
            {
                command.cancel_requested = true;
                wake_driver = true;
            }
            state.mutex.unlock(state.io);
            if (wake_driver) state.cancel_wake.set(state.io);
        }

        fn waitForCompletion(
            state: *State,
            command: *Command,
            deadline: ?std.Io.Clock.Timestamp,
        ) ?anyerror {
            const absolute = deadline orelse {
                command.done.wait(state.io) catch |err| return err;
                return null;
            };
            while (!command.done.isSet()) {
                command.done.waitTimeout(
                    state.io,
                    .{ .deadline = absolute },
                ) catch |err| switch (err) {
                    error.Timeout => {
                        if (absolute.durationFromNow(
                            state.io,
                        ).raw.nanoseconds <= 0) return error.Timeout;
                    },
                    error.Canceled => return error.Canceled,
                };
            }
            return null;
        }

        fn detach(state: *State, command: *Command) void {
            if (command.previous) |previous| {
                previous.next = command.next;
            } else {
                state.head = command.next;
            }
            if (command.next) |next| {
                next.previous = command.previous;
            } else {
                state.tail = command.previous;
            }
            command.previous = null;
            command.next = null;
            state.queued -= 1;
        }

        fn takeBatch(
            state: *State,
            out: *[max_batch_limit]*Command,
        ) std.Io.Cancelable!usize {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            while (state.head == null and !state.closed) {
                try state.ready.wait(state.io, &state.mutex);
            }
            const first = state.head orelse return 0;
            detach(state, first);
            first.state = .in_flight;
            out[0] = first;
            var count: usize = 1;
            while (count < state.options.max_batch_requests) {
                const next = state.head orelse break;
                if (!compatible(first, next)) break;
                detach(state, next);
                next.state = .in_flight;
                out[count] = next;
                count += 1;
            }
            return count;
        }

        fn executeBatch(state: *State, commands: []*Command) void {
            state.mutex.lockUncancelable(state.io);
            state.batches +|= 1;
            if (commands.len > 1) {
                state.coalesced_requests +|= commands.len;
            }
            state.mutex.unlock(state.io);

            var requests: [max_batch_limit]PoolType.UriBatchRequest = undefined;
            var deadlines: [max_batch_limit]?std.Io.Clock.Timestamp = undefined;
            for (commands, requests[0..commands.len], deadlines[0..commands.len]) |command, *request_value, *deadline| {
                request_value.* = .{
                    .uri = command.uri,
                    .request = command.request,
                };
                deadline.* = command.deadline;
            }

            const Mapping = struct {
                state: *State,
                commands: []*Command,

                fn observe(
                    raw: *anyopaque,
                    index: usize,
                    result: Runtime.BatchOwnedHandshakeResponseResult,
                ) void {
                    const self: *@This() = @ptrCast(@alignCast(raw));
                    switch (result) {
                        .response => |response| complete(
                            self.state,
                            self.commands[index],
                            response,
                            null,
                        ),
                        .err => |err| complete(
                            self.state,
                            self.commands[index],
                            null,
                            err,
                        ),
                    }
                }
            };
            var mapping = Mapping{ .state = state, .commands = commands };

            const Cancellation = struct {
                state: *State,
                commands: []*Command,

                fn take(raw: *anyopaque, index: usize) bool {
                    const self: *@This() = @ptrCast(@alignCast(raw));
                    self.state.mutex.lockUncancelable(self.state.io);
                    defer self.state.mutex.unlock(self.state.io);
                    const command = self.commands[index];
                    const value = command.cancel_requested;
                    command.cancel_requested = false;
                    return value;
                }

                fn acknowledge(raw: *anyopaque) void {
                    const self: *@This() = @ptrCast(@alignCast(raw));
                    self.state.mutex.lockUncancelable(self.state.io);
                    defer self.state.mutex.unlock(self.state.io);
                    for (self.commands) |command| {
                        if (command.cancel_requested) return;
                    }
                    self.state.cancel_wake.reset();
                }
            };
            var cancellation = Cancellation{
                .state = state,
                .commands = commands,
            };
            const result = if (commands[0].alt_svc) |target|
                state.pool
                    .requestUriAltSvcBatchWithPerStreamDeadlinesAndCancellation(
                    requests[0..commands.len],
                    target,
                    deadlines[0..commands.len],
                    .{ .context = &mapping, .on_result = Mapping.observe },
                    .{
                        .event = &state.cancel_wake,
                        .context = &cancellation,
                        .take_canceled = Cancellation.take,
                        .acknowledge = Cancellation.acknowledge,
                    },
                )
            else
                state.pool.requestUriBatchWithPerStreamDeadlinesAndCancellation(
                    requests[0..commands.len],
                    deadlines[0..commands.len],
                    .{ .context = &mapping, .on_result = Mapping.observe },
                    .{
                        .event = &state.cancel_wake,
                        .context = &cancellation,
                        .take_canceled = Cancellation.take,
                        .acknowledge = Cancellation.acknowledge,
                    },
                );
            result catch |err| {
                for (commands) |command| {
                    state.mutex.lockUncancelable(state.io);
                    const completed = command.state == .completed;
                    state.mutex.unlock(state.io);
                    if (!completed) complete(state, command, null, err);
                }
            };
        }

        fn complete(
            state: *State,
            command: *Command,
            response_value: ?Runtime.OwnedHandshakeResponse,
            err: ?anyerror,
        ) void {
            var response = response_value;
            state.mutex.lockUncancelable(state.io);
            if (command.abandoned) {
                command.state = .completed;
                state.mutex.unlock(state.io);
                if (response) |*owned| owned.deinit(state.pool.allocator);
                command.done.set(state.io);
                return;
            }
            command.response = response;
            response = null;
            command.err = err;
            command.state = .completed;
            state.mutex.unlock(state.io);
            command.done.set(state.io);
        }

        fn takeResult(
            state: *State,
            command: *Command,
        ) !Runtime.OwnedHandshakeResponse {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            std.debug.assert(command.state == .completed);
            if (command.err) |err| return err;
            const response = command.response.?;
            command.response = null;
            return response;
        }

        fn discardResult(state: *State, command: *Command) void {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (command.response) |*response| {
                response.deinit(state.pool.allocator);
            }
            command.response = null;
        }

        fn compatible(a: *const Command, b: *const Command) bool {
            if (!sameOrigin(a.uri, b.uri)) return false;
            return sameAltSvc(a.alt_svc, b.alt_svc);
        }

        fn sameAltSvc(
            a: ?http3.AltSvcTarget,
            b: ?http3.AltSvcTarget,
        ) bool {
            if (a == null or b == null) return a == null and b == null;
            const lhs = a.?;
            const rhs = b.?;
            return lhs.port == rhs.port and
                std.mem.eql(u8, lhs.alpn, rhs.alpn) and
                std.ascii.eqlIgnoreCase(lhs.connect_host, rhs.connect_host) and
                std.ascii.eqlIgnoreCase(lhs.origin_host, rhs.origin_host);
        }

        fn sameOrigin(lhs_text: []const u8, rhs_text: []const u8) bool {
            const lhs = std.Uri.parse(lhs_text) catch return false;
            const rhs = std.Uri.parse(rhs_text) catch return false;
            if (!std.ascii.eqlIgnoreCase(lhs.scheme, rhs.scheme)) return false;
            const lhs_port = lhs.port orelse defaultPort(lhs.scheme) orelse
                return false;
            const rhs_port = rhs.port orelse defaultPort(rhs.scheme) orelse
                return false;
            if (lhs_port != rhs_port) return false;
            const lhs_host = lhs.host orelse return false;
            const rhs_host = rhs.host orelse return false;
            return std.ascii.eqlIgnoreCase(
                componentBytes(lhs_host),
                componentBytes(rhs_host),
            );
        }

        fn componentBytes(component: std.Uri.Component) []const u8 {
            return switch (component) {
                .raw, .percent_encoded => |value| value,
            };
        }

        fn defaultPort(scheme: []const u8) ?u16 {
            if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
            return null;
        }
    };
}
