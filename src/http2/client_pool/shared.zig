//! Cloneable HTTP/2 request sender backed by one frame-reader driver.
//!
//! Producers enqueue stack-owned commands and wait on per-command events. The
//! driver is the only task allowed to touch the underlying pool. Compatible
//! requests without individual deadlines are coalesced into the pool's
//! multiplexed URI batch. Bodyful batches use its full-duplex flow-control
//! pump; independently bounded requests execute alone so one caller cannot
//! cancel sibling streams.

const std = @import("std");
const batch = @import("batch.zig");
const runtime = @import("../runtime.zig");

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

pub fn Dispatcher(comptime PoolType: type) type {
    return struct {
        state: *State,

        const Self = @This();

        const CommandState = enum {
            idle,
            queued,
            in_flight,
            completed,
        };

        const Command = struct {
            uri: []const u8,
            request: runtime.RequestOptions,
            deadline: ?std.Io.Clock.Timestamp,
            previous: ?*Command = null,
            next: ?*Command = null,
            state: CommandState = .idle,
            abandoned: bool = false,
            response: ?runtime.OwnedResponse = null,
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

            /// Sender copies are lightweight and may cross threads, but none
            /// may outlive the owning Dispatcher.
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
                request_options: runtime.RequestOptions,
            ) PoolType.SharedRequestError!runtime.OwnedResponse {
                return self.requestBefore(uri, request_options, null);
            }

            pub fn requestWithTimeout(
                self: Sender,
                uri: []const u8,
                request_options: runtime.RequestOptions,
                timeout: std.Io.Duration,
            ) PoolType.SharedRequestError!runtime.OwnedResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    .fromNow(self.state.io, .{
                        .raw = timeout,
                        .clock = .awake,
                    }),
                );
            }

            pub fn requestWithDeadline(
                self: Sender,
                uri: []const u8,
                request_options: runtime.RequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) PoolType.SharedRequestError!runtime.OwnedResponse {
                if (deadline.clock != .awake or
                    deadline.durationFromNow(self.state.io).raw.nanoseconds <= 0)
                {
                    return error.Timeout;
                }
                return self.requestBefore(uri, request_options, deadline);
            }

            fn requestBefore(
                self: Sender,
                uri: []const u8,
                request_options: runtime.RequestOptions,
                deadline: ?std.Io.Clock.Timestamp,
            ) PoolType.SharedRequestError!runtime.OwnedResponse {
                var command: Command = .{
                    .uri = uri,
                    .request = request_options,
                    .deadline = deadline,
                };
                try enqueue(self.state, &command);
                const wait_err = waitForCompletion(
                    self.state,
                    &command,
                    deadline,
                );
                if (wait_err) |err| {
                    if (cancelQueued(self.state, &command)) {
                        return @errorCast(err);
                    }
                    self.state.mutex.lockUncancelable(self.state.io);
                    command.abandoned = true;
                    self.state.mutex.unlock(self.state.io);
                    command.done.waitUncancelable(self.state.io);
                    discardResult(self.state, &command);
                    return @errorCast(err);
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

        /// Destroy after the driver task/thread has returned and every Sender
        /// call has completed. `close` wakes queued producers but deliberately
        /// does not join an executor chosen by the caller.
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

        /// Run the sole pool/connection owner until `close` is called. The
        /// caller chooses whether this lives in a std.Io task or OS thread.
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
                        continue;
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
            if (!batchEligible(first)) return count;
            while (count < state.options.max_batch_requests) {
                const next = state.head orelse break;
                if (!batchEligible(next) or
                    !sameOrigin(first.uri, next.uri)) break;
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
            if (commands.len == 1) {
                const command = commands[0];
                const result = if (command.deadline) |deadline|
                    state.pool.requestUriWithDeadline(
                        command.uri,
                        command.request,
                        deadline,
                    )
                else
                    state.pool.requestUri(command.uri, command.request);
                if (result) |response| {
                    complete(state, command, response, null);
                } else |err| {
                    complete(state, command, null, err);
                }
                return;
            }
            var requests: [max_batch_limit]batch.UriRequest = undefined;
            var responses: [max_batch_limit]runtime.OwnedResponse = undefined;
            for (commands, requests[0..commands.len]) |command, *request| {
                request.* = .{
                    .uri = command.uri,
                    .request = command.request,
                };
            }
            state.pool.requestUriBatch(
                requests[0..commands.len],
                responses[0..commands.len],
            ) catch |err| {
                for (commands) |command| complete(state, command, null, err);
                return;
            };
            for (commands, responses[0..commands.len]) |command, response| {
                complete(state, command, response, null);
            }
        }

        fn complete(
            state: *State,
            command: *Command,
            response_value: ?runtime.OwnedResponse,
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
        ) PoolType.SharedRequestError!runtime.OwnedResponse {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            std.debug.assert(command.state == .completed);
            if (command.err) |err| return @errorCast(err);
            const response = command.response.?;
            command.response = null;
            return response;
        }

        fn discardResult(state: *State, command: *Command) void {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (command.response) |*response| response.deinit(
                state.pool.allocator,
            );
            command.response = null;
        }

        fn batchEligible(command: *const Command) bool {
            return command.deadline == null and
                command.request.trailers.len == 0;
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
            if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
            if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
            return null;
        }
    };
}
