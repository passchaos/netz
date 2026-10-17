//! Cloneable HTTP/3 request sender backed by one exclusive-pool driver.
//!
//! Producers enqueue stack-owned commands and wait on per-command events. The
//! sole driver groups compatible origins/routes, invokes the H3 per-stream
//! deadline/cancellation batch core, and remains the only pool/connection
//! reader. Borrowed request storage therefore remains valid until completion.

const std = @import("std");
const http3 = @import("../../mod.zig");
const connection_budget = @import("../../../internal/connection_budget.zig");

pub const Error = error{
    SharedDriverClosed,
    SharedDriverAlreadyRunning,
    SharedQueueFull,
    InvalidSharedOptions,
};

pub const Options = struct {
    max_queued_requests: usize = 256,
    /// Maximum requests concurrently owned by one connection turn. Later
    /// compatible producers are admitted as active streams complete.
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
        pub const RequestError = Runtime.ReceiveTimeoutError ||
            Runtime.HandshakeClientPoolError || Error;
        const CommandState = enum { idle, queued, in_flight, completed };

        const Command = struct {
            uri: []const u8,
            request: Runtime.UriRequestOptions,
            alt_svc: ?http3.AltSvcTarget,
            deadline: ?std.Io.Clock.Timestamp,
            reclaimer: ?connection_budget.Reclaimer = null,
            previous: ?*Command = null,
            next: ?*Command = null,
            state: CommandState = .idle,
            abandoned: bool = false,
            cancel_requested: bool = false,
            response: ?Runtime.OwnedHandshakeResponse = null,
            err: ?RequestError = null,
            done: std.Io.Event = .unset,
        };

        const State = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *PoolType,
            options: Options,
            mutex: std.Io.Mutex = .init,
            ready: std.Io.Condition = .init,
            /// Wakes an active connection turn for newly queued work,
            /// producer cancellation, or dispatcher shutdown.
            activity: std.Io.Event = .unset,
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
            ) RequestError!Runtime.OwnedHandshakeResponse {
                return self.requestBefore(uri, request_options, null, null, null);
            }

            pub fn requestWithTimeout(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) RequestError!Runtime.OwnedHandshakeResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    null,
                    .fromNow(self.state.io, .{
                        .raw = timeout,
                        .clock = .awake,
                    }),
                    null,
                );
            }

            pub fn requestWithDeadline(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) RequestError!Runtime.OwnedHandshakeResponse {
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
                    null,
                );
            }

            pub fn requestAltSvc(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
            ) RequestError!Runtime.OwnedHandshakeResponse {
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    null,
                    null,
                );
            }

            pub fn requestAltSvcWithTimeout(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) RequestError!Runtime.OwnedHandshakeResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    .fromNow(self.state.io, .{
                        .raw = timeout,
                        .clock = .awake,
                    }),
                    null,
                );
            }

            pub fn requestAltSvcWithDeadline(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) RequestError!Runtime.OwnedHandshakeResponse {
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
                    null,
                );
            }

            /// Unified-pool hook retaining cross-transport budget reclaim while
            /// the command still participates in normal sender batching.
            pub fn requestAltSvcReclaiming(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: connection_budget.Reclaimer,
            ) RequestError!Runtime.OwnedHandshakeResponse {
                if (deadline) |absolute| {
                    if (absolute.clock != .awake or absolute.durationFromNow(
                        self.state.io,
                    ).raw.nanoseconds <= 0) return error.Timeout;
                }
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    deadline,
                    reclaimer,
                );
            }

            fn requestBefore(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                alt_svc: ?http3.AltSvcTarget,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: ?connection_budget.Reclaimer,
            ) RequestError!Runtime.OwnedHandshakeResponse {
                var command: Command = .{
                    .uri = uri,
                    .request = request_options,
                    .alt_svc = alt_svc,
                    .deadline = deadline,
                    .reclaimer = reclaimer,
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
            state.activity.set(state.io);
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
            if (state.closed) {
                state.mutex.unlock(state.io);
                return error.SharedDriverClosed;
            }
            if (state.queued >= state.options.max_queued_requests) {
                state.mutex.unlock(state.io);
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
            state.mutex.unlock(state.io);
            state.activity.set(state.io);
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
            if (wake_driver) state.activity.set(state.io);
        }

        fn waitForCompletion(
            state: *State,
            command: *Command,
            deadline: ?std.Io.Clock.Timestamp,
        ) ?RequestError {
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

        const Active = struct {
            command: *Command,
            stream_id: ?u62 = null,
        };

        fn executeBatch(state: *State, commands: []*Command) void {
            state.mutex.lockUncancelable(state.io);
            state.batches +|= 1;
            if (commands.len > 1) {
                state.coalesced_requests +|= commands.len;
            }
            state.mutex.unlock(state.io);

            var active_storage: [max_batch_limit]Active = undefined;
            for (commands, active_storage[0..commands.len]) |command, *active| {
                active.* = .{ .command = command };
            }
            var active_count = commands.len;
            var total_owned = commands.len;
            driveConnection(
                state,
                &active_storage,
                &active_count,
                &total_owned,
            ) catch |err| {
                for (active_storage[0..active_count]) |active| {
                    complete(state, active.command, null, err);
                }
                active_count = 0;
            };
        }

        fn driveConnection(
            state: *State,
            active: *[max_batch_limit]Active,
            active_count: *usize,
            total_owned: *usize,
        ) RequestError!void {
            while (active_count.* != 0) {
                try processControl(
                    state,
                    active,
                    active_count,
                    total_owned,
                    null,
                );
                if (active_count.* == 0) return;
                const before = active_count.*;
                const acquired_result = acquire(
                    state,
                    active[0].command,
                    earliestDeadline(active, active_count.*),
                );
                var lease = acquired_result catch |err| switch (err) {
                    error.Timeout => {
                        expireUnsent(state, active, active_count);
                        if (active_count.* == 0) return;
                        if (active_count.* == before) return err;
                        continue;
                    },
                    else => return err,
                };
                var reusable = true;
                defer if (lease.active) {
                    if (reusable)
                        lease.release()
                    else
                        lease.discard();
                };
                errdefer reusable = false;

                while (active_count.* != 0) {
                    try processControl(
                        state,
                        active,
                        active_count,
                        total_owned,
                        &lease,
                    );
                    if (active_count.* == 0) break;
                    try sendUnsent(state, active, active_count, &lease);
                    if (active_count.* == 0) break;

                    const maybe_event = lease.client()
                        .receiveNextResponseBeforeOrWake(
                        earliestDeadline(active, active_count.*),
                        &state.activity,
                    ) catch |err| switch (err) {
                        error.Timeout => continue,
                        else => return err,
                    };
                    if (maybe_event == null) continue;
                    var event = maybe_event.?;
                    var event_owned = true;
                    defer if (event_owned) {
                        event.deinit(state.pool.allocator);
                    };
                    const stream_id = switch (event) {
                        .response => |response| response.stream_id,
                        .reset => |reset| reset.stream_id,
                    };
                    const index = findStream(
                        active,
                        active_count.*,
                        stream_id,
                    ) orelse return error.UnexpectedStream;
                    const command = active[index].command;
                    switch (event) {
                        .response => |response_value| {
                            var response = response_value.value;
                            event_owned = false;
                            if (response.response.status == 421) {
                                lease.client().removePeerOriginAfterMisdirected(
                                    lease.requestOrigin(),
                                ) catch |err| {
                                    response.deinit(state.pool.allocator);
                                    return err;
                                };
                            }
                            complete(state, command, response, null);
                        },
                        .reset => |reset| complete(
                            state,
                            command,
                            null,
                            if (reset.application_error_code ==
                                http3.ApplicationErrorCode.request_rejected)
                                error.RequestRejected
                            else
                                error.RequestCancelled,
                        ),
                    }
                    removeActive(active, active_count, index);
                }

                if (state.pool.options.peer_settings_observer) |observer| {
                    if (lease.client().peerSettings()) |settings| {
                        observer.observe(
                            observer.context,
                            lease.requestOrigin(),
                            settings,
                        );
                    }
                }
                return;
            }
        }

        fn acquire(
            state: *State,
            command: *Command,
            deadline: ?std.Io.Clock.Timestamp,
        ) RequestError!PoolType.Lease {
            if (command.alt_svc) |target| {
                if (command.reclaimer) |reclaimer| {
                    return state.pool.acquireUriAltSvcReclaiming(
                        command.uri,
                        target,
                        deadline,
                        reclaimer,
                    );
                }
                return if (deadline) |absolute|
                    state.pool.acquireUriAltSvcWithDeadline(
                        command.uri,
                        target,
                        absolute,
                    )
                else
                    state.pool.acquireUriAltSvc(command.uri, target);
            }
            return if (deadline) |absolute|
                state.pool.acquireUriWithDeadline(command.uri, absolute)
            else
                state.pool.acquireUri(command.uri);
        }

        fn processControl(
            state: *State,
            active: *[max_batch_limit]Active,
            active_count: *usize,
            total_owned: *usize,
            lease: ?*PoolType.Lease,
        ) RequestError!void {
            state.mutex.lockUncancelable(state.io);
            state.activity.reset();
            const closed = state.closed;
            if (!closed and active_count.* != 0) {
                const representative = active[0].command;
                const previously_owned = total_owned.*;
                while (active_count.* < state.options.max_batch_requests) {
                    const next = state.head orelse break;
                    if (!compatible(representative, next)) break;
                    detach(state, next);
                    next.state = .in_flight;
                    active[active_count.*] = .{ .command = next };
                    active_count.* += 1;
                    total_owned.* += 1;
                }
                const added = total_owned.* - previously_owned;
                if (added != 0) {
                    state.coalesced_requests +|= if (previously_owned == 1)
                        added + 1
                    else
                        added;
                }
            }
            state.mutex.unlock(state.io);

            if (closed) {
                while (active_count.* != 0) {
                    const index = active_count.* - 1;
                    if (lease) |value| {
                        if (active[index].stream_id) |stream_id| {
                            value.client().tryCancelRequest(
                                stream_id,
                                http3.ApplicationErrorCode.request_cancelled,
                            ) catch {};
                        }
                    }
                    complete(
                        state,
                        active[index].command,
                        null,
                        error.SharedDriverClosed,
                    );
                    active_count.* = index;
                }
                return;
            }

            var index = active_count.*;
            while (index != 0) {
                index -= 1;
                const command = active[index].command;
                state.mutex.lockUncancelable(state.io);
                const canceled = command.cancel_requested;
                command.cancel_requested = false;
                state.mutex.unlock(state.io);
                if (canceled) {
                    if (lease) |value| {
                        if (active[index].stream_id) |stream_id| {
                            try value.client().cancelRequest(
                                stream_id,
                                http3.ApplicationErrorCode.request_cancelled,
                            );
                        }
                    }
                    complete(state, command, null, error.Canceled);
                    removeActive(active, active_count, index);
                    continue;
                }
                const deadline = command.deadline orelse continue;
                if (deadline.durationFromNow(state.io).raw.nanoseconds > 0) {
                    continue;
                }
                if (lease) |value| {
                    if (active[index].stream_id) |stream_id| {
                        try value.client().cancelRequest(
                            stream_id,
                            http3.ApplicationErrorCode.request_cancelled,
                        );
                    }
                }
                complete(state, command, null, error.Timeout);
                removeActive(active, active_count, index);
            }
        }

        fn expireUnsent(
            state: *State,
            active: *[max_batch_limit]Active,
            active_count: *usize,
        ) void {
            var index = active_count.*;
            while (index != 0) {
                index -= 1;
                const command = active[index].command;
                const deadline = command.deadline orelse continue;
                if (deadline.durationFromNow(state.io).raw.nanoseconds > 0) {
                    continue;
                }
                complete(state, command, null, error.Timeout);
                removeActive(active, active_count, index);
            }
        }

        fn sendUnsent(
            state: *State,
            active: *[max_batch_limit]Active,
            active_count: *usize,
            lease: *PoolType.Lease,
        ) RequestError!void {
            var index: usize = 0;
            while (index < active_count.*) {
                if (active[index].stream_id != null) {
                    index += 1;
                    continue;
                }
                const command = active[index].command;
                const stream_id = sendCommand(
                    state,
                    lease.client(),
                    command,
                ) catch |err| switch (err) {
                    error.Timeout,
                    error.GoAwayReceived,
                    error.RequestRejected,
                    => {
                        complete(state, command, null, err);
                        removeActive(active, active_count, index);
                        continue;
                    },
                    else => return err,
                };
                active[index].stream_id = stream_id;
                index += 1;
            }
        }

        fn sendCommand(
            state: *State,
            client: *Runtime.HandshakeClient,
            command: *Command,
        ) RequestError!u62 {
            const uri = std.Uri.parse(command.uri) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(state.pool.allocator, uri);
            defer endpoint.deinit();
            const path = try Runtime.uriRequestTargetAlloc(
                state.pool.allocator,
                uri,
            );
            defer state.pool.allocator.free(path);
            const request: http3.Request = .{
                .method = command.request.method,
                .path = path,
                .scheme = "https",
                .authority = endpoint.authority,
                .headers = command.request.headers,
                .body = command.request.body,
                .trailers = command.request.trailers,
            };
            return if (command.deadline) |absolute|
                client.sendRequestWithDeadline(request, absolute)
            else
                client.sendRequest(request);
        }

        fn earliestDeadline(
            active: *const [max_batch_limit]Active,
            active_count: usize,
        ) ?std.Io.Clock.Timestamp {
            var earliest: ?std.Io.Clock.Timestamp = null;
            for (active[0..active_count]) |value| {
                const deadline = value.command.deadline orelse continue;
                earliest = if (earliest) |current|
                    if (std.Io.Clock.Timestamp.compare(
                        deadline,
                        .lt,
                        current,
                    )) deadline else current
                else
                    deadline;
            }
            return earliest;
        }

        fn findStream(
            active: *const [max_batch_limit]Active,
            active_count: usize,
            stream_id: u62,
        ) ?usize {
            for (active[0..active_count], 0..) |value, index| {
                if (value.stream_id == stream_id) return index;
            }
            return null;
        }

        fn removeActive(
            active: *[max_batch_limit]Active,
            active_count: *usize,
            index: usize,
        ) void {
            std.debug.assert(index < active_count.*);
            active_count.* -= 1;
            if (index != active_count.*) {
                active[index] = active[active_count.*];
            }
        }

        fn complete(
            state: *State,
            command: *Command,
            response_value: ?Runtime.OwnedHandshakeResponse,
            err: ?RequestError,
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
        ) RequestError!Runtime.OwnedHandshakeResponse {
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
            return sameAltSvc(a.alt_svc, b.alt_svc) and
                sameReclaimer(a.reclaimer, b.reclaimer);
        }

        fn sameReclaimer(
            a: ?connection_budget.Reclaimer,
            b: ?connection_budget.Reclaimer,
        ) bool {
            if (a == null or b == null) return a == null and b == null;
            return a.?.context == b.?.context and a.?.reclaim == b.?.reclaim;
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
