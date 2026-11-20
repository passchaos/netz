//! Cloneable request sender driven by one shared-endpoint HTTP/3 owner.
//!
//! Producers retain stack commands while the driver alone acquires leases,
//! mutates HandshakeClient state, reads the UDP endpoint, and correlates
//! response events. Each stable connection slot multiplexes bounded request
//! transactions; unrelated routes share the same UDP socket.
//!
//! While `run` is active, callers must use its senders rather than calling
//! pool acquire/receive methods directly; the dispatcher is the endpoint's
//! sole owner until it returns.

const std = @import("std");
const Guard = @import("../../../internal/mutex_guard.zig").Guard;
const http3 = @import("../../mod.zig");
const connection_budget = @import("../../../internal/connection_budget.zig");
const early_data = @import("../../../http/early_data.zig");
const authority = @import("../handshake_client_pool/shared/authority.zig");
const route_key = @import("../handshake_client_pool/shared/route.zig");
const stream_command = @import("stream_command.zig");
const receive_race = @import("dispatcher/receive.zig");

pub const Error = error{
    SharedEndpointDriverClosed,
    SharedEndpointDriverAlreadyRunning,
    SharedEndpointQueueFull,
    InvalidSharedEndpointOptions,
};

pub const Options = struct {
    max_queued_requests: usize = 256,
    max_active_connections: usize = 16,
    max_requests_per_connection: usize = 64,
    capacity_poll_interval: std.Io.Duration = .fromMilliseconds(5),
};

pub const Stats = struct {
    queued: usize,
    active_connections: usize,
    active_requests: usize,
    completed_requests: u64,
};

pub fn Dispatcher(comptime Pool: type, comptime Runtime: type) type {
    return struct {
        state: *State,

        const Self = @This();
        pub const RequestError = Pool.ReceiveOperationError || Error;
        const StreamType = stream_command.Stream(Pool);
        pub const EarlyRequestMetadata = struct {
            disposition: Runtime.EarlyRequestDisposition,
            retry_reason: Runtime.EarlyDataRetryReason,
        };
        pub const EarlyRequestResult = struct {
            response: Pool.OwnedResponse,
            early_data: ?EarlyRequestMetadata = null,
        };
        const EarlyRequestConfig = struct {
            options: Runtime.PreparedEarlyRequestOptions,
            local_settings: http3.Settings,
            remembered_peer_settings: http3.Settings,
        };
        const CommandState = enum { idle, queued, in_flight, completed };

        const Command = struct {
            uri: []const u8,
            request: Runtime.UriRequestOptions,
            alt_svc: ?http3.AltSvcTarget,
            deadline: ?std.Io.Clock.Timestamp,
            reclaimer: ?connection_budget.Reclaimer = null,
            early_config: ?EarlyRequestConfig = null,
            early_metadata: ?EarlyRequestMetadata = null,
            budget_waiter: connection_budget.Waiter = .{},
            route: route_key.Key,
            previous: ?*Command = null,
            next: ?*Command = null,
            state: CommandState = .idle,
            abandoned: bool = false,
            cancel_requested: bool = false,
            connection_index: ?usize = null,
            pending_acquire: ?*Pool.PendingRequestAcquire = null,
            prepared_early: ?Runtime.PreparedEarlyRequest = null,
            transaction: ?Pool.RequestTransaction = null,
            response: ?Pool.OwnedResponse = null,
            err: ?RequestError = null,
            done: std.Io.Event = .unset,
            stream: ?*StreamType = null,
            stream_request: ?http3.Request = null,
            stream_body_length: ?usize = null,
            stream_id: ?u62 = null,
        };

        /// Streaming request handle. The caller owns it until `deinit`.
        pub const StreamHandle = struct {
            pub const Sink = StreamType.Sink;
            state: *State,
            command: Command,
            stream: *StreamType,
            allocator: std.mem.Allocator,
            active: bool = true,

            pub fn writeBody(
                self: *StreamHandle,
                data: []const u8,
                fin: bool,
            ) !void {
                try self.stream.writeBody(data, fin);
            }

            pub fn writeBodyBlocking(
                self: *StreamHandle,
                data: []const u8,
                fin: bool,
                deadline: ?std.Io.Clock.Timestamp,
            ) !void {
                try self.stream.writeBodyBlocking(data, fin, deadline);
            }

            pub fn writeBodyBlockingTracked(self: *StreamHandle, data: []const u8, fin: bool, accepted: *usize, deadline: ?std.Io.Clock.Timestamp) !void {
                return self.stream.writeBodyBlockingTracked(data, fin, accepted, deadline);
            }

            pub fn acceptedBodyBytes(self: *StreamHandle) usize {
                return self.stream.acceptedBodyBytes();
            }

            pub fn isRequestClosed(self: *StreamHandle) bool {
                return self.stream.isRequestClosed();
            }

            pub fn writeTrailersWithDeadline(self: *StreamHandle, trailers: []const http3.Qpack.HeaderField, deadline: std.Io.Clock.Timestamp) !void {
                return self.stream.writeTrailersWithDeadline(trailers, deadline);
            }

            pub fn writeTrailers(
                self: *StreamHandle,
                trailers: []const http3.Qpack.HeaderField,
            ) !void {
                try self.stream.writeTrailers(trailers);
            }

            pub fn readResponse(
                self: *StreamHandle,
                sink: StreamType.Sink,
                deadline: ?std.Io.Clock.Timestamp,
            ) !*const http3.DecodedResponseHead {
                return self.stream.readResponse(sink, deadline);
            }

            pub fn pollResponse(
                self: *StreamHandle,
                sink: StreamType.Sink,
            ) !bool {
                return self.stream.pollResponse(sink);
            }

            pub fn requestStreamId(self: *StreamHandle) ?u62 {
                return self.stream.requestStreamId();
            }

            pub fn deinit(self: *StreamHandle) void {
                if (!self.active) return;
                self.active = false;
                self.stream.cancel();
                if (!cancelQueued(self.state, &self.command)) {
                    abandonInFlight(self.state, &self.command);
                    self.command.done.waitUncancelable(self.state.io);
                }
                self.stream.deinit();
                self.allocator.destroy(self.stream);
                self.allocator.destroy(self);
            }
        };

        const Connection = struct {
            active: bool = false,
            pending: bool = false,
            lease: Pool.Lease = undefined,
            route: route_key.Key = undefined,
            primary_allowed: bool = true,
            authority: authority.Snapshot = .{},
            authority_generation: u64 = 0,
            commands: []?*Command = &.{},
            command_count: usize = 0,

            fn accepts(self: *const Connection, command: *const Command) bool {
                return !self.pending and
                    ((self.primary_allowed and
                        self.route.eql(&command.route)) or
                        self.authority.allows(&command.route));
            }
        };

        const State = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *Pool,
            options: Options,
            mutex: std.Io.Mutex = .init,
            activity: std.Io.Event = .unset,
            head: ?*Command = null,
            tail: ?*Command = null,
            queued: usize = 0,
            closed: bool = false,
            running: std.atomic.Value(bool) = .init(false),
            connections: []Connection,
            command_storage: []?*Command,
            active_connections: std.atomic.Value(usize) = .init(0),
            active_requests: std.atomic.Value(usize) = .init(0),
            completed_requests: u64 = 0,
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
            ) RequestError!Pool.OwnedResponse {
                return self.requestBefore(
                    uri,
                    request_options,
                    null,
                    null,
                    null,
                );
            }

            pub fn requestWithTimeout(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) RequestError!Pool.OwnedResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    null,
                    .fromNow(self.state.io, .{
                        .clock = .awake,
                        .raw = timeout,
                    }),
                    null,
                );
            }

            pub fn requestWithDeadline(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) RequestError!Pool.OwnedResponse {
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

            pub fn requestAltSvcWithTimeout(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                timeout: std.Io.Duration,
            ) RequestError!Pool.OwnedResponse {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    .fromNow(self.state.io, .{
                        .clock = .awake,
                        .raw = timeout,
                    }),
                    null,
                );
            }

            pub fn requestAltSvc(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
            ) RequestError!Pool.OwnedResponse {
                return self.requestBefore(
                    uri,
                    request_options,
                    target,
                    null,
                    null,
                );
            }

            pub fn requestAltSvcWithDeadline(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                deadline: std.Io.Clock.Timestamp,
            ) RequestError!Pool.OwnedResponse {
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

            pub fn requestAltSvcReclaiming(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: connection_budget.Reclaimer,
            ) RequestError!Pool.OwnedResponse {
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

            /// Offer this request in 0-RTT only if admission creates a new
            /// connection with a usable scoped ticket. Reuse remains 1-RTT.
            pub fn requestAltSvcEarlyReclaiming(
                self: Sender,
                uri: []const u8,
                target: http3.AltSvcTarget,
                request_options: Runtime.UriRequestOptions,
                early_options: Runtime.PreparedEarlyRequestOptions,
                local_settings: http3.Settings,
                remembered_peer_settings: http3.Settings,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: connection_budget.Reclaimer,
            ) RequestError!EarlyRequestResult {
                if (deadline) |absolute| {
                    if (absolute.clock != .awake or absolute.durationFromNow(
                        self.state.io,
                    ).raw.nanoseconds <= 0) return error.Timeout;
                }
                var metadata: ?EarlyRequestMetadata = null;
                const response = try self.requestBeforeConfigured(
                    uri,
                    request_options,
                    target,
                    deadline,
                    reclaimer,
                    .{
                        .options = early_options,
                        .local_settings = local_settings,
                        .remembered_peer_settings = remembered_peer_settings,
                    },
                    &metadata,
                );
                return .{ .response = response, .early_data = metadata };
            }

            /// Open a streaming request on a dedicated route. The worker
            /// sends the head, then multiplexes caller body writes with
            /// response events until the stream finishes.
            pub fn startStream(
                self: Sender,
                uri: []const u8,
                target: ?http3.AltSvcTarget,
                request_value: http3.Request,
                body_length: ?usize,
                deadline: ?std.Io.Clock.Timestamp,
            ) RequestError!*StreamHandle {
                const state = self.state;
                if (deadline) |absolute| {
                    if (absolute.clock != .awake or
                        absolute.durationFromNow(state.io).raw.nanoseconds <= 0)
                    {
                        return error.Timeout;
                    }
                }
                const identity = try route_key.Key.init(
                    uri,
                    target,
                    null,
                );
                const allocator = state.pool.allocator;
                const stream = try allocator.create(StreamType);
                // Ownership moves into `handle` once the command is enqueued.
                // Before that point raw errdefers release the allocations; after
                // it, every failure path calls `handle.deinit()`. Keeping both
                // armed caused a double free on a stream-start timeout.
                var stream_owned = true;
                errdefer if (stream_owned) {
                    stream.deinit();
                    allocator.destroy(stream);
                };
                stream.* = StreamType.init(state.pool, allocator, state.io);
                stream.worker_activity = &state.activity;
                stream.expected_body_length = body_length orelse try http3.contentLength(request_value.headers);
                const handle = try allocator.create(StreamHandle);
                var handle_owned = true;
                errdefer if (handle_owned) allocator.destroy(handle);
                handle.* = .{
                    .state = state,
                    .command = .{
                        .uri = uri,
                        .request = .{},
                        .alt_svc = target,
                        .deadline = deadline,
                        .route = identity,
                        .stream = stream,
                        .stream_request = request_value,
                        .stream_body_length = body_length,
                    },
                    .stream = stream,
                    .allocator = allocator,
                };
                try enqueue(state, &handle.command);
                handle_owned = false;
                stream_owned = false;
                stream.mutex.lockUncancelable(state.io);
                while (stream.stream_id == null and
                    stream.err == null and !stream.finished)
                {
                    stream.mutex.unlock(state.io);
                    if (deadline) |absolute| {
                        stream.user_ready.waitTimeout(
                            state.io,
                            .{ .deadline = absolute },
                        ) catch |err| switch (err) {
                            error.Timeout => {
                                handle.deinit();
                                return error.Timeout;
                            },
                            error.Canceled => {
                                handle.deinit();
                                return error.Canceled;
                            },
                        };
                    } else {
                        stream.user_ready.wait(
                            state.io,
                        ) catch |err| {
                            handle.deinit();
                            return err;
                        };
                    }
                    stream.user_ready.reset();
                    stream.mutex.lockUncancelable(state.io);
                }
                const started = stream.stream_id != null;
                const start_err = stream.err;
                stream.mutex.unlock(state.io);
                if (!started) {
                    handle.deinit();
                    return if (start_err) |err| @errorCast(err) else error.RequestCancelled;
                }
                return handle;
            }

            fn requestBefore(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                alt_svc: ?http3.AltSvcTarget,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: ?connection_budget.Reclaimer,
            ) RequestError!Pool.OwnedResponse {
                return self.requestBeforeConfigured(
                    uri,
                    request_options,
                    alt_svc,
                    deadline,
                    reclaimer,
                    null,
                    null,
                );
            }

            fn requestBeforeConfigured(
                self: Sender,
                uri: []const u8,
                request_options: Runtime.UriRequestOptions,
                alt_svc: ?http3.AltSvcTarget,
                deadline: ?std.Io.Clock.Timestamp,
                reclaimer: ?connection_budget.Reclaimer,
                early_config: ?EarlyRequestConfig,
                early_metadata: ?*?EarlyRequestMetadata,
            ) RequestError!Pool.OwnedResponse {
                var command: Command = .{
                    .uri = uri,
                    .request = request_options,
                    .alt_svc = alt_svc,
                    .deadline = deadline,
                    .reclaimer = reclaimer,
                    .early_config = early_config,
                    .route = try route_key.Key.init(uri, alt_svc, null),
                };
                if (early_metadata) |output| output.* = null;
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
                const response = try takeResult(self.state, &command);
                if (early_metadata) |output| {
                    output.* = command.early_metadata;
                }
                return response;
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *Pool,
            options: Options,
        ) (std.mem.Allocator.Error || Error)!Self {
            if (options.max_queued_requests == 0 or
                options.max_active_connections == 0 or
                options.max_requests_per_connection == 0 or
                options.capacity_poll_interval.nanoseconds <= 0)
            {
                return error.InvalidSharedEndpointOptions;
            }
            const total_slots = std.math.mul(
                usize,
                options.max_active_connections,
                options.max_requests_per_connection,
            ) catch return error.InvalidSharedEndpointOptions;
            const state = try allocator.create(State);
            errdefer allocator.destroy(state);
            const connections = try allocator.alloc(
                Connection,
                options.max_active_connections,
            );
            errdefer allocator.free(connections);
            const command_storage = try allocator.alloc(?*Command, total_slots);
            errdefer allocator.free(command_storage);
            @memset(command_storage, null);
            for (connections, 0..) |*connection, index| {
                const start = index * options.max_requests_per_connection;
                connection.* = .{
                    .commands = command_storage[start .. start + options.max_requests_per_connection],
                };
            }
            state.* = .{
                .allocator = allocator,
                .io = io,
                .pool = pool,
                .options = options,
                .connections = connections,
                .command_storage = command_storage,
            };
            return .{ .state = state };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            std.debug.assert(!self.state.running.load(.acquire));
            std.debug.assert(self.state.queued == 0);
            for (self.state.connections) |connection| {
                std.debug.assert(!connection.active);
            }
            const allocator = self.state.allocator;
            allocator.free(self.state.command_storage);
            allocator.free(self.state.connections);
            allocator.destroy(self.state);
            self.* = undefined;
        }

        pub fn sender(self: *Self) Sender {
            return .{ .state = self.state };
        }

        pub fn close(self: *Self) void {
            closeState(self.state);
        }

        pub fn closeBefore(self: *Self, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
            try closeStateBefore(self.state, deadline);
        }

        fn closeState(state: *State) void {
            closeStateBefore(state, null) catch unreachable;
        }

        fn closeStateBefore(state: *State, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
            var guard = try Guard.initBefore(&state.mutex, state.io, deadline);
            defer guard.unlock();
            if (state.closed) {
                guard.unlock();
                return;
            }
            state.closed = true;
            var command = state.head;
            state.head = null;
            state.tail = null;
            state.queued = 0;
            while (command) |current| {
                const next = current.next;
                current.previous = null;
                current.next = null;
                cancelBudgetWaiter(state, current);
                current.state = .completed;
                current.err = error.SharedEndpointDriverClosed;
                current.done.set(state.io);
                command = next;
            }
            state.activity.set(state.io);
            guard.unlock();
        }

        pub fn run(self: *Self) RequestError!void {
            const state = self.state;
            if (state.running.swap(true, .acq_rel)) {
                return error.SharedEndpointDriverAlreadyRunning;
            }
            defer state.running.store(false, .release);
            errdefer |err| {
                closeState(state);
                failAllActive(state, err);
            }
            while (true) {
                processControl(state);
                try progressPendingConnections(state);
                try admitQueued(state);
                try progressTransactions(state);
                if (isClosed(state)) {
                    failAllActive(state, error.SharedEndpointDriverClosed);
                    return;
                }
                if (activeRequestCount(state) == 0) {
                    state.mutex.lockUncancelable(state.io);
                    state.activity.reset();
                    const closed = state.closed;
                    const capacity_blocked = state.head != null;
                    state.mutex.unlock(state.io);
                    if (!closed) {
                        if (capacity_blocked) {
                            state.activity.waitTimeout(state.io, .{
                                .duration = .{
                                    .clock = .awake,
                                    .raw = state.options.capacity_poll_interval,
                                },
                            }) catch |err| switch (err) {
                                error.Timeout => {},
                                error.Canceled => return error.Canceled,
                            };
                        } else {
                            try state.activity.wait(state.io);
                        }
                    }
                    continue;
                }
                const maybe_event = try receive_race.beforeActivity(
                    Pool,
                    RequestError,
                    state.pool,
                    state.io,
                    &state.activity,
                    earliestDeadline(state),
                );
                if (maybe_event) |event_value| {
                    var event = event_value;
                    defer event.deinit(state.pool.allocator);
                    try processEvent(state, &event);
                }
            }
        }

        pub fn stats(self: *Self) Stats {
            const state = self.state;
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            return .{
                .queued = state.queued,
                .active_connections = state.active_connections.load(.acquire),
                .active_requests = state.active_requests.load(.acquire),
                .completed_requests = state.completed_requests,
            };
        }

        fn enqueue(state: *State, command: *Command) Error!void {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (state.closed) return error.SharedEndpointDriverClosed;
            if (state.queued >= state.options.max_queued_requests) {
                return error.SharedEndpointQueueFull;
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
            state.activity.set(state.io);
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

        fn cancelQueued(state: *State, command: *Command) bool {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            if (command.state != .queued) return false;
            detach(state, command);
            cancelBudgetWaiter(state, command);
            command.state = .completed;
            return true;
        }

        fn abandonInFlight(state: *State, command: *Command) void {
            state.mutex.lockUncancelable(state.io);
            command.abandoned = true;
            if (command.state == .in_flight) command.cancel_requested = true;
            state.activity.set(state.io);
            state.mutex.unlock(state.io);
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
                    error.Timeout => if (absolute.durationFromNow(
                        state.io,
                    ).raw.nanoseconds <= 0) return error.Timeout,
                    error.Canceled => return error.Canceled,
                };
            }
            return null;
        }

        fn processControl(state: *State) void {
            state.mutex.lockUncancelable(state.io);
            state.activity.reset();
            state.mutex.unlock(state.io);
            for (state.connections, 0..) |*connection, connection_index| {
                if (!connection.active) continue;
                var index = connection.command_count;
                while (index != 0) {
                    index -= 1;
                    const command = connection.commands[index].?;
                    state.mutex.lockUncancelable(state.io);
                    const canceled = command.cancel_requested;
                    command.cancel_requested = false;
                    const closed = state.closed;
                    state.mutex.unlock(state.io);
                    const expired = if (command.deadline) |deadline|
                        deadline.durationFromNow(state.io).raw.nanoseconds <= 0
                    else
                        false;
                    if (!canceled and !expired and !closed) continue;
                    if (command.pending_acquire) |pending| {
                        pending.deinit();
                        command.pending_acquire = null;
                    }
                    clearPreparedEarly(command);
                    if (command.stream) |stream| {
                        if (command.stream_id) |stream_id| {
                            connection.lease.client().tryCancelRequest(
                                stream_id,
                                http3.ApplicationErrorCode.request_cancelled,
                            ) catch {};
                        }
                        stream.fail(if (closed)
                            error.SharedEndpointDriverClosed
                        else if (expired)
                            error.Timeout
                        else
                            error.Canceled);
                    }
                    if (command.transaction) |*transaction| {
                        transaction.deinit();
                    }
                    command.transaction = null;
                    removeConnectionCommand(state, connection, index);
                    command.connection_index = null;
                    complete(
                        state,
                        command,
                        null,
                        if (closed)
                            error.SharedEndpointDriverClosed
                        else if (expired)
                            error.Timeout
                        else
                            error.Canceled,
                    );
                }
                if (connection.command_count == 0) {
                    if (connection.pending)
                        releasePendingConnection(state, connection_index)
                    else
                        releaseConnection(state, connection_index, false);
                }
            }
        }

        fn admitQueued(state: *State) RequestError!void {
            while (true) {
                state.mutex.lockUncancelable(state.io);
                const command = firstAdmissibleCommand(state) orelse {
                    state.mutex.unlock(state.io);
                    return;
                };
                detach(state, command);
                command.state = .in_flight;
                state.mutex.unlock(state.io);

                if (command.deadline) |deadline| {
                    if (deadline.durationFromNow(state.io).raw.nanoseconds <= 0) {
                        complete(state, command, null, error.Timeout);
                        continue;
                    }
                }
                var connection_index = findConnection(state, command);
                if (connection_index == null) {
                    connection_index = firstFreeConnection(state);
                    if (connection_index == null) {
                        requeueFront(state, command);
                        return;
                    }
                    const acquired = beginAcquireForCommand(
                        state,
                        command,
                    ) catch |err| {
                        if (err == error.ConnectionLimitReached) {
                            requeueFront(state, command);
                            return;
                        }
                        complete(state, command, null, err);
                        continue;
                    };
                    const index = connection_index.?;
                    state.connections[index].active = true;
                    state.connections[index].route = command.route;
                    state.connections[index].primary_allowed = true;
                    state.connections[index].authority = .{};
                    state.connections[index].authority_generation = 0;
                    state.connections[index].command_count = 0;
                    _ = state.active_connections.fetchAdd(1, .acq_rel);
                    switch (acquired) {
                        .lease => |lease| {
                            state.connections[index].pending = false;
                            state.connections[index].lease = lease;
                            applyEarlyMetadata(command, lease);
                            refreshAuthority(
                                state,
                                &state.connections[index],
                            );
                        },
                        .pending => |pending| {
                            state.connections[index].pending = true;
                            command.pending_acquire = pending;
                        },
                    }
                }
                const index = connection_index.?;
                const connection = &state.connections[index];
                cancelBudgetWaiter(state, command);
                state.mutex.lockUncancelable(state.io);
                const canceled = command.cancel_requested or command.abandoned or
                    state.closed;
                state.mutex.unlock(state.io);
                if (canceled) {
                    if (command.pending_acquire) |pending| {
                        pending.deinit();
                        command.pending_acquire = null;
                    }
                    clearPreparedEarly(command);
                    complete(state, command, null, error.Canceled);
                    if (connection.command_count == 0) {
                        // An accepted early request was already committed by
                        // the handshake. Without a transaction there is no
                        // owner for its eventual response, so fail closed on
                        // this connection instead of pooling an orphan stream.
                        const early_request_in_flight = if (command.early_metadata) |metadata|
                            metadata.disposition == .accepted
                        else
                            false;
                        if (connection.pending)
                            releasePendingConnection(state, index)
                        else
                            releaseConnection(
                                state,
                                index,
                                early_request_in_flight,
                            );
                    }
                    continue;
                }
                command.connection_index = index;
                if (connection.pending) {
                    addConnectionCommand(state, connection, command);
                    continue;
                }
                startCommand(state, connection, command) catch |err| {
                    command.connection_index = null;
                    complete(state, command, null, err);
                    if (connection.command_count == 0) {
                        releaseConnection(state, index, true);
                    }
                    continue;
                };
                addConnectionCommand(state, connection, command);
            }
        }

        fn firstAdmissibleCommand(state: *State) ?*Command {
            const has_free_connection = firstFreeConnection(state) != null;
            var command = state.head;
            while (command) |candidate| : (command = candidate.next) {
                // One pending handshake owns this exact route. Preserve
                // multiplexing by waiting for its promotion instead of
                // creating duplicate connections merely because another
                // driver slot is free.
                if (findPendingConnection(state, candidate) != null) continue;
                if (has_free_connection or
                    findConnection(state, candidate) != null)
                {
                    return candidate;
                }
            }
            return null;
        }

        fn findPendingConnection(
            state: *State,
            command: *const Command,
        ) ?usize {
            for (state.connections, 0..) |*connection, index| {
                if (connection.active and connection.pending and
                    connection.route.eql(&command.route))
                {
                    return index;
                }
            }
            return null;
        }

        fn beginAcquireForCommand(
            state: *State,
            command: *Command,
        ) RequestError!Pool.DriverAcquire {
            var early_request: ?*const Runtime.PreparedEarlyRequest = null;
            if (command.early_config) |config| {
                const uri = std.Uri.parse(command.uri) catch
                    return error.InvalidUri;
                var endpoint = try Runtime.uriEndpoint(
                    state.allocator,
                    uri,
                );
                defer endpoint.deinit();
                const path = try Runtime.uriRequestTargetAlloc(
                    state.allocator,
                    uri,
                );
                defer state.allocator.free(path);
                command.prepared_early = try Runtime.PreparedEarlyRequest
                    .initWithOptions(
                    state.allocator,
                    .{
                        .method = command.request.method,
                        .path = path,
                        .scheme = "https",
                        .authority = endpoint.authority,
                        .headers = command.request.headers,
                        .body = command.request.body,
                        .trailers = command.request.trailers,
                    },
                    config.local_settings,
                    config.remembered_peer_settings,
                    config.options,
                );
                early_request = &command.prepared_early.?;
            }
            const result = state.pool.beginUriForRequestDriver(
                command.uri,
                command.alt_svc,
                command.deadline,
                if (command.reclaimer != null)
                    &command.budget_waiter
                else
                    null,
                command.reclaimer,
                early_request,
                &state.activity,
            ) catch |err| {
                clearPreparedEarly(command);
                return @errorCast(err);
            };
            switch (result) {
                .lease => clearPreparedEarly(command),
                .pending => |pending| if (!pending.usesEarlyRequest()) {
                    clearPreparedEarly(command);
                },
            }
            return result;
        }

        fn clearPreparedEarly(command: *Command) void {
            if (command.prepared_early) |*prepared| prepared.deinit();
            command.prepared_early = null;
        }

        fn applyEarlyMetadata(command: *Command, lease: Pool.Lease) void {
            if (lease.early_disposition) |disposition| {
                command.early_metadata = .{
                    .disposition = disposition,
                    .retry_reason = if (disposition == .accepted)
                        .none
                    else
                        .early_data_rejected,
                };
            }
        }

        fn startCommand(
            state: *State,
            connection: *Connection,
            command: *Command,
        ) RequestError!void {
            if (command.stream) |stream| {
                const request = command.stream_request orelse
                    return error.InvalidHeader;
                const stream_id = connection.lease.client().tryStartRequest(
                    request,
                    command.stream_body_length,
                ) catch |err| return @errorCast(err);
                command.stream_id = stream_id;
                stream.markStarted(stream_id);
                return;
            }
            command.transaction = try initCommandTransaction(
                state,
                connection,
                command,
            );
        }

        fn initCommandTransaction(
            state: *State,
            connection: *Connection,
            command: *Command,
        ) RequestError!Pool.RequestTransaction {
            return if (command.early_metadata) |metadata|
                if (metadata.disposition == .accepted)
                    Pool.RequestTransaction.initAcceptedEarly(
                        state.pool,
                        &connection.lease,
                        command.uri,
                        command.request,
                    )
                else
                    Pool.RequestTransaction.init(
                        state.pool,
                        &connection.lease,
                        command.uri,
                        command.request,
                    )
            else
                Pool.RequestTransaction.init(
                    state.pool,
                    &connection.lease,
                    command.uri,
                    command.request,
                );
        }

        fn requeueFront(state: *State, command: *Command) void {
            state.mutex.lockUncancelable(state.io);
            command.state = .queued;
            command.previous = null;
            command.next = state.head;
            if (state.head) |head| head.previous = command else state.tail = command;
            state.head = command;
            state.queued += 1;
            state.mutex.unlock(state.io);
        }

        fn findConnection(state: *State, command: *const Command) ?usize {
            for (state.connections, 0..) |*connection, index| {
                if (!connection.active or
                    connection.command_count >= connection.commands.len)
                {
                    continue;
                }
                if (connection.accepts(command)) return index;
            }
            return null;
        }

        fn firstFreeConnection(state: *State) ?usize {
            for (state.connections, 0..) |connection, index| {
                if (!connection.active) return index;
            }
            return null;
        }

        fn addConnectionCommand(
            state: *State,
            connection: *Connection,
            command: *Command,
        ) void {
            std.debug.assert(connection.command_count < connection.commands.len);
            connection.commands[connection.command_count] = command;
            connection.command_count += 1;
            _ = state.active_requests.fetchAdd(1, .acq_rel);
        }

        fn removeConnectionCommand(
            state: *State,
            connection: *Connection,
            index: usize,
        ) void {
            std.debug.assert(index < connection.command_count);
            connection.command_count -= 1;
            connection.commands[index] = connection.commands[
                connection.command_count
            ];
            connection.commands[connection.command_count] = null;
            const previous = state.active_requests.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
        }

        fn progressPendingConnections(state: *State) RequestError!void {
            for (state.connections, 0..) |*connection, connection_index| {
                if (!connection.active or !connection.pending) continue;
                std.debug.assert(connection.command_count == 1);
                const command = connection.commands[0].?;
                const pending = command.pending_acquire.?;
                const maybe_lease = pending.poll() catch |err| {
                    pending.deinit();
                    command.pending_acquire = null;
                    clearPreparedEarly(command);
                    removeConnectionCommand(state, connection, 0);
                    command.connection_index = null;
                    complete(state, command, null, @errorCast(err));
                    releasePendingConnection(state, connection_index);
                    continue;
                };
                const lease = maybe_lease orelse {
                    if (!pending.usesEarlyRequest()) {
                        clearPreparedEarly(command);
                    }
                    continue;
                };
                pending.deinit();
                command.pending_acquire = null;
                clearPreparedEarly(command);
                connection.pending = false;
                connection.lease = lease;
                applyEarlyMetadata(command, lease);
                refreshAuthority(state, connection);

                state.mutex.lockUncancelable(state.io);
                const closed = state.closed;
                const canceled = command.cancel_requested or
                    command.abandoned or closed;
                state.mutex.unlock(state.io);
                const expired = if (command.deadline) |deadline|
                    deadline.durationFromNow(state.io).raw.nanoseconds <= 0
                else
                    false;
                if (canceled or expired) {
                    removeConnectionCommand(state, connection, 0);
                    command.connection_index = null;
                    complete(
                        state,
                        command,
                        null,
                        if (closed)
                            error.SharedEndpointDriverClosed
                        else if (expired)
                            error.Timeout
                        else
                            error.Canceled,
                    );
                    const early_request_in_flight = if (command.early_metadata) |metadata|
                        metadata.disposition == .accepted
                    else
                        false;
                    releaseConnection(
                        state,
                        connection_index,
                        early_request_in_flight,
                    );
                    continue;
                }
                startCommand(state, connection, command) catch |err| {
                    removeConnectionCommand(state, connection, 0);
                    command.connection_index = null;
                    complete(state, command, null, err);
                    releaseConnection(state, connection_index, true);
                    continue;
                };
            }
        }

        fn progressStream(
            state: *State,
            connection: *Connection,
            command: *Command,
            stream: *StreamType,
        ) RequestError!void {
            const stream_id = command.stream_id orelse return;
            const client = connection.lease.client();
            while (true) {
                if (stream.worker_write == null) {
                    stream.worker_write = stream.takeWrite();
                }
                if (stream.worker_write) |*write| {
                    client.trySendRequestBodyFragment(
                        stream_id,
                        write.data,
                        write.fin,
                        &write.fragment,
                    ) catch |err| switch (err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        error.StreamLimitExceeded,
                        error.AntiAmplificationLimited,
                        => return,
                        else => {
                            state.pool.allocator.free(write.data);
                            stream.worker_write = null;
                            stream.fail(err);
                            return @errorCast(err);
                        },
                    };
                    if (!write.fragment.complete) continue;
                    state.pool.allocator.free(write.data);
                    stream.worker_write = null;
                    continue;
                }
                if (stream.worker_trailers == null) {
                    stream.worker_trailers = stream.takeTrailers();
                }
                if (stream.worker_trailers) |*trailers| {
                    client.tryFinishRequestTrailers(
                        stream_id,
                        trailers.fields,
                    ) catch |err| switch (err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        error.StreamLimitExceeded,
                        error.AntiAmplificationLimited,
                        => return,
                        else => {
                            trailers.deinit(state.pool.allocator);
                            stream.worker_trailers = null;
                            stream.fail(err);
                            return @errorCast(err);
                        },
                    };
                    trailers.deinit(state.pool.allocator);
                    stream.worker_trailers = null;
                    continue;
                }
                return;
            }
        }

        fn progressTransactions(state: *State) RequestError!void {
            for (state.connections, 0..) |*connection, connection_index| {
                if (!connection.active or connection.pending) continue;
                var index: usize = 0;
                while (index < connection.command_count) {
                    const command = connection.commands[index].?;
                    if (command.stream) |stream| {
                        progressStream(
                            state,
                            connection,
                            command,
                            stream,
                        ) catch |err| {
                            removeConnectionCommand(state, connection, index);
                            command.connection_index = null;
                            complete(state, command, null, err);
                            continue;
                        };
                        index += 1;
                        continue;
                    }
                    command.transaction.?.progress() catch |err| {
                        command.transaction.?.deinit();
                        command.transaction = null;
                        removeConnectionCommand(state, connection, index);
                        command.connection_index = null;
                        complete(state, command, null, err);
                        continue;
                    };
                    index += 1;
                }
                refreshAuthority(state, connection);
                if (connection.command_count == 0) {
                    releaseConnection(state, connection_index, false);
                }
            }
        }

        fn processStreamEvent(
            state: *State,
            connection: *Connection,
            command: *Command,
            stream: *StreamType,
            event: *Pool.Event,
        ) RequestError!bool {
            const response = switch (event.*) {
                .response => |*value| value,
                else => return false,
            };
            switch (response.response) {
                .reset => {
                    stream.fail(error.RequestCancelled);
                    return true;
                },
                .message => |*message| switch (message.value) {
                    .head => |head_value| {
                        event.* = .consumed;
                        var head = head_value;
                        if (head != .response) {
                            head.deinit(state.pool.allocator);
                            return false;
                        }
                        const decoded = head.response;
                        if (decoded.status < 200) {
                            stream.deliverInformational(decoded) catch |err| {
                                stream.fail(err);
                                return @errorCast(err);
                            };
                            return false;
                        }
                        stream.deliverHead(decoded);
                        return false;
                    },
                    .data_available => {
                        var buffer: [16 * 1024]u8 = undefined;
                        const maybe_count = state.pool.readResponseDataOnce(
                            connection.lease.connectionHandle(),
                            command.stream_id.?,
                            &buffer,
                        ) catch |err| {
                            stream.fail(err);
                            return @errorCast(err);
                        };
                        const count = maybe_count orelse 0;
                        if (count != 0) {
                            stream.deliverData(buffer[0..count]) catch |err| {
                                stream.fail(err);
                                return @errorCast(err);
                            };
                        }
                        return false;
                    },
                    .trailers => |trailers_value| {
                        event.* = .consumed;
                        stream.deliverTrailers(trailers_value);
                        return false;
                    },
                    .finished => {
                        stream.finish();
                        return true;
                    },
                    .push_promise => return false,
                },
            }
        }

        fn processEvent(
            state: *State,
            event: *Pool.Event,
        ) RequestError!void {
            switch (event.*) {
                .response => |response_event| {
                    const connection_index = findConnectionHandle(
                        state,
                        response_event.connection_handle,
                    ) orelse return error.UnknownConnectionHandle;
                    const connection = &state.connections[connection_index];
                    const event_stream_id = responseStreamId(
                        response_event.response,
                    );
                    var stream_index: usize = 0;
                    while (stream_index < connection.command_count) : (stream_index += 1) {
                        const stream_command_value =
                            connection.commands[stream_index].?;
                        const stream = stream_command_value.stream orelse
                            continue;
                        if (stream_command_value.stream_id != event_stream_id) {
                            continue;
                        }
                        const finished = processStreamEvent(
                            state,
                            connection,
                            stream_command_value,
                            stream,
                            event,
                        ) catch |err| {
                            stream.fail(err);
                            removeConnectionCommand(
                                state,
                                connection,
                                stream_index,
                            );
                            stream_command_value.connection_index = null;
                            complete(state, stream_command_value, null, err);
                            refreshAuthority(state, connection);
                            if (connection.command_count == 0) {
                                releaseConnection(
                                    state,
                                    connection_index,
                                    true,
                                );
                            }
                            return;
                        };
                        if (finished) {
                            removeConnectionCommand(
                                state,
                                connection,
                                stream_index,
                            );
                            stream_command_value.connection_index = null;
                            complete(
                                state,
                                stream_command_value,
                                null,
                                null,
                            );
                            refreshAuthority(state, connection);
                            if (connection.command_count == 0) {
                                releaseConnection(
                                    state,
                                    connection_index,
                                    false,
                                );
                            }
                        }
                        return;
                    }
                    var index: usize = 0;
                    while (index < connection.command_count) : (index += 1) {
                        const command = connection.commands[index].?;
                        const stream_id = command.transaction.?.requestStreamId() orelse
                            continue;
                        if (stream_id != responseStreamId(response_event.response)) {
                            continue;
                        }
                        const result = command.transaction.?.processEvent(event);
                        const maybe_response = result catch |err| {
                            command.transaction.?.deinit();
                            command.transaction = null;
                            removeConnectionCommand(state, connection, index);
                            command.connection_index = null;
                            complete(state, command, null, err);
                            refreshAuthority(state, connection);
                            if (connection.command_count == 0) {
                                releaseConnection(state, connection_index, true);
                            }
                            return;
                        };
                        if (maybe_response) |response_value| {
                            var response = response_value;
                            if (command.early_metadata) |*metadata| {
                                if (metadata.disposition == .accepted and
                                    metadata.retry_reason == .none and
                                    response.response.status ==
                                        early_data.too_early_status)
                                {
                                    response.deinit();
                                    metadata.retry_reason = .too_early;
                                    command.transaction = null;
                                    if (command.deadline) |deadline| {
                                        if (deadline.durationFromNow(
                                            state.io,
                                        ).raw.nanoseconds <= 0) {
                                            removeConnectionCommand(
                                                state,
                                                connection,
                                                index,
                                            );
                                            command.connection_index = null;
                                            complete(
                                                state,
                                                command,
                                                null,
                                                error.Timeout,
                                            );
                                            refreshAuthority(state, connection);
                                            if (connection.command_count == 0) {
                                                releaseConnection(
                                                    state,
                                                    connection_index,
                                                    false,
                                                );
                                            }
                                            return;
                                        }
                                    }
                                    command.transaction = Pool.RequestTransaction
                                        .init(
                                        state.pool,
                                        &connection.lease,
                                        command.uri,
                                        command.request,
                                    ) catch |err| {
                                        removeConnectionCommand(
                                            state,
                                            connection,
                                            index,
                                        );
                                        command.connection_index = null;
                                        complete(state, command, null, err);
                                        refreshAuthority(state, connection);
                                        if (connection.command_count == 0) {
                                            releaseConnection(
                                                state,
                                                connection_index,
                                                true,
                                            );
                                        }
                                        return;
                                    };
                                    refreshAuthority(state, connection);
                                    return;
                                }
                            }
                            command.transaction = null;
                            removeConnectionCommand(state, connection, index);
                            command.connection_index = null;
                            complete(state, command, response, null);
                            refreshAuthority(state, connection);
                            if (connection.command_count == 0) {
                                releaseConnection(state, connection_index, false);
                            }
                        }
                        return;
                    }
                    return error.UnexpectedStream;
                },
                .progress => |handle| try progressConnection(state, handle, event),
                .timer => |timer| try progressConnection(
                    state,
                    timer.connection_handle,
                    event,
                ),
                .closed => |closed| {
                    const index = findConnectionHandle(
                        state,
                        closed.connection_handle,
                    ) orelse return;
                    failConnection(state, index, error.ConnectionClosed);
                },
                .push => |push| {
                    const index = findConnectionHandle(
                        state,
                        push.connection_handle,
                    ) orelse return;
                    state.connections[index].lease.tryCancelPush(
                        push.push.push_id,
                    ) catch |err| {
                        failConnection(state, index, @errorCast(err));
                    };
                },
                .consumed, .unrouted => {},
            }
        }

        fn progressConnection(
            state: *State,
            handle: usize,
            event: *Pool.Event,
        ) RequestError!void {
            const connection_index = findConnectionHandle(state, handle) orelse
                return;
            const connection = &state.connections[connection_index];
            var index: usize = 0;
            while (index < connection.command_count) {
                const command = connection.commands[index].?;
                if (command.stream != null) {
                    index += 1;
                    continue;
                }
                const result = command.transaction.?.processEvent(event) catch |err| {
                    command.transaction.?.deinit();
                    command.transaction = null;
                    removeConnectionCommand(state, connection, index);
                    command.connection_index = null;
                    complete(state, command, null, err);
                    continue;
                };
                if (result) |response_value| {
                    var response = response_value;
                    response.deinit();
                    return error.UnexpectedStream;
                }
                index += 1;
            }
            refreshAuthority(state, connection);
            if (connection.command_count == 0) {
                releaseConnection(state, connection_index, false);
            }
        }

        fn findConnectionHandle(state: *State, handle: usize) ?usize {
            for (state.connections, 0..) |connection, index| {
                if (connection.active and !connection.pending and
                    connection.lease.connectionHandle() == handle)
                {
                    return index;
                }
            }
            return null;
        }

        fn refreshAuthority(state: *State, connection: *Connection) void {
            std.debug.assert(!connection.pending);
            const generation = connection.lease.client().peerOriginGeneration();
            if (generation == connection.authority_generation) return;
            const next = authority.Snapshot.build(
                state.allocator,
                connection.lease.client(),
                connection.lease.connectionOrigin(),
            ) catch authority.Snapshot{};
            var previous = connection.authority;
            connection.authority = next;
            connection.authority_generation = generation;
            connection.primary_allowed = !connection.lease.client()
                .peerOriginExcluded(connection.route.origin());
            previous.deinit();
        }

        fn releaseConnection(
            state: *State,
            index: usize,
            discard: bool,
        ) void {
            const connection = &state.connections[index];
            std.debug.assert(connection.active);
            std.debug.assert(!connection.pending);
            std.debug.assert(connection.command_count == 0);
            connection.authority.deinit();
            if (discard) connection.lease.discard() else connection.lease.release();
            connection.active = false;
            connection.pending = false;
            connection.primary_allowed = true;
            connection.authority_generation = 0;
            const previous = state.active_connections.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
        }

        fn releasePendingConnection(state: *State, index: usize) void {
            const connection = &state.connections[index];
            std.debug.assert(connection.active);
            std.debug.assert(connection.pending);
            std.debug.assert(connection.command_count == 0);
            connection.authority.deinit();
            connection.active = false;
            connection.pending = false;
            connection.primary_allowed = true;
            connection.authority_generation = 0;
            const previous = state.active_connections.fetchSub(1, .acq_rel);
            std.debug.assert(previous != 0);
        }

        fn failConnection(
            state: *State,
            index: usize,
            err: RequestError,
        ) void {
            const connection = &state.connections[index];
            while (connection.command_count != 0) {
                const command_index = connection.command_count - 1;
                const command = connection.commands[command_index].?;
                if (command.pending_acquire) |pending| {
                    pending.deinit();
                    command.pending_acquire = null;
                }
                clearPreparedEarly(command);
                if (command.stream) |stream| stream.fail(err);
                if (command.transaction) |*transaction| transaction.deinit();
                command.transaction = null;
                removeConnectionCommand(state, connection, command_index);
                command.connection_index = null;
                complete(state, command, null, err);
            }
            if (connection.pending)
                releasePendingConnection(state, index)
            else
                releaseConnection(state, index, true);
        }

        fn failAllActive(state: *State, err: RequestError) void {
            for (state.connections, 0..) |connection, index| {
                if (connection.active) failConnection(state, index, err);
            }
        }

        fn complete(
            state: *State,
            command: *Command,
            response_value: ?Pool.OwnedResponse,
            err: ?RequestError,
        ) void {
            var response = response_value;
            cancelBudgetWaiter(state, command);
            state.mutex.lockUncancelable(state.io);
            if (command.abandoned) {
                command.state = .completed;
                state.mutex.unlock(state.io);
                if (response) |*owned| owned.deinit();
                command.done.set(state.io);
                return;
            }
            command.response = response;
            response = null;
            command.err = err;
            command.state = .completed;
            state.completed_requests +|= 1;
            state.mutex.unlock(state.io);
            // Stream callers wait on the stream's own event, not command.done.
            // A pending connection failure must wake them here.
            if (err) |value| if (command.stream) |stream| stream.fail(value);
            command.done.set(state.io);
        }

        fn takeResult(
            state: *State,
            command: *Command,
        ) RequestError!Pool.OwnedResponse {
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
            if (command.response) |*response| response.deinit();
            command.response = null;
        }

        fn cancelBudgetWaiter(state: *State, command: *Command) void {
            state.pool.cancelConnectionBudgetWaiter(&command.budget_waiter);
        }

        fn isClosed(state: *State) bool {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            return state.closed;
        }

        fn activeRequestCount(state: *State) usize {
            return state.active_requests.load(.acquire);
        }

        fn earliestDeadline(state: *State) ?std.Io.Clock.Timestamp {
            var earliest: ?std.Io.Clock.Timestamp = null;
            for (state.connections) |connection| {
                if (!connection.active) continue;
                for (connection.commands[0..connection.command_count]) |maybe| {
                    const deadline = maybe.?.deadline orelse continue;
                    earliest = if (earliest) |current|
                        if (std.Io.Clock.Timestamp.compare(
                            deadline,
                            .lt,
                            current,
                        )) deadline else current
                    else
                        deadline;
                }
            }
            state.mutex.lockUncancelable(state.io);
            const capacity_blocked = state.head != null;
            state.mutex.unlock(state.io);
            if (capacity_blocked) {
                const poll_deadline = std.Io.Clock.Timestamp.fromNow(
                    state.io,
                    .{
                        .clock = .awake,
                        .raw = state.options.capacity_poll_interval,
                    },
                );
                earliest = if (earliest) |current|
                    if (std.Io.Clock.Timestamp.compare(
                        poll_deadline,
                        .lt,
                        current,
                    )) poll_deadline else current
                else
                    poll_deadline;
            }
            return earliest;
        }

        fn responseStreamId(response: Runtime.StreamingResponseEvent) u62 {
            return switch (response) {
                .message => |message| message.stream_id,
                .reset => |reset| reset.stream_id,
            };
        }
    };
}
