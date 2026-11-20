//! Cloneable HTTP/3 request sender backed by bounded route drivers.
//!
//! Producers enqueue stack-owned commands and wait on per-command events. The
//! dispatcher assigns each active origin/Alt-Svc route to exactly one driver,
//! while unrelated routes may acquire and drive independent connections in
//! parallel. Each connection therefore retains one send/receive owner without
//! imposing cross-origin head-of-line blocking. Borrowed request storage
//! remains valid until completion.

const std = @import("std");
const Guard = @import("../../../internal/mutex_guard.zig").Guard;
const http3 = @import("../../mod.zig");
const connection_budget = @import("../../../internal/connection_budget.zig");
const authority = @import("shared/authority.zig");
const route_key = @import("shared/route.zig");
const stream_command = @import("../shared_handshake_client_pool/stream_command.zig");

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
    /// Maximum independently driven origin/Alt-Svc routes. Each route retains
    /// exactly one connection owner while unrelated routes can progress in
    /// parallel.
    max_connection_drivers: usize = 1,
};

pub const Stats = struct {
    queued: usize,
    batches: u64,
    coalesced_requests: u64,
};

const max_batch_limit: usize = 64;
const max_driver_limit: usize = 64;

pub fn Dispatcher(comptime PoolType: type, comptime Runtime: type) type {
    return struct {
        state: *State,

        const Self = @This();
        pub const RequestError = Runtime.ReceiveTimeoutError ||
            Runtime.HandshakeClientPoolError || Error;
        const StreamType = stream_command.Stream(PoolType);
        const CommandState = enum { idle, queued, in_flight, completed };

        const RouteTurn = struct {
            key: route_key.Key = undefined,
            primary_allowed: bool = true,
            authority: authority.Snapshot = .{},
            authority_generation: u64 = 0,
            activity: std.Io.Event = .unset,
            next: ?*RouteTurn = null,
        };

        const Command = struct {
            uri: []const u8,
            request: Runtime.UriRequestOptions,
            alt_svc: ?http3.AltSvcTarget,
            deadline: ?std.Io.Clock.Timestamp,
            reclaimer: ?connection_budget.Reclaimer = null,
            route_key: route_key.Key,
            previous: ?*Command = null,
            next: ?*Command = null,
            state: CommandState = .idle,
            abandoned: bool = false,
            cancel_requested: bool = false,
            active_route: ?*RouteTurn = null,
            response: ?Runtime.OwnedHandshakeResponse = null,
            err: ?RequestError = null,
            done: std.Io.Event = .unset,
            stream: ?*StreamType = null,
            stream_request: ?http3.Request = null,
            stream_body_length: ?usize = null,
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

        const State = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            pool: *PoolType,
            options: Options,
            mutex: std.Io.Mutex = .init,
            ready: std.Io.Condition = .init,
            head: ?*Command = null,
            tail: ?*Command = null,
            active_routes: ?*RouteTurn = null,
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
                errdefer allocator.destroy(stream);
                stream.* = StreamType.init(state.pool, allocator, state.io);
                stream.expected_body_length = body_length orelse try http3.contentLength(request_value.headers);
                errdefer stream.deinit();
                const handle = try allocator.create(StreamHandle);
                errdefer allocator.destroy(handle);
                handle.* = .{
                    .state = state,
                    .command = .{
                        .uri = uri,
                        .request = .{},
                        .alt_svc = target,
                        .deadline = deadline,
                        .route_key = identity,
                        .stream = stream,
                        .stream_request = request_value,
                        .stream_body_length = body_length,
                    },
                    .stream = stream,
                    .allocator = allocator,
                };
                try enqueue(state, &handle.command);
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
            ) RequestError!Runtime.OwnedHandshakeResponse {
                const identity = try route_key.Key.init(
                    uri,
                    alt_svc,
                    reclaimer,
                );
                var command: Command = .{
                    .uri = uri,
                    .request = request_options,
                    .alt_svc = alt_svc,
                    .deadline = deadline,
                    .reclaimer = reclaimer,
                    .route_key = identity,
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
                options.max_batch_requests > max_batch_limit or
                options.max_connection_drivers == 0 or
                options.max_connection_drivers > max_driver_limit)
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
            std.debug.assert(self.state.active_routes == null);
            const allocator = self.state.allocator;
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
            var route = state.active_routes;
            while (route) |active| : (route = active.next) {
                active.activity.set(state.io);
            }
            guard.unlock();
        }

        pub fn run(self: *Self) (Error || std.Io.Cancelable)!void {
            const state = self.state;
            if (state.running.swap(true, .acq_rel)) {
                return error.SharedDriverAlreadyRunning;
            }
            defer state.running.store(false, .release);
            var workers: std.Io.Group = .init;
            var start: std.Io.Event = .unset;
            // Prevent an already-closed dispatcher from letting the first
            // worker finish the group before the remaining members are
            // registered. The stack event remains valid until group await.
            for (0..state.options.max_connection_drivers) |_| {
                workers.async(state.io, Worker.run, .{ state, &start });
            }
            start.set(state.io);
            workers.await(state.io) catch |err| {
                closeState(state);
                return err;
            };
        }

        const Worker = struct {
            fn run(state: *State, start: *std.Io.Event) void {
                start.wait(state.io) catch {
                    closeState(state);
                    return;
                };
                runFallible(state) catch {
                    closeState(state);
                };
            }

            fn runFallible(state: *State) RequestError!void {
                while (true) {
                    var commands: [max_batch_limit]*Command = undefined;
                    var route: RouteTurn = .{};
                    switch (try takeBatch(state, &route, &commands)) {
                        .closed => return,
                        .batch => |count| {
                            const result = executeBatch(
                                state,
                                &route,
                                commands[0..count],
                            );
                            finishRoute(state, &route);
                            result catch |err| {
                                if (err == error.Canceled) return err;
                            };
                        },
                    }
                }
            }
        };

        fn finishRoute(state: *State, route: *RouteTurn) void {
            state.mutex.lockUncancelable(state.io);
            var link = &state.active_routes;
            while (link.*) |active| {
                if (active == route) {
                    link.* = active.next;
                    route.next = null;
                    var published = route.authority;
                    route.authority = .{};
                    state.ready.broadcast(state.io);
                    state.mutex.unlock(state.io);
                    published.deinit();
                    return;
                }
                link = &active.next;
            }
            state.mutex.unlock(state.io);
            unreachable;
        }

        fn routeAccepts(
            route: *const RouteTurn,
            command: *const Command,
        ) bool {
            return (route.primary_allowed and
                route.key.eql(&command.route_key)) or
                route.authority.allows(&command.route_key);
        }

        fn findActiveRoute(
            state: *State,
            command: *const Command,
        ) ?*RouteTurn {
            var route = state.active_routes;
            while (route) |active| : (route = active.next) {
                if (routeAccepts(active, command)) return active;
            }
            return null;
        }

        fn firstRunnableCommand(state: *State) ?*Command {
            var command = state.head;
            while (command) |candidate| : (command = candidate.next) {
                if (findActiveRoute(state, candidate) == null) {
                    return candidate;
                }
            }
            return null;
        }

        const TakeResult = union(enum) {
            closed,
            batch: usize,
        };

        fn takeBatch(
            state: *State,
            route: *RouteTurn,
            out: *[max_batch_limit]*Command,
        ) RequestError!TakeResult {
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            while (true) {
                if (state.closed) return .closed;
                const first = firstRunnableCommand(state) orelse {
                    try state.ready.wait(state.io, &state.mutex);
                    continue;
                };
                route.* = .{
                    .key = first.route_key,
                    .primary_allowed = true,
                    .authority = .{},
                    .authority_generation = 0,
                    .activity = .unset,
                    .next = state.active_routes,
                };
                state.active_routes = route;

                detach(state, first);
                first.state = .in_flight;
                first.active_route = route;
                out[0] = first;
                if (first.stream != null) return .{ .batch = 1 };
                var count: usize = 1;
                var current = state.head;
                while (current) |candidate| {
                    const next = candidate.next;
                    if (count < state.options.max_batch_requests and
                        routeAccepts(route, candidate))
                    {
                        detach(state, candidate);
                        candidate.state = .in_flight;
                        candidate.active_route = route;
                        out[count] = candidate;
                        count += 1;
                    }
                    current = next;
                }
                return .{ .batch = count };
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
            if (findActiveRoute(state, command)) |route| {
                route.activity.set(state.io);
            } else {
                state.ready.signal(state.io);
            }
            state.mutex.unlock(state.io);
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
            state.mutex.lockUncancelable(state.io);
            command.abandoned = true;
            if (command.state == .in_flight and
                !command.cancel_requested)
            {
                command.cancel_requested = true;
                if (command.active_route) |route| route.activity.set(state.io);
            }
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

        const Active = struct {
            command: *Command,
            stream_id: ?u62 = null,
        };

        fn executeBatch(
            state: *State,
            route: *RouteTurn,
            commands: []*Command,
        ) RequestError!void {
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
                route,
                &active_storage,
                &active_count,
                &total_owned,
            ) catch |err| {
                for (active_storage[0..active_count]) |active| {
                    complete(state, active.command, null, err);
                }
                return err;
            };
        }

        fn refreshAuthority(
            state: *State,
            route: *RouteTurn,
            lease: *PoolType.Lease,
        ) void {
            const generation = lease.client().peerOriginGeneration();
            state.mutex.lockUncancelable(state.io);
            const current = route.authority_generation;
            state.mutex.unlock(state.io);
            if (current == generation) return;

            var built_ok = true;
            var next = authority.Snapshot.build(
                state.pool.allocator,
                lease.client(),
                lease.connectionOrigin(),
            ) catch blk: {
                built_ok = false;
                break :blk authority.Snapshot{};
            };
            var next_owned = true;
            defer if (next_owned) next.deinit();

            state.mutex.lockUncancelable(state.io);
            var previous = route.authority;
            route.authority = if (state.closed) .{} else next;
            if (!state.closed) {
                next_owned = false;
                route.primary_allowed = !lease.client().peerOriginExcluded(
                    route.key.origin(),
                );
                if (built_ok) route.authority_generation = generation;
                var command = state.head;
                while (command) |candidate| : (command = candidate.next) {
                    if (routeAccepts(route, candidate)) {
                        route.activity.set(state.io);
                        break;
                    }
                }
                // A generation change can also revoke a previously published
                // origin (notably after 421). Re-evaluate queued commands on
                // idle workers so they may acquire an independent connection.
                state.ready.broadcast(state.io);
            }
            state.mutex.unlock(state.io);
            previous.deinit();
        }

        fn driveConnection(
            state: *State,
            route: *RouteTurn,
            active: *[max_batch_limit]Active,
            active_count: *usize,
            total_owned: *usize,
        ) RequestError!void {
            while (active_count.* != 0) {
                try processControl(
                    state,
                    route,
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
                refreshAuthority(state, route, &lease);
                if (active[0].command.stream) |stream| {
                    return driveStream(
                        state,
                        route,
                        active[0].command,
                        stream,
                        &lease,
                    );
                }

                while (active_count.* != 0) {
                    try processControl(
                        state,
                        route,
                        active,
                        active_count,
                        total_owned,
                        &lease,
                    );
                    if (active_count.* == 0) break;
                    try sendUnsent(state, active, active_count, &lease);
                    if (active_count.* == 0) break;
                    refreshAuthority(state, route, &lease);

                    const receive_result = lease.client()
                        .receiveNextResponseBeforeOrWake(
                        earliestDeadline(active, active_count.*),
                        &route.activity,
                    );
                    refreshAuthority(state, route, &lease);
                    const maybe_event = receive_result catch |err| switch (err) {
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
                                    command.route_key.origin(),
                                ) catch |err| {
                                    response.deinit(state.pool.allocator);
                                    return err;
                                };
                                refreshAuthority(state, route, &lease);
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
            route: *RouteTurn,
            active: *[max_batch_limit]Active,
            active_count: *usize,
            total_owned: *usize,
            lease: ?*PoolType.Lease,
        ) RequestError!void {
            state.mutex.lockUncancelable(state.io);
            route.activity.reset();
            const closed = state.closed;
            if (!closed and active_count.* != 0) {
                const previously_owned = total_owned.*;
                var current = state.head;
                while (current) |candidate| {
                    const next = candidate.next;
                    if (active_count.* < state.options.max_batch_requests and
                        routeAccepts(route, candidate))
                    {
                        detach(state, candidate);
                        candidate.state = .in_flight;
                        candidate.active_route = route;
                        active[active_count.*] = .{ .command = candidate };
                        active_count.* += 1;
                        total_owned.* += 1;
                    }
                    current = next;
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

        fn driveStream(
            state: *State,
            route: *RouteTurn,
            command: *Command,
            stream: *StreamType,
            lease: *PoolType.Lease,
        ) RequestError!void {
            _ = route;
            const request = command.stream_request orelse
                return error.InvalidHeader;
            const stream_id = lease.client().tryStartRequest(
                request,
                command.stream_body_length,
            ) catch |err| {
                stream.fail(err);
                return @errorCast(err);
            };
            stream.markStarted(stream_id);

            var pending_write: ?StreamType.Write = null;
            var pending_trailers: ?StreamType.OwnedTrailers = null;
            defer {
                if (pending_write) |write| {
                    state.pool.allocator.free(write.data);
                }
                if (pending_trailers) |*trailers| {
                    trailers.deinit(state.pool.allocator);
                }
            }

            while (true) {
                if (stream.isCancelled()) {
                    lease.client().tryCancelRequest(
                        stream_id,
                        http3.ApplicationErrorCode.request_cancelled,
                    ) catch {};
                    stream.finish();
                    complete(state, command, null, null);
                    return;
                }
                while (true) {
                    if (pending_write == null) {
                        pending_write = stream.takeWrite();
                    }
                    if (pending_write) |*write| {
                        lease.client().trySendRequestBodyFragment(
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
                            => break,
                            else => {
                                state.pool.allocator.free(write.data);
                                pending_write = null;
                                stream.fail(err);
                                return @errorCast(err);
                            },
                        };
                        if (!write.fragment.complete) continue;
                        state.pool.allocator.free(write.data);
                        pending_write = null;
                        continue;
                    }
                    if (pending_trailers == null) {
                        pending_trailers = stream.takeTrailers();
                    }
                    if (pending_trailers) |*trailers| {
                        lease.client().tryFinishRequestTrailers(
                            stream_id,
                            trailers.fields,
                        ) catch |err| switch (err) {
                            error.PacingLimited,
                            error.CongestionLimited,
                            error.FlowControlBlocked,
                            error.StreamLimitExceeded,
                            error.AntiAmplificationLimited,
                            => break,
                            else => {
                                trailers.deinit(state.pool.allocator);
                                pending_trailers = null;
                                stream.fail(err);
                                return @errorCast(err);
                            },
                        };
                        trailers.deinit(state.pool.allocator);
                        pending_trailers = null;
                        continue;
                    }
                    break;
                }

                stream.resetActivityIfIdle();
                const maybe_event = lease.client()
                    .receiveResponseEventBeforeOrWake(
                    stream_id,
                    command.deadline,
                    &stream.activity,
                ) catch |err| {
                    stream.fail(err);
                    return @errorCast(err);
                };
                if (maybe_event) |event_value| {
                    var event = event_value;
                    defer event.deinit(state.pool.allocator);
                    switch (event) {
                        .head => |head_value| {
                            event = .finished;
                            var head = head_value;
                            if (head != .response) {
                                head.deinit(state.pool.allocator);
                                continue;
                            }
                            const decoded = head.response;
                            if (decoded.status < 200) {
                                stream.deliverInformational(decoded) catch |err| {
                                    stream.fail(err);
                                    return @errorCast(err);
                                };
                                continue;
                            }
                            stream.deliverHead(decoded);
                        },
                        .data_available => {
                            var buffer: [16 * 1024]u8 = undefined;
                            const maybe_count = lease.client()
                                .readResponseDataOnce(
                                stream_id,
                                &buffer,
                            ) catch |err| {
                                stream.fail(err);
                                return @errorCast(err);
                            };
                            const count = maybe_count orelse 0;
                            if (count != 0) {
                                stream.deliverData(
                                    buffer[0..count],
                                ) catch |err| {
                                    stream.fail(err);
                                    return @errorCast(err);
                                };
                            }
                        },
                        .trailers => |trailers_value| {
                            event = .finished;
                            stream.deliverTrailers(trailers_value);
                        },
                        .finished => {
                            stream.finish();
                            complete(state, command, null, null);
                            return;
                        },
                        .push_promise => |promise_value| {
                            event = .finished;
                            var promise = promise_value;
                            promise.deinit(state.pool.allocator);
                        },
                    }
                }
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
                command.active_route = null;
                state.mutex.unlock(state.io);
                if (response) |*owned| owned.deinit(state.pool.allocator);
                command.done.set(state.io);
                return;
            }
            command.response = response;
            response = null;
            command.err = err;
            command.state = .completed;
            command.active_route = null;
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
    };
}
