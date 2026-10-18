//! Dispatcher-owned H3 CONNECT-UDP relay registry.

const std = @import("std");

const net = std.Io.net;

pub fn Server(comptime Runtime: type) type {
    return struct {
        pub const ConnectionHandle = @FieldType(
            Runtime.EndpointRequestEvent,
            "connection_handle",
        );

        pub const Key = struct {
            connection_handle: ConnectionHandle,
            stream_id: u62,

            pub fn eql(a: Key, b: Key) bool {
                return a.connection_handle == b.connection_handle and
                    a.stream_id == b.stream_id;
            }
        };

        pub const Options = struct {
            /// Bound covering active relays plus unconsumed relay-closed
            /// events, so terminal notification never requires allocation.
            max_relays: usize = 32,
            max_queued_target_datagrams: usize = 16,
            max_queued_target_bytes: usize = 64 * 1024,
            per_relay_turn_budget: usize = 16,
        };

        pub const EndReason = enum {
            association_closed,
            connection_closed,
            stream_reset,
        };

        pub const Stats = struct {
            session_to_udp_datagrams: u64 = 0,
            session_to_udp_bytes: u64 = 0,
            udp_to_session_datagrams: u64 = 0,
            udp_to_session_bytes: u64 = 0,
            dropped_unexpected_source: u64 = 0,
            dropped_truncated: u64 = 0,
            dropped_backpressure: u64 = 0,
        };

        pub const RelayClosed = struct {
            key: Key,
            reason: EndReason,
            stats: Stats,
        };

        pub const Event = union(enum) {
            endpoint: Runtime.EndpointServerEvent,
            relay_closed: RelayClosed,

            pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .endpoint => |*event| event.deinit(allocator),
                    .relay_closed => {},
                }
                self.* = undefined;
            }
        };

        const State = struct {
            key: Key,
            socket: net.Socket,
            target: net.IpAddress,
            session: Runtime.ConnectUdpServerSession,
            session_buffer: []u8,
            udp_buffer: []u8,
            pending: std.ArrayList([]u8) = .empty,
            pending_bytes: usize = 0,
            stats: Stats = .{},

            fn deinit(
                self: *State,
                allocator: std.mem.Allocator,
                io: std.Io,
            ) void {
                for (self.pending.items) |payload| allocator.free(payload);
                self.pending.deinit(allocator);
                allocator.free(self.session_buffer);
                allocator.free(self.udp_buffer);
                self.session.deinit();
                self.socket.close(io);
                allocator.destroy(self);
            }
        };

        const UdpResult = struct {
            key: Key,
            result: anyerror!net.IncomingMessage,
        };

        const Wake = union(enum) {
            endpoint: anyerror!?Runtime.EndpointServerEvent,
            udp: UdpResult,
        };

        endpoint: *Runtime.EndpointServer,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        states: std.ArrayList(*State) = .empty,
        relay_events: std.ArrayList(RelayClosed) = .empty,
        pending_endpoint: ?Runtime.EndpointServerEvent = null,
        wake_storage: []Wake,
        completed_storage: []Wake,
        round_robin_start: usize = 0,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            endpoint: *Runtime.EndpointServer,
            options: Options,
        ) !Self {
            if (options.max_relays == 0 or
                options.max_queued_target_datagrams == 0 or
                options.max_queued_target_bytes == 0 or
                options.per_relay_turn_budget == 0)
            {
                return error.InvalidRelayOptions;
            }
            const result_capacity = std.math.add(
                usize,
                options.max_relays,
                1,
            ) catch return error.IntegerOverflow;
            const wake_storage = try allocator.alloc(Wake, result_capacity);
            errdefer allocator.free(wake_storage);
            const completed_storage = try allocator.alloc(
                Wake,
                result_capacity,
            );
            errdefer allocator.free(completed_storage);
            var self = Self{
                .endpoint = endpoint,
                .allocator = allocator,
                .io = io,
                .options = options,
                .wake_storage = wake_storage,
                .completed_storage = completed_storage,
            };
            errdefer self.states.deinit(allocator);
            try self.states.ensureTotalCapacity(
                allocator,
                options.max_relays,
            );
            errdefer self.relay_events.deinit(allocator);
            try self.relay_events.ensureTotalCapacity(
                allocator,
                options.max_relays,
            );
            return self;
        }

        pub fn deinit(self: *Self) void {
            if (self.pending_endpoint) |*event| event.deinit(self.allocator);
            for (self.states.items) |state| {
                state.deinit(self.allocator, self.io);
            }
            self.states.deinit(self.allocator);
            self.relay_events.deinit(self.allocator);
            self.allocator.free(self.wake_storage);
            self.allocator.free(self.completed_storage);
            self.* = undefined;
        }

        pub fn relayCount(self: *const Self) usize {
            return self.states.items.len;
        }

        pub fn relayStats(self: *const Self, key: Key) ?Stats {
            const index = self.findIndex(key) orelse return null;
            return self.states.items[index].stats;
        }

        /// Register an already accepted CONNECT-UDP association. UDP socket
        /// ownership transfers only on success and is returned by unregister.
        pub fn register(
            self: *Self,
            key: Key,
            socket: net.Socket,
            target: net.IpAddress,
        ) !void {
            if (self.relay_events.items.len >= self.options.max_relays or
                self.states.items.len >=
                    self.options.max_relays - self.relay_events.items.len)
            {
                return error.RelayLimitReached;
            }
            if (self.findIndex(key) != null) return error.DuplicateRelay;
            const parent = self.endpoint.session(key.connection_handle) orelse
                return error.UnknownConnectionHandle;
            var typed = try parent.connectUdpSession(key.stream_id);
            var typed_owned = true;
            errdefer if (typed_owned) typed.deinit();
            const send_maximum = typed.maxPayloadSize() orelse
                return error.DatagramUnavailable;
            const receive_maximum = typed.maxReceivePayloadSize() orelse
                return error.DatagramUnavailable;
            try self.endpoint.dispatcher.refreshConnectionTimer(
                key.connection_handle,
            );
            const state = try self.allocator.create(State);
            var state_owned = true;
            errdefer if (state_owned) self.allocator.destroy(state);
            const session_buffer = try self.allocator.alloc(
                u8,
                receive_maximum,
            );
            errdefer self.allocator.free(session_buffer);
            const udp_buffer = try self.allocator.alloc(u8, send_maximum);
            errdefer self.allocator.free(udp_buffer);
            state.* = .{
                .key = key,
                .socket = socket,
                .target = target,
                .session = typed,
                .session_buffer = session_buffer,
                .udp_buffer = udp_buffer,
            };
            try self.states.append(self.allocator, state);
            typed_owned = false;
            state_owned = false;
        }

        /// Finish the response half after a relay-closed event. This is a
        /// nonblocking dispatcher-owned send for `association_closed` events;
        /// reset and connection-close events have no response half to finish.
        /// PacingLimited/CongestionLimited leave the association registered so
        /// the caller can progress the endpoint and retry with the same key.
        pub fn tryFinishResponse(self: *Self, key: Key) !void {
            const parent = self.endpoint.session(key.connection_handle) orelse
                return error.UnknownConnectionHandle;
            try parent.trySendResponseBody(key.stream_id, &.{}, true);
            try parent.closeConnectDatagramAssociation(key.stream_id);
            try self.endpoint.dispatcher.refreshConnectionTimer(
                key.connection_handle,
            );
        }

        /// Remove one relay and transfer its UDP socket back to the caller.
        pub fn unregister(self: *Self, key: Key) ?struct { net.Socket, Stats } {
            const index = self.findIndex(key) orelse return null;
            const state = self.states.orderedRemove(index);
            const socket = state.socket;
            const stats = state.stats;
            for (state.pending.items) |payload| self.allocator.free(payload);
            state.pending.deinit(self.allocator);
            self.allocator.free(state.session_buffer);
            self.allocator.free(state.udp_buffer);
            state.session.deinit();
            self.allocator.destroy(state);
            self.normalizeCursor();
            return .{ socket, stats };
        }

        pub fn pumpOnce(
            self: *Self,
            supported_versions: []const u32,
            poll_interval: std.Io.Clock.Duration,
        ) anyerror!?Event {
            if (self.pending_endpoint) |event| {
                self.pending_endpoint = null;
                return .{ .endpoint = event };
            }
            if (self.relay_events.items.len != 0) {
                return .{ .relay_closed = self.relay_events.orderedRemove(0) };
            }
            const revisit_relays = try self.serviceRelays();
            if (self.relay_events.items.len != 0) {
                return .{ .relay_closed = self.relay_events.orderedRemove(0) };
            }
            // A full per-relay budget cannot prove the already-routed queue is
            // empty. Yield one nonblocking turn so the caller can reschedule
            // every relay fairly before this pump waits for new endpoint I/O.
            if (revisit_relays) return null;
            if (self.states.items.len == 0) {
                const event = (try self.endpoint.receiveOnce(
                    supported_versions,
                    poll_interval,
                )) orelse return null;
                return .{ .endpoint = event };
            }

            const Task = struct {
                fn endpointReceive(
                    endpoint: *Runtime.EndpointServer,
                    versions: []const u32,
                    interval: std.Io.Clock.Duration,
                ) anyerror!?Runtime.EndpointServerEvent {
                    return endpoint.receiveOnce(versions, interval);
                }

                fn udpReceive(
                    state: *State,
                    active_io: std.Io,
                ) UdpResult {
                    return .{
                        .key = state.key,
                        .result = state.socket.receive(
                            active_io,
                            state.udp_buffer,
                        ),
                    };
                }
            };
            var select: std.Io.Select(Wake) = .init(
                self.io,
                self.wake_storage,
            );
            var drained = false;
            defer if (!drained) select.cancelDiscard();
            const count = self.states.items.len;
            for (0..count) |offset| {
                const index = (self.round_robin_start + offset) % count;
                select.async(
                    .udp,
                    Task.udpReceive,
                    .{ self.states.items[index], self.io },
                );
            }
            try select.concurrent(
                .endpoint,
                Task.endpointReceive,
                .{ self.endpoint, supported_versions, poll_interval },
            );

            var completed_count: usize = 1;
            self.completed_storage[0] = try select.await();
            while (select.cancel()) |late| {
                self.completed_storage[completed_count] = late;
                completed_count += 1;
            }
            drained = true;

            var closed_handle: ?ConnectionHandle = null;
            for (self.completed_storage[0..completed_count]) |wake| switch (wake) {
                .endpoint => |result| {
                    const maybe_event = result catch |err| switch (err) {
                        error.Canceled => continue,
                        else => return err,
                    };
                    if (maybe_event) |event| {
                        if (event == .closed) {
                            closed_handle = event.closed.handle;
                        }
                        if (self.pending_endpoint != null) {
                            var duplicate = event;
                            duplicate.deinit(self.allocator);
                            return error.DuplicateEndpointEvent;
                        }
                        self.pending_endpoint = event;
                    }
                },
                .udp => {},
            };
            for (self.completed_storage[0..completed_count]) |wake| switch (wake) {
                .udp => |udp| {
                    if (closed_handle) |handle| {
                        if (udp.key.connection_handle == handle) continue;
                    }
                    try self.handleUdpResult(udp);
                },
                .endpoint => {},
            };
            if (closed_handle) |handle| {
                try self.removeConnectionRelays(handle);
            }
            _ = try self.serviceRelays();

            if (self.pending_endpoint) |event| {
                self.pending_endpoint = null;
                return .{ .endpoint = event };
            }
            if (self.relay_events.items.len != 0) {
                return .{ .relay_closed = self.relay_events.orderedRemove(0) };
            }
            return null;
        }

        fn serviceRelays(self: *Self) !bool {
            if (self.states.items.len == 0) return false;
            const count = self.states.items.len;
            const start = self.round_robin_start;
            var revisit = false;
            var visited: usize = 0;
            while (visited < count) : (visited += 1) {
                const index = (start + visited) % count;
                if (try self.serviceState(
                    self.states.items[index],
                    &revisit,
                )) |reason| {
                    try self.closeState(index, reason);
                    return false;
                }
            }
            self.round_robin_start = (start + 1) % count;
            return revisit;
        }

        fn serviceState(
            self: *Self,
            state: *State,
            revisit: *bool,
        ) !?EndReason {
            var budget = self.options.per_relay_turn_budget;
            while (budget != 0 and state.pending.items.len != 0) : (budget -= 1) {
                const payload = state.pending.items[0];
                state.session.trySend(payload) catch |err| switch (err) {
                    error.CongestionLimited, error.PacingLimited => {
                        try self.endpoint.dispatcher.refreshConnectionTimer(
                            state.key.connection_handle,
                        );
                        break;
                    },
                    error.ConnectDatagramAssociationClosed => return .association_closed,
                    error.ConnectionClosed => return .connection_closed,
                    else => return err,
                };
                _ = state.pending.orderedRemove(0);
                state.pending_bytes -= payload.len;
                state.stats.udp_to_session_datagrams +|= 1;
                state.stats.udp_to_session_bytes +|= @intCast(payload.len);
                self.allocator.free(payload);
                try self.endpoint.dispatcher.refreshConnectionTimer(
                    state.key.connection_handle,
                );
            }
            if (budget == 0 and state.pending.items.len != 0) {
                revisit.* = true;
            }

            budget = self.options.per_relay_turn_budget;
            var session_drained = false;
            while (budget != 0) : (budget -= 1) {
                const step = state.session.pollReceiveIntoStep(
                    state.session_buffer,
                ) catch |err| switch (err) {
                    error.ConnectDatagramAssociationClosed => return .association_closed,
                    error.ConnectionClosed => return .connection_closed,
                    error.RequestCancelled => return .stream_reset,
                    else => return err,
                };
                switch (step) {
                    .empty => {
                        session_drained = true;
                        break;
                    },
                    .ignored_context => {},
                    .payload => |received| {
                        try state.socket.send(
                            self.io,
                            &state.target,
                            received.payload,
                        );
                        state.stats.session_to_udp_datagrams +|= 1;
                        state.stats.session_to_udp_bytes +|= @intCast(
                            received.payload.len,
                        );
                    },
                }
            }
            if (!session_drained and budget == 0) revisit.* = true;
            return null;
        }

        fn handleUdpResult(self: *Self, udp: UdpResult) !void {
            const index = self.findIndex(udp.key) orelse return;
            const state = self.states.items[index];
            const message = udp.result catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
            if (message.flags.trunc) {
                state.stats.dropped_truncated +|= 1;
                return;
            }
            if (!net.IpAddress.eql(&message.from, &state.target)) {
                state.stats.dropped_unexpected_source +|= 1;
                return;
            }
            if (state.pending.items.len == 0) {
                state.session.trySend(message.data) catch |err| switch (err) {
                    error.CongestionLimited, error.PacingLimited => {
                        try self.endpoint.dispatcher.refreshConnectionTimer(
                            state.key.connection_handle,
                        );
                        return self.enqueue(state, message.data);
                    },
                    error.ConnectDatagramAssociationClosed => {
                        return self.closeState(index, .association_closed);
                    },
                    error.ConnectionClosed => {
                        return self.closeState(index, .connection_closed);
                    },
                    else => return err,
                };
                state.stats.udp_to_session_datagrams +|= 1;
                state.stats.udp_to_session_bytes +|= @intCast(
                    message.data.len,
                );
                try self.endpoint.dispatcher.refreshConnectionTimer(
                    state.key.connection_handle,
                );
                return;
            }
            try self.enqueue(state, message.data);
        }

        fn enqueue(self: *Self, state: *State, payload: []const u8) !void {
            const new_bytes = std.math.add(
                usize,
                state.pending_bytes,
                payload.len,
            ) catch {
                state.stats.dropped_backpressure +|= 1;
                return;
            };
            if (state.pending.items.len >=
                self.options.max_queued_target_datagrams or
                new_bytes > self.options.max_queued_target_bytes)
            {
                state.stats.dropped_backpressure +|= 1;
                return;
            }
            const owned = try self.allocator.dupe(u8, payload);
            errdefer self.allocator.free(owned);
            try state.pending.append(self.allocator, owned);
            state.pending_bytes = new_bytes;
        }

        fn closeState(
            self: *Self,
            index: usize,
            reason: EndReason,
        ) !void {
            if (self.relay_events.items.len >= self.options.max_relays) {
                return error.RelayEventQueueFull;
            }
            const state = self.states.orderedRemove(index);
            const event = RelayClosed{
                .key = state.key,
                .reason = reason,
                .stats = state.stats,
            };
            state.deinit(self.allocator, self.io);
            self.normalizeCursor();
            self.relay_events.appendAssumeCapacity(event);
        }

        fn removeConnectionRelays(
            self: *Self,
            handle: ConnectionHandle,
        ) !void {
            var index: usize = self.states.items.len;
            while (index != 0) {
                index -= 1;
                if (self.states.items[index].key.connection_handle != handle) {
                    continue;
                }
                try self.closeState(index, .connection_closed);
            }
        }

        fn findIndex(self: *const Self, key: Key) ?usize {
            for (self.states.items, 0..) |state, index| {
                if (Key.eql(state.key, key)) return index;
            }
            return null;
        }

        fn normalizeCursor(self: *Self) void {
            if (self.states.items.len == 0) {
                self.round_robin_start = 0;
            } else {
                self.round_robin_start %= self.states.items.len;
            }
        }
    };
}
