//! Event-driven raw QUIC server for many connections on one UDP endpoint.
//!
//! `Server` is the sole socket receive owner. It admits Initial packets into
//! bounded handshake inboxes, performs TLS handshakes concurrently, promotes
//! established connections into stable storage, routes 1-RTT packets by CID,
//! and services the aggregate connection timer schedule. Applications consume
//! returned packets and use `connection(handle)` with socket-free poll/send
//! operations before refreshing the connection timer.

const std = @import("std");
const builtin = @import("builtin");
const deadline_policy = @import("../internal/deadline.zig");
const quic = @import("mod.zig");

test {
    _ = @import("endpoint_server/tests.zig");
}

pub const Options = struct {
    max_pending_handshakes: usize = 128,
    /// Aggregate pending plus established connection limit. Zero inherits
    /// `max_pending_handshakes`.
    max_connections: usize = 0,
    inbox_capacity: usize = 16,
    /// Absolute lifetime of one admitted handshake. Zero derives the bounded
    /// PTO budget from `ServerOptions.handshake_recovery`.
    handshake_timeout_ms: u32 = 0,
    /// Bound how long a socket wait may hide a completed handshake worker.
    handshake_poll_interval: std.Io.Duration = .fromMilliseconds(5),
};

pub const WorkerError = quic.handshake.AcceptTimeoutError;
pub const Error = WorkerError || quic.endpoint_dispatcher.Error ||
    std.Io.ConcurrentError || error{InvalidOptions};

pub const HandshakeFailure = struct {
    handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
    err: WorkerError,
};

pub const Event = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    packet: quic.endpoint_dispatcher.RoutedPacket,
    timer: quic.endpoint_dispatcher.TimerEvent,
    handshake_failed: HandshakeFailure,
    /// Unknown packets and Initials rejected by the configured admission
    /// budget retain their dispatcher ownership and classification.
    unrouted: quic.endpoint_dispatcher.Event,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .packet => |*packet| packet.packet.deinit(allocator),
            .unrouted => |*event| event.deinit(allocator),
            .connected, .timer, .handshake_failed => {},
        }
        self.* = undefined;
    }
};

pub const VisitEvent = union(enum) {
    connected: quic.endpoint_dispatcher.ConnectionHandle,
    packet: struct {
        connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
        connection_id_sequence: u64,
    },
    timer: quic.endpoint_dispatcher.TimerEvent,
    handshake_failed: HandshakeFailure,
    unrouted: quic.endpoint_dispatcher.Event,

    pub fn deinit(self: *VisitEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .unrouted => |*event| event.deinit(allocator),
            .connected, .packet, .timer, .handshake_failed => {},
        }
        self.* = undefined;
    }
};

fn callbackErrorSet(comptime callback: anytype) type {
    const callback_type = switch (@typeInfo(@TypeOf(callback))) {
        .@"fn" => @TypeOf(callback),
        .pointer => |pointer| pointer.child,
        else => @compileError("packet visitor must be a function"),
    };
    const return_type = @typeInfo(callback_type).@"fn".return_type orelse
        @compileError("packet visitor must have an explicit return type");
    return switch (@typeInfo(return_type)) {
        .error_union => |error_union| error_union.error_set,
        else => @compileError("packet visitor must return an error union"),
    };
}

const Admission = struct {
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
    inbox: *quic.handshake_inbox.Inbox,
    connection: *quic.handshake.EstablishedConnection,
    initial: quic.runtime.OwnedBytes,
    server_connection_id: [
        quic.endpoint_dispatcher.default_server_connection_id_len
    ]u8,
    deadline_ns: u64,
    registered: bool = true,
    initial_owned: bool = true,
    connection_initialized: bool = false,
    connection_owned: bool = true,

    fn source(self: *Admission) quic.runtime.DatagramSource {
        return self.inbox.datagramSource();
    }

    fn deadline(self: *const Admission) std.Io.Clock.Timestamp {
        return .{
            .raw = .{ .nanoseconds = @intCast(@min(
                self.deadline_ns,
                @as(u64, @intCast(std.math.maxInt(i64))),
            )) },
            .clock = .awake,
        };
    }

    fn takeInitial(self: *Admission) quic.runtime.OwnedBytes {
        std.debug.assert(self.initial_owned);
        self.initial_owned = false;
        return self.initial;
    }

    fn takeConnection(
        self: *Admission,
    ) *quic.handshake.EstablishedConnection {
        std.debug.assert(self.connection_initialized);
        std.debug.assert(self.connection_owned);
        self.connection_owned = false;
        return self.connection;
    }

    fn deinit(self: *Admission) void {
        const allocator = self.inbox.allocator;
        if (self.registered) {
            _ = self.dispatcher.unregisterPendingHandshake(
                self.handle,
            ) catch false;
        }
        if (self.initial_owned) self.initial.deinit(allocator);
        if (self.connection_owned) {
            if (self.connection_initialized) self.connection.deinit();
            allocator.destroy(self.connection);
        }
        self.inbox.deinit();
        allocator.destroy(self.inbox);
        self.* = undefined;
    }
};

const Completion = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    admission: *Admission,
    result: union(enum) {
        success,
        failure: WorkerError,
    },

    fn deinit(self: *Completion) void {
        const allocator = self.admission.inbox.allocator;
        self.admission.deinit();
        allocator.destroy(self.admission);
        self.* = undefined;
    }
};

comptime {
    // The bounded completion queue is sized by max_pending_handshakes. Keep
    // established connection state behind its final stable pointer so every
    // queue slot remains fixed-size metadata rather than a multi-kilobyte
    // connection value.
    std.debug.assert(@sizeOf(Completion) <= 4 * @sizeOf(usize));
}

const WorkerContext = struct {
    endpoint: *quic.runtime.Endpoint,
    options: quic.handshake.ServerOptions,
    io: std.Io,
    completed: *std.Io.Queue(Completion),
};

/// Shared-endpoint raw QUIC connection owner. Connection pointers remain
/// stable until `removeConnection` or `deinit`; callers must not move or free
/// them. All UDP receives must flow through this server.
pub const Server = struct {
    allocator: std.mem.Allocator,
    endpoint: *quic.runtime.Endpoint,
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    options: Options,
    handshake_options: quic.handshake.ServerOptions,
    next_handle: quic.endpoint_dispatcher.ConnectionHandle = 1,
    next_handle_mutex: std.Io.Mutex = .init,
    workers: std.Io.Group = .init,
    worker_context: *WorkerContext,
    active_workers: std.atomic.Value(usize) = .init(0),
    handshake_poll_count: if (builtin.is_test) usize else void =
        if (builtin.is_test) 0 else {},
    completed_storage: []Completion,
    completed: *std.Io.Queue(Completion),
    admissions_mutex: std.Io.Mutex = .init,
    admissions: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.PendingHandshakeHandle,
        *Admission,
    ) = .empty,
    connections: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        *quic.handshake.EstablishedConnection,
    ) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        handshake_options: quic.handshake.ServerOptions,
        options: Options,
    ) Error!Server {
        if (options.max_pending_handshakes == 0 or
            options.inbox_capacity == 0 or
            options.handshake_poll_interval.nanoseconds <= 0)
        {
            return error.InvalidOptions;
        }
        const completed_storage = try allocator.alloc(
            Completion,
            options.max_pending_handshakes,
        );
        errdefer allocator.free(completed_storage);
        const completed = try allocator.create(std.Io.Queue(Completion));
        errdefer allocator.destroy(completed);
        completed.* = .init(completed_storage);
        const worker_context = try allocator.create(WorkerContext);
        errdefer allocator.destroy(worker_context);
        const dispatcher = try allocator.create(
            quic.endpoint_dispatcher.Dispatcher,
        );
        errdefer allocator.destroy(dispatcher);
        dispatcher.* = .init(allocator, endpoint);
        errdefer dispatcher.deinit();
        const server = Server{
            .allocator = allocator,
            .endpoint = endpoint,
            .dispatcher = dispatcher,
            .options = options,
            .handshake_options = handshake_options,
            .worker_context = worker_context,
            .completed_storage = completed_storage,
            .completed = completed,
        };
        worker_context.* = .{
            .endpoint = endpoint,
            .options = handshake_options,
            .io = endpoint.io,
            .completed = completed,
        };
        return server;
    }

    pub fn deinit(self: *Server) void {
        self.workers.cancel(self.endpoint.io);
        while (self.pollCompletion()) |completion| {
            var owned = completion;
            owned.deinit();
        }
        self.completed.close(self.endpoint.io);
        var admission_iterator = self.admissions.valueIterator();
        while (admission_iterator.next()) |admission| {
            admission.*.deinit();
            self.allocator.destroy(admission.*);
        }
        self.admissions.deinit(self.allocator);
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            _ = self.dispatcher.unregisterConnection(
                entry.key_ptr.*,
            ) catch false;
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit(self.allocator);
        self.dispatcher.deinit();
        self.allocator.destroy(self.dispatcher);
        self.allocator.destroy(self.worker_context);
        self.allocator.destroy(self.completed);
        self.allocator.free(self.completed_storage);
        self.* = undefined;
    }

    pub fn address(self: *const Server) std.Io.net.IpAddress {
        return self.endpoint.address();
    }

    pub fn connectionCount(self: *const Server) usize {
        return self.connections.count();
    }

    pub fn pendingHandshakeCount(self: *const Server) usize {
        return self.active_workers.load(.acquire);
    }

    pub fn connection(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*quic.handshake.EstablishedConnection {
        return self.connections.get(handle);
    }

    pub fn refreshConnectionTimer(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!void {
        try self.dispatcher.refreshConnectionTimer(handle);
    }

    /// Apply the connection's negotiated ACK policy after the application has
    /// accepted a routed packet. Keeping this explicit lets callers finish
    /// protocol-level transactional processing before acknowledging it.
    pub fn acknowledgePacketIfNeeded(
        self: *Server,
        packet: *const quic.endpoint_dispatcher.RoutedPacket,
    ) Error!bool {
        const established = self.connection(packet.connection_handle) orelse
            return error.UnknownConnectionHandle;
        const sent = established.connection.sendAckForPacketIfNeeded(
            packet.packet.packet.packet_number,
            packet.packet.frames,
        ) catch |err| {
            self.dispatcher.refreshConnectionTimer(
                packet.connection_handle,
            ) catch {};
            return err;
        };
        try self.dispatcher.refreshConnectionTimer(packet.connection_handle);
        return sent;
    }

    /// Attempt one nonblocking application send and keep the endpoint timer
    /// schedule synchronized on both success and transport backpressure.
    pub fn trySend(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        frames: []const quic.Frame,
    ) Error!void {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        established.connection.trySend(frames) catch |err| {
            self.dispatcher.refreshConnectionTimer(handle) catch {};
            return err;
        };
        try self.dispatcher.refreshConnectionTimer(handle);
    }

    /// Reserve one bidirectional stream without reading the shared socket.
    /// Null means the endpoint loop must drive peer credit or other transport
    /// progress before retrying.
    pub fn pollOpenStream(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!?u64 {
        return self.dispatcher.pollOpenStream(handle);
    }

    /// Reserve one unidirectional stream without reading the shared socket.
    /// Null means the endpoint loop must drive peer credit or other transport
    /// progress before retrying.
    pub fn pollOpenUnidirectionalStream(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!?u64 {
        return self.dispatcher.pollOpenUnidirectionalStream(handle);
    }

    pub fn pollOpenUniStream(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!?u64 {
        return self.pollOpenUnidirectionalStream(handle);
    }

    /// Poll one ready stream fairly without reading the shared socket. Any
    /// generated flow-control work is reflected in the aggregate timer heap.
    pub fn pollStream(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        out: []u8,
    ) Error!?quic.one_rtt.StreamRead {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        const result = established.connection.pollStream(out) catch |err| {
            self.dispatcher.refreshConnectionTimer(handle) catch {};
            return err;
        };
        try self.dispatcher.refreshConnectionTimer(handle);
        return result;
    }

    /// Targeted socket-free stream poll for protocols with an existing stream
    /// association.
    pub fn pollStreamId(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        stream_id: u62,
        out: []u8,
    ) Error!?quic.one_rtt.StreamRead {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        const result = established.connection.pollStreamId(
            stream_id,
            out,
        ) catch |err| {
            self.dispatcher.refreshConnectionTimer(handle) catch {};
            return err;
        };
        try self.dispatcher.refreshConnectionTimer(handle);
        return result;
    }

    pub fn removeConnection(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!bool {
        var removed = self.connections.fetchRemove(handle) orelse
            return false;
        defer {
            removed.value.deinit();
            self.allocator.destroy(removed.value);
        }
        if (!try self.dispatcher.unregisterConnection(handle)) {
            return error.UnknownConnectionHandle;
        }
        return true;
    }

    pub fn receive(
        self: *Server,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) Error!Event {
        while (true) {
            if (try self.receiveOnce(
                supported_versions,
                poll_interval,
            )) |event| return event;
        }
    }

    pub fn receiveOnce(
        self: *Server,
        supported_versions: []const u32,
        poll_interval: std.Io.Clock.Duration,
    ) Error!?Event {
        if (poll_interval.raw.nanoseconds <= 0) return error.Timeout;
        return self.receiveUntil(supported_versions, .{
            .duration = poll_interval,
        }) catch |err| switch (err) {
            error.Timeout => null,
            else => |other| return other,
        };
    }

    pub fn receiveWithTimeout(
        self: *Server,
        supported_versions: []const u32,
        timeout: std.Io.Duration,
    ) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(supported_versions, .fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveWithDeadline(
        self: *Server,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Event {
        const absolute = try deadline_policy.usableAwake(
            self.endpoint.io,
            deadline,
        );
        while (true) {
            const poll_deadline = if (self.hasActiveHandshakes())
                deadline_policy.earlier(
                    absolute,
                    .fromNow(self.endpoint.io, .{
                        .raw = self.options.handshake_poll_interval,
                        .clock = .awake,
                    }),
                ).?
            else
                absolute;
            if (self.receiveUntil(
                supported_versions,
                .{ .deadline = poll_deadline },
            ) catch |err| switch (err) {
                error.Timeout => {
                    if (absolute.durationFromNow(self.endpoint.io)
                        .raw.nanoseconds <= 0) return error.Timeout;
                    continue;
                },
                else => |other| return other,
            }) |event| return event;
        }
    }

    /// Receive and apply an established packet in caller-owned storage. The
    /// borrowed packet/frame view is valid only during `visitor`; after a
    /// successful callback the negotiated ACK policy is applied before the
    /// aggregate timer is refreshed. Unknown and handshake datagrams retain
    /// owning event variants because they can outlive this call.
    pub fn receiveVisiting(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        while (true) {
            if (try self.receiveVisitingOnce(
                supported_versions,
                storage,
                self.options.handshake_poll_interval,
                context,
                visitor,
            )) |event| return event;
        }
    }

    pub fn receiveVisitingOnce(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        poll_interval: std.Io.Duration,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!?VisitEvent {
        if (poll_interval.nanoseconds <= 0) return error.Timeout;
        const deadline = .fromNow(self.endpoint.io, .{
            .raw = poll_interval,
            .clock = .awake,
        });
        return self.receiveVisitingUntil(
            supported_versions,
            storage,
            deadline,
            context,
            visitor,
        ) catch |err| switch (err) {
            error.Timeout => null,
            else => |other| return other,
        };
    }

    pub fn receiveVisitingWithDeadline(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        const absolute = try deadline_policy.usableAwake(
            self.endpoint.io,
            deadline,
        );
        return self.receiveVisitingUntil(
            supported_versions,
            storage,
            absolute,
            context,
            visitor,
        );
    }

    /// Bounded multi-datagram counterpart to `receiveVisitingWithDeadline`.
    /// The visitor runs synchronously for each established packet before any
    /// borrowed receive storage can be reused. Returned events contain only
    /// stable summaries or explicitly owned exceptional datagrams.
    pub fn receiveManyVisitingTimeout(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        if (output.len == 0 or
            output.len > quic.runtime.max_receive_batch_messages)
        {
            return error.BufferTooShort;
        }
        return self.receiveManyVisitingUntil(
            supported_versions,
            storage,
            output,
            timeout.toTimestamp(self.endpoint.io),
            context,
            visitor,
        );
    }

    pub fn receiveManyVisitingWithDeadline(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        return self.receiveManyVisitingTimeout(
            supported_versions,
            storage,
            output,
            .{ .deadline = try deadline_policy.usableAwake(
                self.endpoint.io,
                deadline,
            ) },
            context,
            visitor,
        );
    }

    fn receiveManyVisitingUntil(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        caller_deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        while (true) {
            const receive_timeout: std.Io.Timeout = if (self.hasActiveHandshakes()) deadline: {
                if (self.pollCompletion()) |completion_value| {
                    var completion = completion_value;
                    output[0] = eventToVisit(try self.finishCompletion(
                        &completion,
                    ));
                    return 1;
                }
                _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
                break :deadline .{ .deadline = earlierByRemaining(
                    self.endpoint.io,
                    caller_deadline,
                    .fromNow(self.endpoint.io, .{
                        .raw = self.options.handshake_poll_interval,
                        .clock = .awake,
                    }),
                ) };
            } else if (caller_deadline) |deadline|
                .{ .deadline = deadline }
            else
                .none;
            const Adapter = struct {
                server: *Server,
                context: @TypeOf(context),

                fn visit(
                    adapter: *@This(),
                    packet: quic.endpoint_dispatcher.RoutedPacketView,
                ) (Error || callbackErrorSet(visitor))!void {
                    try visitor(adapter.context, packet);
                    const established = adapter.server.connection(
                        packet.connection_handle,
                    ) orelse return error.UnknownConnectionHandle;
                    _ = try established.connection.sendAckForPacketIfNeeded(
                        packet.packet.packet_number,
                        packet.packet.frames,
                    );
                }
            };
            var adapter = Adapter{ .server = self, .context = context };
            var dispatcher_events: [quic.runtime.max_receive_batch_messages]quic.endpoint_dispatcher.VisitEvent = undefined;
            const dispatcher_count = self.dispatcher
                .receiveManyVisitingTimeout(
                supported_versions,
                storage,
                dispatcher_events[0..output.len],
                receive_timeout,
                &adapter,
                Adapter.visit,
            ) catch |err| switch (err) {
                error.Timeout => {
                    if (caller_deadline) |deadline| {
                        if (deadline.durationFromNow(self.endpoint.io)
                            .raw.nanoseconds <= 0) return error.Timeout;
                    }
                    continue;
                },
                else => |other| return other,
            };
            defer for (dispatcher_events[0..dispatcher_count]) |*event| {
                event.deinit(self.allocator);
            };

            var count: usize = 0;
            errdefer for (output[0..count]) |*event| {
                event.deinit(self.allocator);
            };
            for (dispatcher_events[0..dispatcher_count]) |*event| {
                switch (event.*) {
                    .new_initial => {
                        const owned = visitEventToEvent(event);
                        var admission = owned;
                        defer admission.deinit(self.allocator);
                        self.admit(&admission) catch |err| switch (err) {
                            error.PendingHandshakeLimitReached => {
                                const rejected = admission;
                                admission = .consumed;
                                output[count] = .{ .unrouted = rejected };
                                count += 1;
                            },
                            else => |other| return other,
                        };
                    },
                    .packet => |packet| {
                        output[count] = .{ .packet = .{
                            .connection_handle = packet.connection_handle,
                            .connection_id_sequence = packet.connection_id_sequence,
                        } };
                        count += 1;
                    },
                    .timer => |timer| {
                        output[count] = .{ .timer = timer };
                        count += 1;
                    },
                    .unrouted => {
                        output[count] = .{
                            .unrouted = visitEventToEvent(event),
                        };
                        count += 1;
                    },
                    .consumed,
                    .pending_handshake,
                    .discarded_long_header,
                    => {},
                }
            }
            if (count != 0) return count;
        }
    }

    fn receiveVisitingUntil(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        absolute: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        while (true) {
            const poll_deadline = if (self.hasActiveHandshakes()) deadline: {
                if (self.pollCompletion()) |completion_value| {
                    var completion = completion_value;
                    const event = try self.finishCompletion(&completion);
                    return eventToVisit(event);
                }
                _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
                break :deadline deadline_policy.earlier(
                    absolute,
                    .fromNow(self.endpoint.io, .{
                        .raw = self.options.handshake_poll_interval,
                        .clock = .awake,
                    }),
                ).?;
            } else absolute;
            const Adapter = struct {
                server: *Server,
                context: @TypeOf(context),

                fn visit(
                    adapter: *@This(),
                    packet: quic.endpoint_dispatcher.RoutedPacketView,
                ) (Error || callbackErrorSet(visitor))!void {
                    try visitor(adapter.context, packet);
                    const established = adapter.server.connection(
                        packet.connection_handle,
                    ) orelse return error.UnknownConnectionHandle;
                    _ = try established.connection.sendAckForPacketIfNeeded(
                        packet.packet.packet_number,
                        packet.packet.frames,
                    );
                }
            };
            var adapter = Adapter{ .server = self, .context = context };
            var event = self.dispatcher.receiveVisitingTimeout(
                supported_versions,
                storage,
                .{ .deadline = poll_deadline },
                &adapter,
                Adapter.visit,
            ) catch |err| switch (err) {
                error.Timeout => {
                    if (absolute.durationFromNow(self.endpoint.io)
                        .raw.nanoseconds <= 0) return error.Timeout;
                    continue;
                },
                else => |other| return other,
            };
            switch (event) {
                .new_initial => {
                    const owned = visitEventToEvent(&event);
                    var admission = owned;
                    defer admission.deinit(self.allocator);
                    self.admit(&admission) catch |err| switch (err) {
                        error.PendingHandshakeLimitReached => {
                            const rejected = admission;
                            admission = .consumed;
                            return .{ .unrouted = rejected };
                        },
                        else => |other| return other,
                    };
                },
                .packet => |packet| return .{ .packet = .{
                    .connection_handle = packet.connection_handle,
                    .connection_id_sequence = packet.connection_id_sequence,
                } },
                .timer => |timer| return .{ .timer = timer },
                .unrouted => {
                    const owned = visitEventToEvent(&event);
                    return .{ .unrouted = owned };
                },
                .consumed, .pending_handshake, .discarded_long_header => {},
            }
        }
    }

    fn receiveUntil(
        self: *Server,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) Error!?Event {
        if (self.hasActiveHandshakes()) {
            if (self.pollCompletion()) |completion_value| {
                var completion = completion_value;
                const event = try self.finishCompletion(&completion);
                return event;
            }
            _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
        }
        var endpoint_event = try self.dispatcher.receiveTimeout(
            supported_versions,
            timeout,
        );
        var endpoint_owned = true;
        defer if (endpoint_owned) endpoint_event.deinit(self.allocator);
        switch (endpoint_event) {
            .new_initial => {
                self.admit(&endpoint_event) catch |err| switch (err) {
                    error.PendingHandshakeLimitReached => {
                        endpoint_owned = false;
                        return .{ .unrouted = endpoint_event };
                    },
                    else => |other| return other,
                };
                return null;
            },
            .packet => |packet| {
                endpoint_event = .consumed;
                endpoint_owned = false;
                return .{ .packet = packet };
            },
            .timer => |timer| return .{ .timer = timer },
            .unrouted => {
                endpoint_owned = false;
                return .{ .unrouted = endpoint_event };
            },
            .consumed, .pending_handshake, .discarded_long_header => return null,
        }
    }

    fn admit(
        self: *Server,
        event: *quic.endpoint_dispatcher.Event,
    ) Error!void {
        if (event.* != .new_initial) return error.InvalidPacket;
        const limit = if (self.options.max_connections == 0)
            self.options.max_pending_handshakes
        else
            self.options.max_connections;
        if (self.connections.count() +| self.active_workers.load(.acquire) >=
            limit) return error.PendingHandshakeLimitReached;

        var active = self.active_workers.load(.acquire);
        while (true) {
            if (active >= self.options.max_pending_handshakes) {
                return error.PendingHandshakeLimitReached;
            }
            if (self.active_workers.cmpxchgWeak(
                active,
                active + 1,
                .acq_rel,
                .acquire,
            )) |observed| {
                active = observed;
                continue;
            }
            break;
        }
        errdefer _ = self.active_workers.fetchSub(1, .acq_rel);

        const handle = self.reserveHandle();
        const initial = event.new_initial;
        const inbox = try self.dispatcher.admitPendingHandshake(
            handle,
            initial,
            self.options.max_pending_handshakes,
            self.options.inbox_capacity,
        );
        const admission = self.allocator.create(Admission) catch |err| {
            _ = self.dispatcher.unregisterPendingHandshake(handle) catch false;
            inbox.deinit();
            self.allocator.destroy(inbox);
            return err;
        };
        const connection_storage = self.allocator.create(
            quic.handshake.EstablishedConnection,
        ) catch |err| {
            self.allocator.destroy(admission);
            _ = self.dispatcher.unregisterPendingHandshake(handle) catch false;
            inbox.deinit();
            self.allocator.destroy(inbox);
            return err;
        };
        admission.* = .{
            .dispatcher = self.dispatcher,
            .handle = handle,
            .inbox = inbox,
            .connection = connection_storage,
            .initial = event.takeNewInitial().?,
            .server_connection_id = undefined,
            .deadline_ns = handshakeDeadlineNs(
                self.endpoint.io,
                self.options.handshake_timeout_ms,
                self.handshake_options.handshake_recovery.budgetMillis(),
            ),
        };
        @memcpy(
            &admission.server_connection_id,
            inbox.connectionIds()[1].slice(),
        );
        errdefer {
            admission.deinit();
            self.allocator.destroy(admission);
        }
        self.admissions_mutex.lockUncancelable(self.endpoint.io);
        self.admissions.put(
            self.allocator,
            handle,
            admission,
        ) catch |err| {
            self.admissions_mutex.unlock(self.endpoint.io);
            return err;
        };
        self.admissions_mutex.unlock(self.endpoint.io);
        errdefer {
            self.admissions_mutex.lockUncancelable(self.endpoint.io);
            _ = self.admissions.remove(handle);
            self.admissions_mutex.unlock(self.endpoint.io);
        }
        try self.workers.concurrent(
            self.endpoint.io,
            runWorker,
            .{ self.worker_context, admission },
        );
    }

    fn finishCompletion(
        self: *Server,
        completion: *Completion,
    ) Error!Event {
        errdefer completion.deinit();
        const handle = completion.handle;
        switch (completion.result) {
            .failure => |err| {
                completion.admission.deinit();
                self.allocator.destroy(completion.admission);
                completion.* = undefined;
                return .{ .handshake_failed = .{
                    .handle = handle,
                    .err = err,
                } };
            },
            .success => {
                try self.connections.ensureUnusedCapacity(self.allocator, 1);
                const owned = completion.admission.takeConnection();
                errdefer {
                    owned.deinit();
                    self.allocator.destroy(owned);
                }
                try self.dispatcher.promotePendingHandshake(
                    completion.admission.handle,
                    handle,
                    &owned.connection,
                );
                completion.admission.registered = false;
                completion.admission.deinit();
                self.allocator.destroy(completion.admission);
                self.connections.putAssumeCapacityNoClobber(handle, owned);
                completion.* = undefined;
                return .{ .connected = handle };
            },
        }
    }

    fn pollCompletion(self: *Server) ?Completion {
        var values: [1]Completion = undefined;
        const count = self.completed.get(
            self.endpoint.io,
            &values,
            0,
        ) catch return null;
        if (count == 0) return null;
        const previous = self.active_workers.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        self.admissions_mutex.lockUncancelable(self.endpoint.io);
        _ = self.admissions.remove(values[0].handle);
        self.admissions_mutex.unlock(self.endpoint.io);
        return values[0];
    }

    fn hasActiveHandshakes(self: *Server) bool {
        if (self.active_workers.load(.acquire) == 0) return false;
        if (comptime builtin.is_test) self.handshake_poll_count +|= 1;
        return true;
    }

    fn expireHandshakes(self: *Server, now_ns: u64) usize {
        var expired: [64]*Admission = undefined;
        var count: usize = 0;
        self.admissions_mutex.lockUncancelable(self.endpoint.io);
        var iterator = self.admissions.valueIterator();
        while (iterator.next()) |admission| {
            if (now_ns < admission.*.deadline_ns) continue;
            if (count == expired.len) break;
            expired[count] = admission.*;
            count += 1;
        }
        self.admissions_mutex.unlock(self.endpoint.io);
        for (expired[0..count]) |admission| admission.inbox.close();
        return count;
    }

    fn reserveHandle(
        self: *Server,
    ) quic.endpoint_dispatcher.ConnectionHandle {
        self.next_handle_mutex.lockUncancelable(self.endpoint.io);
        defer self.next_handle_mutex.unlock(self.endpoint.io);
        const handle = self.next_handle;
        self.next_handle +%= 1;
        if (self.next_handle == 0) self.next_handle = 1;
        return handle;
    }
};

fn eventToVisit(event: Event) VisitEvent {
    return switch (event) {
        .connected => |handle| .{ .connected = handle },
        .packet => unreachable,
        .timer => |timer| .{ .timer = timer },
        .handshake_failed => |failure| .{ .handshake_failed = failure },
        .unrouted => |unrouted| .{ .unrouted = unrouted },
    };
}

fn visitEventToEvent(event: *quic.endpoint_dispatcher.VisitEvent) quic.endpoint_dispatcher.Event {
    return switch (event.*) {
        .new_initial => |initial| blk: {
            event.* = .consumed;
            break :blk .{ .new_initial = initial };
        },
        .unrouted => |unrouted| blk: {
            event.* = .consumed;
            break :blk .{ .unrouted = unrouted };
        },
        else => unreachable,
    };
}

fn runWorker(
    context: *WorkerContext,
    admission: *Admission,
) std.Io.Cancelable!void {
    var options = context.options;
    options.local_connection_id = &admission.server_connection_id;
    const result: @FieldType(Completion, "result") = blk: {
        admission.connection.* = quic.handshake.acceptFromInitialSourceWithDeadline(
            context.endpoint,
            admission.source(),
            admission.takeInitial(),
            options,
            admission.deadline(),
        ) catch |err| {
            break :blk .{ .failure = err };
        };
        admission.connection_initialized = true;
        break :blk .success;
    };
    context.completed.putOneUncancelable(context.io, .{
        .handle = admission.handle,
        .admission = admission,
        .result = result,
    }) catch |err| switch (err) {
        error.Closed => unreachable,
    };
}

fn handshakeDeadlineNs(
    io: std.Io,
    configured_ms: u32,
    recovery_ms: u64,
) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    const now_ns = if (now <= 0)
        0
    else
        std.math.cast(u64, now) orelse std.math.maxInt(u64);
    const milliseconds = if (configured_ms != 0)
        @as(u64, configured_ms)
    else
        recovery_ms;
    return now_ns +| (std.math.mul(
        u64,
        milliseconds,
        std.time.ns_per_ms,
    ) catch std.math.maxInt(u64));
}

fn monotonicNowNs(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return std.math.cast(u64, now) orelse std.math.maxInt(u64);
}

fn earlierByRemaining(
    io: std.Io,
    first: ?std.Io.Clock.Timestamp,
    second: std.Io.Clock.Timestamp,
) std.Io.Clock.Timestamp {
    const first_value = first orelse return second;
    return if (first_value.durationFromNow(io).raw.nanoseconds <
        second.durationFromNow(io).raw.nanoseconds)
        first_value
    else
        second;
}

test "QUIC endpoint server skips handshake maintenance when idle" {
    var server: Server = undefined;
    server.active_workers = .init(0);
    server.handshake_poll_count = 0;

    try std.testing.expect(!server.hasActiveHandshakes());
    try std.testing.expectEqual(@as(usize, 0), server.handshake_poll_count);

    server.active_workers.store(1, .release);
    try std.testing.expect(server.hasActiveHandshakes());
    try std.testing.expectEqual(@as(usize, 1), server.handshake_poll_count);
}
