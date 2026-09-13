//! Event-driven raw QUIC server for many connections on one UDP endpoint.
//!
//! `Server` is the sole socket receive owner. It admits Initial packets into
//! bounded handshake inboxes, performs TLS handshakes concurrently, promotes
//! established connections into stable storage, routes 1-RTT packets by CID,
//! and services the aggregate connection timer schedule. Applications consume
//! returned packets and use `connection(handle)` with socket-free poll/send
//! operations before refreshing the connection timer.

const std = @import("std");
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

const Admission = struct {
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    handle: quic.endpoint_dispatcher.PendingHandshakeHandle,
    inbox: *quic.handshake_inbox.Inbox,
    initial: quic.runtime.OwnedBytes,
    server_connection_id: [
        quic.endpoint_dispatcher.default_server_connection_id_len
    ]u8,
    deadline_ns: u64,
    registered: bool = true,
    initial_owned: bool = true,

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

    fn deinit(self: *Admission) void {
        const allocator = self.inbox.allocator;
        if (self.registered) {
            _ = self.dispatcher.unregisterPendingHandshake(
                self.handle,
            ) catch false;
        }
        if (self.initial_owned) self.initial.deinit(allocator);
        self.inbox.deinit();
        allocator.destroy(self.inbox);
        self.* = undefined;
    }
};

const Completion = struct {
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    admission: *Admission,
    result: union(enum) {
        connection: quic.handshake.EstablishedConnection,
        failure: WorkerError,
    },

    fn deinit(self: *Completion) void {
        const allocator = self.admission.inbox.allocator;
        switch (self.result) {
            .connection => |*connection| connection.deinit(),
            .failure => {},
        }
        self.admission.deinit();
        allocator.destroy(self.admission);
        self.* = undefined;
    }
};

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
            const poll_deadline = deadline_policy.earlier(
                absolute,
                .fromNow(self.endpoint.io, .{
                    .raw = self.options.handshake_poll_interval,
                    .clock = .awake,
                }),
            ).?;
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

    fn receiveUntil(
        self: *Server,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) Error!?Event {
        if (self.pollCompletion()) |completion_value| {
            var completion = completion_value;
            const event = try self.finishCompletion(&completion);
            return event;
        }
        _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
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
        admission.* = .{
            .dispatcher = self.dispatcher,
            .handle = handle,
            .inbox = inbox,
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
        errdefer admission.deinit();
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
            .connection => |established| {
                try self.connections.ensureUnusedCapacity(self.allocator, 1);
                const owned = try self.allocator.create(
                    quic.handshake.EstablishedConnection,
                );
                owned.* = established;
                completion.result = .{ .failure = error.HandshakeReceiveFailed };
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

fn runWorker(
    context: *WorkerContext,
    admission: *Admission,
) std.Io.Cancelable!void {
    var options = context.options;
    options.local_connection_id = &admission.server_connection_id;
    const result: @FieldType(Completion, "result") = blk: {
        const established = quic.handshake.acceptFromInitialSourceWithDeadline(
            context.endpoint,
            admission.source(),
            admission.takeInitial(),
            options,
            admission.deadline(),
        ) catch |err| break :blk .{ .failure = err };
        break :blk .{ .connection = established };
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
