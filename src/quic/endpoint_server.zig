//! Event-driven raw QUIC server for many connections on one UDP endpoint.
//!
//! `Server` is the sole socket receive owner. It admits Initial packets into
//! bounded handshake inboxes, performs TLS handshakes concurrently, promotes
//! established connections into stable storage, routes 1-RTT packets by CID,
//! and services the aggregate connection timer schedule. Applications consume
//! returned packets and use `connection(handle)` with socket-free poll/send
//! operations before refreshing the connection timer.

const std = @import("std");
const secure_random = @import("../internal/secure_random.zig");
const builtin = @import("builtin");
const deadline_policy = @import("../internal/deadline.zig");
const quic = @import("mod.zig");
const closing_handshake = @import("handshake/closing.zig");
const owned_receive_race = @import("owned_receive_race.zig");

test {
    _ = @import("endpoint_server/tests.zig");
}

pub const Options = struct {
    /// Total reserved live-handshake plus closing slots. Unexpired closing
    /// routes are never evicted to admit a new handshake.
    closing_handshake_capacity: usize = closing_handshake.default_capacity,
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
    /// Endpoint-owned replay history installed automatically when Retry or
    /// NEW_TOKEN validation is configured without a caller-owned filter.
    /// Zero explicitly disables this convenience; an explicit filter in
    /// `ServerOptions` always wins and remains caller-owned.
    address_validation_replay_capacity: usize =
        quic.address_validation_token.default_replay_filter_entries,
    /// Stable endpoint secret for server connection-ID reset tokens. Null
    /// preserves the historical behavior of returning unknown short-header
    /// datagrams to the application without sending a stateless reset.
    stateless_reset_key: ?[quic.stateless_reset.static_key_len]u8 = null,
    /// Endpoint-wide minimum interval between automatic reset responses.
    /// Quinn uses the same 20 ms default to bound reflection work.
    stateless_reset_min_interval: std.Io.Duration = .fromMilliseconds(20),
    /// Keep the local CID pool filled to the peer's advertised active limit
    /// when a reset key is configured. One-shot sends retry on later endpoint
    /// packet/timer turns rather than blocking the sole receive owner.
    automatic_connection_id_replenishment: bool = true,
    /// Advertise an endpoint-owned preferred address with a fresh per-
    /// connection CID and derived reset token. Without `preferred_endpoint`,
    /// this must exactly match the primary endpoint's bound address.
    preferred_address: ?std.Io.net.IpAddress = null,
    /// Caller-owned UDP endpoint for a distinct preferred address. When set,
    /// `preferred_address` must be null or exactly match this endpoint. The
    /// server remains the sole receive owner for both sockets.
    preferred_endpoint: ?*quic.runtime.Endpoint = null,
    /// Optional second address carried in the same RFC preferred_address
    /// parameter. One of the two addresses must be the primary endpoint and
    /// `preferred_endpoint` supplies the other family.
    preferred_additional_address: ?std.Io.net.IpAddress = null,
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
    preferred_server_connection_id: [
        quic.endpoint_dispatcher.default_server_connection_id_len
    ]u8 = undefined,
    preferred_endpoints: PreferredEndpointSet = .{},
    version: quic.Version,
    deadline_ns: u64,
    registered: bool = true,
    initial_owned: bool = true,
    connection_initialized: bool = false,
    connection_owned: bool = true,
    closing_packet: ?closing_handshake.Packet = null,
    closing_lifetime_ns: u64,
    retain_closing: bool = false,

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
        if (self.registered and !(self.retain_closing and self.dispatcher.closePendingHandshake(self.handle, self.closing_packet, self.closing_lifetime_ns))) {
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

fn createAddressValidationReplayFilter(
    allocator: std.mem.Allocator,
    io: std.Io,
    capacity: usize,
) std.mem.Allocator.Error!*quic.address_validation_token.SharedReplayFilter {
    std.debug.assert(capacity != 0);
    const replay_filter = try allocator.create(
        quic.address_validation_token.SharedReplayFilter,
    );
    errdefer allocator.destroy(replay_filter);
    replay_filter.* = quic.address_validation_token.SharedReplayFilter.init(
        allocator,
        io,
        capacity,
    ) catch |err| switch (err) {
        error.InvalidCapacity, error.InvalidToken, error.TokenExpired, error.TokenNotYetValid, error.TokenReplay => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
    return replay_filter;
}

fn destroyAddressValidationReplayFilter(
    allocator: std.mem.Allocator,
    replay_filter: *quic.address_validation_token.SharedReplayFilter,
) void {
    replay_filter.deinit();
    allocator.destroy(replay_filter);
}

const WorkerContext = struct {
    endpoint: *quic.runtime.Endpoint,
    options: quic.handshake.ServerOptions,
    io: std.Io,
    completed: *std.Io.Queue(Completion),
};

const PendingEndpointDatagramView = struct {
    from: std.Io.net.IpAddress,
    received_on: *quic.runtime.Endpoint,
    len: usize,
    ecn: quic.packet_space.EcnCodepoint,
};

const PreferredEndpointSet = struct {
    ipv4: ?*quic.runtime.Endpoint = null,
    ipv6: ?*quic.runtime.Endpoint = null,
    secondary: ?*quic.runtime.Endpoint = null,

    fn present(self: PreferredEndpointSet) bool {
        return self.ipv4 != null or self.ipv6 != null;
    }
};

/// Shared-endpoint raw QUIC connection owner. Connection pointers remain
/// stable until `removeConnection` or `deinit`; callers must not move or free
/// them. All UDP receives must flow through this server.
pub const Server = struct {
    allocator: std.mem.Allocator,
    endpoint: *quic.runtime.Endpoint,
    dispatcher: *quic.endpoint_dispatcher.Dispatcher,
    options: Options,
    preferred_endpoints: PreferredEndpointSet = .{},
    handshake_options: quic.handshake.ServerOptions,
    owned_address_validation_replay_filter: ?*quic.address_validation_token.SharedReplayFilter = null,
    last_stateless_reset_ns: ?u64 = null,
    connection_id_replenishment_failures: u64 = 0,
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
    pending_multi_endpoint_datagram: ?quic.runtime.OwnedBytes = null,
    preferred_receive_storage: []u8 = &.{},
    pending_multi_endpoint_storage: []u8 = &.{},
    pending_multi_endpoint_view: ?PendingEndpointDatagramView = null,
    multi_endpoint_view_count: if (builtin.is_test) usize else void =
        if (builtin.is_test) 0 else {},
    multi_endpoint_owning_count: if (builtin.is_test) usize else void =
        if (builtin.is_test) 0 else {},

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        handshake_options: quic.handshake.ServerOptions,
        options: Options,
    ) Error!Server {
        if (options.closing_handshake_capacity == 0 or options.max_pending_handshakes == 0 or
            options.inbox_capacity == 0 or
            options.handshake_poll_interval.nanoseconds <= 0 or
            options.stateless_reset_min_interval.nanoseconds < 0)
        {
            return error.InvalidOptions;
        }
        var effective_handshake_options = handshake_options;
        if (handshake_options.local_transport_parameters
            .preferred_address != null)
        {
            // A fixed CID cannot be shared safely across accepted
            // connections. Use Options.preferred_address so this owner can
            // generate and route a unique sequence-1 CID for every admission.
            return error.InvalidOptions;
        }
        if (handshake_options.transport_parameters.len != 0) {
            const raw_transport_parameters =
                quic.parseTransportParametersTyped(
                    endpoint.allocator,
                    handshake_options.transport_parameters,
                    .server,
                ) catch return error.InvalidOptions;
            if (raw_transport_parameters.preferred_address != null) {
                // Raw bytes would preserve one caller-owned CID across every
                // admission and hide it from pending-handshake routing.
                return error.InvalidOptions;
            }
        }
        if (options.stateless_reset_key) |key| {
            if (handshake_options.transport_parameters.len != 0 or
                handshake_options.local_transport_parameters
                    .stateless_reset_token != null)
            {
                // The shared server chooses a fresh CID for every admission.
                // Raw or pre-filled Initial tokens cannot be proven to match
                // that not-yet-generated value, so fail before any worker runs.
                return error.InvalidOptions;
            }
            if (handshake_options.initial_one_rtt_config
                .local_stateless_reset_key) |configured|
            {
                if (!std.mem.eql(u8, &configured, &key)) {
                    return error.InvalidOptions;
                }
            }
            effective_handshake_options.initial_one_rtt_config
                .local_stateless_reset_key = key;
        } else if (handshake_options.initial_one_rtt_config
            .local_stateless_reset_key != null)
        {
            // Keep one authoritative endpoint-level opt-in. Advertising reset
            // tokens without installing the matching unknown-CID policy would
            // leave peers unable to use them after this process loses state.
            return error.InvalidOptions;
        }
        var owned_address_validation_replay_filter: ?*quic.address_validation_token.SharedReplayFilter = null;
        if (effective_handshake_options.address_validation_replay_filter ==
            null and options.address_validation_replay_capacity != 0 and
            (effective_handshake_options.retry != null or
                effective_handshake_options.address_validation_secrets.len != 0))
        {
            const replay_filter = try createAddressValidationReplayFilter(
                allocator,
                endpoint.io,
                options.address_validation_replay_capacity,
            );
            owned_address_validation_replay_filter = replay_filter;
            effective_handshake_options.address_validation_replay_filter =
                replay_filter;
        }
        errdefer if (owned_address_validation_replay_filter) |replay_filter| {
            destroyAddressValidationReplayFilter(allocator, replay_filter);
        };
        const preferred_endpoints = try resolvePreferredEndpoints(
            endpoint,
            options,
        );
        if (preferred_endpoints.present() and
            options.stateless_reset_key == null) return error.InvalidOptions;
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
        dispatcher.closing_handshake_capacity = options.closing_handshake_capacity;
        errdefer dispatcher.deinit();
        const preferred_receive_storage: []u8 = if (preferred_endpoints.secondary != null)
            try allocator.alloc(u8, endpoint.limits.max_datagram_size)
        else
            @constCast(&.{});
        errdefer if (preferred_receive_storage.len != 0) {
            allocator.free(preferred_receive_storage);
        };
        const pending_multi_endpoint_storage: []u8 = if (preferred_endpoints.secondary != null)
            try allocator.alloc(u8, endpoint.limits.max_datagram_size)
        else
            @constCast(&.{});
        errdefer if (pending_multi_endpoint_storage.len != 0) {
            allocator.free(pending_multi_endpoint_storage);
        };
        var effective_options = options;
        effective_options.preferred_endpoint = preferred_endpoints.secondary;
        effective_options.preferred_address = if (preferred_endpoints.secondary) |secondary|
            secondary.address()
        else if (preferred_endpoints.ipv4) |ipv4|
            ipv4.address()
        else if (preferred_endpoints.ipv6) |ipv6|
            ipv6.address()
        else
            null;
        const server = Server{
            .allocator = allocator,
            .endpoint = endpoint,
            .dispatcher = dispatcher,
            .options = effective_options,
            .preferred_endpoints = preferred_endpoints,
            .handshake_options = effective_handshake_options,
            .owned_address_validation_replay_filter = owned_address_validation_replay_filter,
            .worker_context = worker_context,
            .completed_storage = completed_storage,
            .completed = completed,
            .preferred_receive_storage = preferred_receive_storage,
            .pending_multi_endpoint_storage = pending_multi_endpoint_storage,
        };
        worker_context.* = .{
            .endpoint = endpoint,
            .options = effective_handshake_options,
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
        if (self.pending_multi_endpoint_datagram) |*datagram| {
            datagram.deinit((datagram.received_on orelse self.endpoint).allocator);
        }
        if (self.preferred_receive_storage.len != 0) {
            self.allocator.free(self.preferred_receive_storage);
        }
        if (self.pending_multi_endpoint_storage.len != 0) {
            self.allocator.free(self.pending_multi_endpoint_storage);
        }
        self.dispatcher.deinit();
        self.allocator.destroy(self.dispatcher);
        self.allocator.destroy(self.worker_context);
        if (self.owned_address_validation_replay_filter) |replay_filter| {
            destroyAddressValidationReplayFilter(
                self.allocator,
                replay_filter,
            );
        }
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

    /// Whether this server supplied the default process-local address-token
    /// replay history rather than borrowing an explicit caller-owned filter.
    pub fn ownsAddressValidationReplayFilter(self: *const Server) bool {
        return self.owned_address_validation_replay_filter != null;
    }

    /// Current authenticated Retry/NEW_TOKEN fingerprints retained by the
    /// effective replay filter, whether endpoint- or caller-owned.
    pub fn addressValidationReplayEntryCount(self: *Server) usize {
        const replay_filter = self.handshake_options
            .address_validation_replay_filter orelse return 0;
        return replay_filter.entryCount();
    }

    /// Number of established connection-ID routes retained by the endpoint.
    /// Resource monitors can pair this with `connectionCount` after removals.
    pub fn connectionRouteCount(self: *const Server) usize {
        return self.dispatcher.routeCount();
    }

    /// Number of in-progress handshake route sets retained by the endpoint.
    pub fn pendingHandshakeRouteCount(self: *const Server) usize {
        return self.dispatcher.pendingHandshakeCount();
    }

    pub fn connectionIdReplenishmentFailures(self: *const Server) u64 {
        return self.connection_id_replenishment_failures;
    }

    pub fn connection(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) ?*quic.handshake.EstablishedConnection {
        return self.connections.get(handle);
    }

    /// Adopt an already-established connection into this event loop. The
    /// server takes ownership of `established` and returns the handle used by
    /// `pollStream`, `streamSendCredit`, and `sendBatch`. This is the entry
    /// point for callers that complete `handshake.connect` or
    /// `handshake.accept` before starting the loop.
    pub fn adoptConnection(
        self: *Server,
        established: *quic.handshake.EstablishedConnection,
    ) Error!quic.endpoint_dispatcher.ConnectionHandle {
        const handle = self.reserveHandle();
        try self.dispatcher.registerConnection(handle, &established.connection);
        errdefer _ = self.dispatcher.unregisterConnection(handle) catch false;
        try self.connections.put(self.allocator, handle, established);
        return handle;
    }

    pub fn refreshConnectionTimer(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!void {
        try self.dispatcher.refreshConnectionTimer(handle);
    }

    /// Snapshot the immediately usable STREAM send credit without reading the
    /// shared socket or mutating connection state. Nonblocking endpoint loops
    /// can use this to submit a positive flow-control tail instead of retrying
    /// a larger transactional frame until another packet happens to arrive.
    pub fn streamSendCredit(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        stream_id: u64,
    ) Error!quic.one_rtt.SendCredit {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        return established.connection.streamSendCredit(stream_id);
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

    /// Submit one nonblocking multi-packet batch. Each inner slice becomes one
    /// QUIC packet, and the endpoint backend may hand the whole batch to the
    /// socket in one GSO/sendmmsg call. The endpoint timer schedule is
    /// refreshed once per batch instead of once per packet, so high-rate
    /// senders amortize dispatcher bookkeeping.
    pub fn sendBatch(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        packets: []const []const quic.Frame,
    ) Error!quic.one_rtt.ConnectionBatchSendResult {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        const result = established.connection.sendManyProgress(
            packets,
        ) catch |err| {
            self.dispatcher.refreshConnectionTimer(handle) catch {};
            return err;
        };
        try self.dispatcher.refreshConnectionTimer(handle);
        return result;
    }

    /// Monotonic nanosecond deadline published by the most recent
    /// pacing-limited send. Null when the connection is not pacing-blocked.
    pub fn pendingPacingDeadline(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!?u64 {
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        return established.connection.pendingPacingDeadline();
    }

    /// Issue and route another local CID whose reset token is derived from the
    /// same endpoint key used by automatic unknown-CID responses.
    pub fn sendNewConnectionId(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        connection_id: []const u8,
    ) Error!void {
        if (self.options.stateless_reset_key == null) {
            return error.InvalidConnectionId;
        }
        if (connection_id.len != quic.endpoint_dispatcher
            .default_server_connection_id_len)
        {
            return error.InvalidConnectionId;
        }
        try self.dispatcher.sendNewConnectionIdWithDerivedToken(
            handle,
            connection_id,
        );
    }

    /// Atomically advertise a derived-token CID and ask the peer to retire
    /// every lower sequence. Old routes remain valid until the peer confirms
    /// each retirement with RETIRE_CONNECTION_ID.
    pub fn sendNewConnectionIdRetiringPriorTo(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        connection_id: []const u8,
        retire_prior_to: u64,
    ) Error!void {
        if (self.options.stateless_reset_key == null) {
            return error.InvalidConnectionId;
        }
        if (connection_id.len != quic.endpoint_dispatcher
            .default_server_connection_id_len)
        {
            return error.InvalidConnectionId;
        }
        try self.dispatcher
            .sendNewConnectionIdWithDerivedTokenRetiringPriorTo(
            handle,
            connection_id,
            retire_prior_to,
        );
    }

    /// Best-effort nonblocking CID pool maintenance for externally scheduled
    /// endpoint loops. Returns the number of newly advertised identifiers.
    pub fn replenishConnectionIds(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) Error!usize {
        if (self.options.stateless_reset_key == null or
            !self.options.automatic_connection_id_replenishment) return 0;
        const established = self.connection(handle) orelse
            return error.UnknownConnectionHandle;
        const current = established.connection.localConnectionIdCount();
        const target = established.connection.localConnectionIdTarget();
        if (current >= target) return 0;
        const needed = target - current;
        var connection_id_storage: [quic.connection_id.max_pool_size][
            quic.endpoint_dispatcher.default_server_connection_id_len
        ]u8 = undefined;
        var connection_ids: [quic.connection_id.max_pool_size][]const u8 =
            undefined;
        var attempts: usize = 0;
        while (true) {
            if (attempts == quic.connection_id.max_pool_size * 2) {
                return error.DuplicateConnectionId;
            }
            attempts += 1;
            for (connection_id_storage[0..needed], 0..) |*connection_id, index| {
                try secure_random.fill(self.endpoint.io, connection_id);
                connection_ids[index] = connection_id;
            }
            self.dispatcher.trySendNewConnectionIdsWithDerivedTokens(
                handle,
                connection_ids[0..needed],
            ) catch |err| switch (err) {
                error.DuplicateConnectionId => continue,
                error.PacingLimited,
                error.CongestionLimited,
                error.AntiAmplificationLimited,
                error.FlowControlBlocked,
                error.ConnectionClosed,
                => return 0,
                else => |other| return other,
            };
            return needed;
        }
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
        const deadline = std.Io.Clock.Timestamp.fromNow(self.endpoint.io, .{
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

    /// Relative-timeout counterpart to `receiveVisitingWithDeadline`. A
    /// non-positive duration returns `Timeout` before any receive attempt.
    pub fn receiveVisitingWithTimeout(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        timeout: std.Io.Duration,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveVisitingWithDeadline(
            supported_versions,
            storage,
            .fromNow(self.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            visitor,
        );
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
        const deadline = try deadline_policy.fromIoTimeout(self.endpoint.io, timeout);
        if (output.len == 0 or
            output.len > quic.runtime.max_receive_batch_messages)
        {
            return error.BufferTooShort;
        }
        if (self.preferred_endpoints.secondary != null) {
            const required_storage = std.math.mul(
                usize,
                output.len,
                self.endpoint.limits.max_datagram_size,
            ) catch return error.BufferTooShort;
            if (storage.len < required_storage) return error.BufferTooShort;
            return self.receiveManyVisitingMultiEndpoint(
                supported_versions,
                storage,
                output,
                if (deadline) |until| .{ .deadline = until } else .none,
                context,
                visitor,
            );
        }
        return self.receiveManyVisitingUntil(
            supported_versions,
            storage,
            output,
            deadline,
            context,
            visitor,
        );
    }

    /// Relative-timeout counterpart to `receiveManyVisitingWithDeadline`. A
    /// non-positive duration returns `Timeout` before any receive attempt or
    /// buffer validation.
    pub fn receiveManyVisitingWithTimeout(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        timeout: std.Io.Duration,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveManyVisitingWithDeadline(
            supported_versions,
            storage,
            output,
            .fromNow(self.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
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
                    if (self.pending_multi_endpoint_view != null or
                        self.pending_multi_endpoint_datagram != null)
                    {
                        continue;
                    }
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
                        self.maintainConnectionIds(packet.connection_handle);
                        output[count] = .{ .packet = .{
                            .connection_handle = packet.connection_handle,
                            .connection_id_sequence = packet.connection_id_sequence,
                        } };
                        count += 1;
                    },
                    .timer => |timer| {
                        self.maintainConnectionIds(timer.connection_handle);
                        output[count] = .{ .timer = timer };
                        count += 1;
                    },
                    .unrouted => {
                        if (try self.handleUnrouted(&event.unrouted)) continue;
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

    fn receiveManyVisitingMultiEndpoint(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        var count: usize = 0;
        errdefer for (output[0..count]) |*event| {
            event.deinit(self.allocator);
        };
        const first_timeout = timeout.toDeadline(self.endpoint.io);
        while (count < output.len) {
            const event_storage = storage[count * self.endpoint.limits.max_datagram_size ..];
            output[count] = self.receiveVisitingMultiEndpoint(
                supported_versions,
                event_storage,
                if (count == 0) first_timeout else .{ .duration = .{
                    .clock = .awake,
                    .raw = .zero,
                } },
                context,
                visitor,
            ) catch |err| switch (err) {
                error.Timeout => if (count != 0) return count else return err,
                else => |other| return other,
            };
            count += 1;
        }
        return count;
    }

    fn receiveVisitingUntil(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        absolute: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        if (self.preferred_endpoints.secondary != null) {
            return self.receiveVisitingMultiEndpoint(
                supported_versions,
                storage,
                .{ .deadline = absolute },
                context,
                visitor,
            );
        }
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
                .packet => |packet| {
                    self.maintainConnectionIds(packet.connection_handle);
                    return .{ .packet = .{
                        .connection_handle = packet.connection_handle,
                        .connection_id_sequence = packet.connection_id_sequence,
                    } };
                },
                .timer => |timer| {
                    self.maintainConnectionIds(timer.connection_handle);
                    return .{ .timer = timer };
                },
                .unrouted => {
                    const handled = self.handleUnrouted(
                        &event.unrouted,
                    ) catch |err| {
                        event.deinit(self.allocator);
                        return err;
                    };
                    if (handled) {
                        event.deinit(self.allocator);
                        continue;
                    }
                    const owned = visitEventToEvent(&event);
                    return .{ .unrouted = owned };
                },
                .consumed, .pending_handshake, .discarded_long_header => {},
            }
        }
    }

    fn receiveVisitingMultiEndpoint(
        self: *Server,
        supported_versions: []const u32,
        storage: []u8,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        const caller_deadline = timeout.toTimestamp(self.endpoint.io);
        while (true) {
            const active_handshakes = self.hasActiveHandshakes();
            if (active_handshakes) {
                if (self.pollCompletion()) |completion_value| {
                    var completion = completion_value;
                    return eventToVisit(try self.finishCompletion(
                        &completion,
                    ));
                }
                _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
            }
            if (try self.dispatcher.poll()) |dispatcher_event_value| {
                var dispatcher_event = dispatcher_event_value;
                defer dispatcher_event.deinit(self.allocator);
                if (try self.finishDispatcherEvent(
                    &dispatcher_event,
                )) |event| {
                    return try self.visitOwnedServerEvent(
                        event,
                        context,
                        visitor,
                    );
                }
                continue;
            }
            const preferred = self.preferred_endpoints.secondary orelse
                unreachable;
            const receive_timeout = multiEndpointReceiveTimeout(
                self.endpoint.io,
                timeout,
                self.dispatcher.nextTimerDeadline(),
                if (active_handshakes)
                    self.options.handshake_poll_interval
                else
                    null,
            );
            const datagram = receiveViewFromEitherEndpoint(
                self,
                preferred,
                storage,
                receive_timeout,
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
            if (comptime builtin.is_test) {
                self.multi_endpoint_view_count +|= 1;
            }
            if (datagram.received_on != self.endpoint and
                datagram.bytes.len != 0 and
                (datagram.bytes[0] & 0x80) != 0)
            {
                continue;
            }
            if (try datagram.received_on.?
                .sendVersionNegotiationIfUnsupported(
                datagram.from,
                datagram.bytes,
                supported_versions,
            )) continue;

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
            var event = try self.dispatcher.dispatchVisitingDatagram(
                datagram,
                &adapter,
                Adapter.visit,
            );
            defer event.deinit(self.allocator);
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
                .packet => |packet| {
                    self.maintainConnectionIds(packet.connection_handle);
                    return .{ .packet = .{
                        .connection_handle = packet.connection_handle,
                        .connection_id_sequence = packet.connection_id_sequence,
                    } };
                },
                .timer => |timer| {
                    self.maintainConnectionIds(timer.connection_handle);
                    return .{ .timer = timer };
                },
                .unrouted => {
                    if (try self.handleUnrouted(&event.unrouted)) continue;
                    return .{ .unrouted = visitEventToEvent(&event) };
                },
                .consumed, .pending_handshake, .discarded_long_header => {},
            }
        }
    }

    fn finishDispatcherEvent(
        self: *Server,
        endpoint_event: *quic.endpoint_dispatcher.Event,
    ) Error!?Event {
        switch (endpoint_event.*) {
            .new_initial => {
                self.admit(endpoint_event) catch |err| switch (err) {
                    error.PendingHandshakeLimitReached => {
                        const rejected = endpoint_event.*;
                        endpoint_event.* = .consumed;
                        return .{ .unrouted = rejected };
                    },
                    else => |other| return other,
                };
                return null;
            },
            .packet => |packet| {
                self.maintainConnectionIds(packet.connection_handle);
                const result = Event{ .packet = packet };
                endpoint_event.* = .consumed;
                return result;
            },
            .timer => |timer| {
                self.maintainConnectionIds(timer.connection_handle);
                return .{ .timer = timer };
            },
            .unrouted => {
                if (try self.handleUnrouted(&endpoint_event.unrouted)) {
                    return null;
                }
                const result = Event{ .unrouted = endpoint_event.* };
                endpoint_event.* = .consumed;
                return result;
            },
            .consumed, .pending_handshake, .discarded_long_header => return null,
        }
    }

    fn visitOwnedServerEvent(
        self: *Server,
        event_value: Event,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        var event = event_value;
        var owns_event = true;
        defer if (owns_event) event.deinit(self.allocator);
        return switch (event) {
            .packet => |*packet| blk: {
                try visitor(context, .{
                    .connection_handle = packet.connection_handle,
                    .connection_id_sequence = packet.connection_id_sequence,
                    .packet = .{
                        .from = packet.packet.from,
                        .packet_number = packet.packet.packet.packet_number,
                        .frames = packet.packet.frames,
                        .peer_initiated_key_update = packet.packet.peer_initiated_key_update,
                    },
                });
                _ = try self.acknowledgePacketIfNeeded(packet);
                break :blk .{ .packet = .{
                    .connection_handle = packet.connection_handle,
                    .connection_id_sequence = packet.connection_id_sequence,
                } };
            },
            .connected => |handle| .{ .connected = handle },
            .timer => |timer| .{ .timer = timer },
            .handshake_failed => |failure| .{ .handshake_failed = failure },
            .unrouted => |unrouted| blk: {
                owns_event = false;
                break :blk .{ .unrouted = unrouted };
            },
        };
    }

    fn receiveUntil(
        self: *Server,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) Error!?Event {
        const active_handshakes = self.hasActiveHandshakes();
        if (active_handshakes) {
            if (self.pollCompletion()) |completion_value| {
                var completion = completion_value;
                const event = try self.finishCompletion(&completion);
                return event;
            }
            _ = self.expireHandshakes(monotonicNowNs(self.endpoint.io));
        }
        var endpoint_event = if (self.preferred_endpoints.secondary) |preferred| blk: {
            if (comptime builtin.is_test) {
                self.multi_endpoint_owning_count +|= 1;
            }
            if (try self.dispatcher.poll()) |event| break :blk event;
            var datagram = receiveFromEitherEndpoint(
                self,
                preferred,
                multiEndpointReceiveTimeout(
                    self.endpoint.io,
                    timeout,
                    self.dispatcher.nextTimerDeadline(),
                    if (active_handshakes)
                        self.options.handshake_poll_interval
                    else
                        null,
                ),
            ) catch |err| switch (err) {
                error.Timeout => return null,
                else => |other| return other,
            };
            if (datagram.received_on != self.endpoint) {
                const received_on = datagram.received_on.?;
                const bytes = self.allocator.dupe(
                    u8,
                    datagram.bytes,
                ) catch |err| {
                    datagram.deinit(received_on.allocator);
                    return err;
                };
                const from = datagram.from;
                const ecn = datagram.ecn;
                datagram.deinit(received_on.allocator);
                datagram = .{
                    .from = from,
                    .received_on = received_on,
                    .bytes = bytes,
                    .ecn = ecn,
                };
            }
            if (datagram.received_on != self.endpoint and
                datagram.bytes.len != 0 and
                (datagram.bytes[0] & 0x80) != 0)
            {
                // Handshake packet-number spaces remain owned by the primary
                // endpoint. The advertised address becomes usable only after
                // the client has authenticated its transport parameters.
                datagram.deinit(self.allocator);
                return null;
            }
            if (try datagram.received_on.?
                .sendVersionNegotiationIfUnsupported(
                datagram.from,
                datagram.bytes,
                supported_versions,
            )) {
                datagram.deinit(self.allocator);
                return null;
            }
            break :blk try self.dispatcher.dispatch(datagram);
        } else try self.dispatcher.receiveTimeout(
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
                self.maintainConnectionIds(packet.connection_handle);
                endpoint_event = .consumed;
                endpoint_owned = false;
                return .{ .packet = packet };
            },
            .timer => |timer| {
                self.maintainConnectionIds(timer.connection_handle);
                return .{ .timer = timer };
            },
            .unrouted => {
                if (try self.handleUnrouted(&endpoint_event.unrouted)) {
                    return null;
                }
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
        const has_preferred_address = self.preferred_endpoints.present();
        const inbox = try self.dispatcher
            .admitPendingHandshakeWithServerConnectionIds(
            handle,
            initial,
            self.options.max_pending_handshakes,
            self.options.inbox_capacity,
            if (has_preferred_address) 2 else 1,
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
            .preferred_endpoints = self.preferred_endpoints,
            .version = @enumFromInt(initial.version),
            .closing_lifetime_ns = closing_handshake.lifetimeNs(self.handshake_options.handshake_recovery.initial_pto_ms),
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
        if (has_preferred_address) {
            @memcpy(
                &admission.preferred_server_connection_id,
                inbox.connectionIds()[2].slice(),
            );
        }
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

    fn handleUnrouted(
        self: *Server,
        unrouted: *const quic.endpoint_dispatcher.UnroutedDatagram,
    ) Error!bool {
        const key = self.options.stateless_reset_key orelse return false;
        if (unrouted.kind != .unknown_short_header) return false;

        const bytes = unrouted.datagram.bytes;
        const cid_len = quic.endpoint_dispatcher
            .default_server_connection_id_len;
        // A 1-RTT packet needs one header byte, the endpoint's fixed-length
        // CID, at least one packet-number and payload byte, and a 16-byte AEAD
        // tag. RFC 9000 requires undersized packets to be discarded.
        if (bytes.len < cid_len + 19 or quic.stateless_reset.responseLen(
            bytes,
            self.endpoint.limits.max_datagram_size,
        ) == null) return true;

        const now_ns = monotonicNowNs(self.endpoint.io);
        if (statelessResetRateLimited(
            self.last_stateless_reset_ns,
            now_ns,
            statelessResetIntervalNs(
                self.options.stateless_reset_min_interval,
            ),
        )) return true;

        const endpoint = unrouted.datagram.received_on orelse self.endpoint;
        const sent = try endpoint.sendStatelessResetForConnectionId(
            unrouted.datagram.from,
            bytes,
            key,
            bytes[1 .. 1 + cid_len],
        );
        if (sent) self.last_stateless_reset_ns = now_ns;
        return true;
    }

    fn finishCompletion(
        self: *Server,
        completion: *Completion,
    ) Error!Event {
        errdefer completion.deinit();
        const handle = completion.handle;
        switch (completion.result) {
            .failure => |err| {
                completion.admission.retain_closing = completion.admission.closing_packet != null or err == error.ConnectionClosed;
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
                if (self.preferred_endpoints.secondary) |preferred_endpoint| {
                    try owned.connection.registerLocalPreferredEndpoint(
                        preferred_endpoint,
                    );
                }
                completion.admission.registered = false;
                completion.admission.deinit();
                self.allocator.destroy(completion.admission);
                self.connections.putAssumeCapacityNoClobber(handle, owned);
                self.maintainConnectionIds(handle);
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

    fn maintainConnectionIds(
        self: *Server,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) void {
        _ = self.replenishConnectionIds(handle) catch {
            self.connection_id_replenishment_failures +|= 1;
        };
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
    options.version = admission.version;
    if (admission.preferred_endpoints.present()) {
        const key = options.initial_one_rtt_config
            .local_stateless_reset_key orelse unreachable;
        options.local_transport_parameters.preferred_address =
            preferredAddressForEndpoints(
                admission.preferred_endpoints,
                &admission.preferred_server_connection_id,
                quic.stateless_reset.tokenForConnectionId(
                    key,
                    &admission.preferred_server_connection_id,
                ),
            );
    }
    options.failed_close_out = &admission.closing_packet;
    options.failed_close_lifetime_out = &admission.closing_lifetime_ns;
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

fn preferredAddressForEndpoints(
    endpoints: PreferredEndpointSet,
    connection_id: []const u8,
    token: [quic.stateless_reset.token_len]u8,
) quic.PreferredAddress {
    var preferred = quic.PreferredAddress{
        .connection_id = connection_id,
        .stateless_reset_token = token,
    };
    if (endpoints.ipv4) |endpoint| {
        preferred.ipv4_address = endpoint.address().ip4.bytes;
        preferred.ipv4_port = endpoint.address().ip4.port;
    }
    if (endpoints.ipv6) |endpoint| {
        preferred.ipv6_address = endpoint.address().ip6.bytes;
        preferred.ipv6_port = endpoint.address().ip6.port;
    }
    return preferred;
}

fn resolvePreferredEndpoints(
    primary: *quic.runtime.Endpoint,
    options: Options,
) error{InvalidOptions}!PreferredEndpointSet {
    var result = PreferredEndpointSet{};
    if (options.preferred_endpoint) |preferred| {
        if (preferred == primary) return error.InvalidOptions;
        if (options.preferred_address) |configured| {
            if (!configured.eql(&preferred.address())) {
                return error.InvalidOptions;
            }
        }
        switch (preferred.address()) {
            .ip4 => result.ipv4 = preferred,
            .ip6 => result.ipv6 = preferred,
        }
    } else if (options.preferred_address) |address| {
        if (!address.eql(&primary.address())) return error.InvalidOptions;
        switch (address) {
            .ip4 => result.ipv4 = primary,
            .ip6 => result.ipv6 = primary,
        }
    }
    if (options.preferred_additional_address) |additional| {
        if (!additional.eql(&primary.address()) or
            options.preferred_endpoint == null or
            options.preferred_address != null) return error.InvalidOptions;
        switch (additional) {
            .ip4 => {
                if (result.ipv4 != null) return error.InvalidOptions;
                result.ipv4 = primary;
            },
            .ip6 => {
                if (result.ipv6 != null) return error.InvalidOptions;
                result.ipv6 = primary;
            },
        }
    }
    for ([_]?*quic.runtime.Endpoint{ result.ipv4, result.ipv6 }) |candidate| {
        const endpoint = candidate orelse continue;
        if (!preferredAddressIsUsable(endpoint.address()) or
            endpoint.io.userdata != primary.io.userdata or
            endpoint.io.vtable != primary.io.vtable or
            endpoint.limits.max_datagram_size !=
                primary.limits.max_datagram_size or
            (endpoint != primary and endpoint.groReceiveEnabled()))
        {
            return error.InvalidOptions;
        }
    }
    if (result.ipv4) |endpoint| {
        if (endpoint.address() != .ip4) return error.InvalidOptions;
    }
    if (result.ipv6) |endpoint| {
        if (endpoint.address() != .ip6) return error.InvalidOptions;
    }
    const ipv4_secondary = result.ipv4 != null and result.ipv4 != primary;
    const ipv6_secondary = result.ipv6 != null and result.ipv6 != primary;
    if (ipv4_secondary and ipv6_secondary) return error.InvalidOptions;
    result.secondary = if (ipv4_secondary)
        result.ipv4
    else if (ipv6_secondary)
        result.ipv6
    else
        null;
    return result;
}

pub const testing = if (builtin.is_test) struct {
    pub fn preferredAddressForOptions(
        primary: *quic.runtime.Endpoint,
        options: Options,
        connection_id: []const u8,
        token: [quic.stateless_reset.token_len]u8,
    ) error{InvalidOptions}!quic.PreferredAddress {
        const endpoints = try @import("endpoint_server.zig")
            .resolvePreferredEndpoints(
            primary,
            options,
        );
        return @import("endpoint_server.zig").preferredAddressForEndpoints(
            endpoints,
            connection_id,
            token,
        );
    }
} else struct {};

fn preferredAddressIsUsable(address: std.Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |ip4| ip4.port != 0 and
            !std.mem.eql(u8, &ip4.bytes, &([_]u8{0} ** 4)),
        .ip6 => |ip6| ip6.port != 0 and
            !std.mem.eql(u8, &ip6.bytes, &([_]u8{0} ** 16)),
    };
}

fn receiveFromEitherEndpoint(
    server: *Server,
    preferred: *quic.runtime.Endpoint,
    timeout: std.Io.Timeout,
) quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes {
    if (server.pending_multi_endpoint_view) |pending| {
        server.pending_multi_endpoint_view = null;
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = try pending.received_on.allocator.dupe(
                u8,
                server.pending_multi_endpoint_storage[0..pending.len],
            ),
            .ecn = pending.ecn,
        };
    }
    return owned_receive_race.receive(
        &server.pending_multi_endpoint_datagram,
        server.endpoint.io,
        server.endpoint,
        preferred,
        timeout,
    );
}

fn receiveViewFromEitherEndpoint(
    server: *Server,
    preferred: *quic.runtime.Endpoint,
    primary_storage: []u8,
    timeout: std.Io.Timeout,
) quic.runtime.ReceiveTimeoutError!quic.runtime.ReceivedBytesView {
    if (primary_storage.len == 0) return error.BufferTooShort;
    if (server.pending_multi_endpoint_view) |pending| {
        server.pending_multi_endpoint_view = null;
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = server.pending_multi_endpoint_storage[0..pending.len],
            .ecn = pending.ecn,
        };
    }
    if (server.pending_multi_endpoint_datagram) |pending_value| {
        var pending = pending_value;
        server.pending_multi_endpoint_datagram = null;
        defer pending.deinit(
            (pending.received_on orelse server.endpoint).allocator,
        );
        const storage = if (pending.received_on == preferred)
            server.preferred_receive_storage
        else
            primary_storage;
        if (pending.bytes.len > storage.len) return error.BufferTooShort;
        @memcpy(storage[0..pending.bytes.len], pending.bytes);
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = storage[0..pending.bytes.len],
            .ecn = pending.ecn,
        };
    }

    const primary = server.endpoint;
    const bounded = timeout.toDeadline(primary.io);
    const ReceiveResult = quic.runtime.ReceiveTimeoutError!quic.runtime.ReceivedBytesView;
    const Wake = union(enum) {
        primary: ReceiveResult,
        preferred: ReceiveResult,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(primary.io, &wake_storage);
    select.async(
        .primary,
        receiveEndpointDatagramInto,
        .{ primary, primary_storage, bounded },
    );
    select.async(
        .preferred,
        receiveEndpointDatagramInto,
        .{
            preferred,
            server.preferred_receive_storage[0..@min(
                primary_storage.len,
                server.preferred_receive_storage.len,
            )],
            bounded,
        },
    );
    const first = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    while (select.cancel()) |wake| switch (wake) {
        .primary, .preferred => |result| if (result) |view| {
            if (server.pending_multi_endpoint_view == null) {
                std.debug.assert(
                    view.bytes.len <=
                        server.pending_multi_endpoint_storage.len,
                );
                @memcpy(
                    server.pending_multi_endpoint_storage[0..view.bytes.len],
                    view.bytes,
                );
                server.pending_multi_endpoint_view = .{
                    .from = view.from,
                    .received_on = view.received_on orelse primary,
                    .len = view.bytes.len,
                    .ecn = view.ecn,
                };
            }
        } else |_| {},
    };
    return switch (first) {
        .primary => |result| try result,
        .preferred => |result| try result,
    };
}

fn receiveEndpointDatagramInto(
    endpoint: *quic.runtime.Endpoint,
    storage: []u8,
    timeout: std.Io.Timeout,
) quic.runtime.ReceiveTimeoutError!quic.runtime.ReceivedBytesView {
    return endpoint.receiveBytesIntoTimeout(storage, timeout);
}

fn multiEndpointReceiveTimeout(
    io: std.Io,
    caller: std.Io.Timeout,
    scheduled: ?quic.endpoint_timers.EndpointTimerDeadline,
    handshake_poll_interval: ?std.Io.Duration,
) std.Io.Timeout {
    var remaining_ns: ?i96 = if (caller.toDurationFromNow(io)) |duration|
        duration.raw.nanoseconds
    else
        null;
    if (scheduled) |value| {
        const timer = std.Io.Clock.Timestamp{
            .clock = .awake,
            .raw = .fromNanoseconds(
                std.math.cast(i96, value.timer.deadline_ns) orelse
                    std.math.maxInt(i96),
            ),
        };
        const duration = timer.durationFromNow(io).raw.nanoseconds;
        remaining_ns = if (remaining_ns) |current|
            @min(current, duration)
        else
            duration;
    }
    if (handshake_poll_interval) |interval| {
        remaining_ns = if (remaining_ns) |current|
            @min(current, interval.nanoseconds)
        else
            interval.nanoseconds;
    }
    return if (remaining_ns) |nanoseconds| .{ .duration = .{
        .clock = .awake,
        .raw = .fromNanoseconds(@max(nanoseconds, 0)),
    } } else .none;
}

test "QUIC endpoint server preserves simultaneous multi-endpoint datagrams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var primary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer primary.deinit();
    var preferred = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer preferred.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer sender.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    var server: Server = undefined;
    server.allocator = failing.allocator();
    server.endpoint = &primary;
    server.pending_multi_endpoint_datagram = null;
    server.preferred_receive_storage = try allocator.alloc(u8, 128);
    server.pending_multi_endpoint_storage = try allocator.alloc(u8, 128);
    server.pending_multi_endpoint_view = null;
    defer {
        if (server.pending_multi_endpoint_datagram) |*datagram| {
            datagram.deinit((datagram.received_on orelse &primary).allocator);
        }
        allocator.free(server.preferred_receive_storage);
        allocator.free(server.pending_multi_endpoint_storage);
    }

    try sender.sendBytes(primary.address(), "primary");
    try sender.sendBytes(preferred.address(), "preferred");
    var primary_storage: [128]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    });
    const first = try receiveViewFromEitherEndpoint(
        &server,
        &preferred,
        &primary_storage,
        .{ .deadline = deadline },
    );
    const first_primary = std.mem.eql(u8, first.bytes, "primary");
    const first_preferred = std.mem.eql(u8, first.bytes, "preferred");
    try std.testing.expect(first_primary != first_preferred);

    const second = try receiveViewFromEitherEndpoint(
        &server,
        &preferred,
        &primary_storage,
        .{ .deadline = deadline },
    );
    try std.testing.expect(if (first_primary)
        std.mem.eql(u8, second.bytes, "preferred")
    else
        std.mem.eql(u8, second.bytes, "primary"));
    try std.testing.expect(first.received_on != second.received_on);
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC endpoint server transfers a pending view to owning receive" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var primary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer primary.deinit();
    var preferred = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 128 },
    );
    defer preferred.deinit();
    var server: Server = undefined;
    server.allocator = allocator;
    server.endpoint = &primary;
    server.pending_multi_endpoint_datagram = null;
    server.pending_multi_endpoint_storage = try allocator.alloc(u8, 128);
    server.pending_multi_endpoint_view = .{
        .from = .{ .ip4 = .loopback(4444) },
        .received_on = &preferred,
        .len = "retained-view".len,
        .ecn = .ect0,
    };
    @memcpy(
        server.pending_multi_endpoint_storage[0.."retained-view".len],
        "retained-view",
    );
    defer allocator.free(server.pending_multi_endpoint_storage);

    var datagram = try receiveFromEitherEndpoint(
        &server,
        &preferred,
        .{ .duration = .{ .clock = .awake, .raw = .zero } },
    );
    defer datagram.deinit(datagram.received_on.?.allocator);
    try std.testing.expectEqualStrings("retained-view", datagram.bytes);
    try std.testing.expectEqual(&preferred, datagram.received_on.?);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect0, datagram.ecn);
    try std.testing.expect(server.pending_multi_endpoint_view == null);
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

fn statelessResetIntervalNs(interval: std.Io.Duration) u64 {
    if (interval.nanoseconds <= 0) return 0;
    return std.math.cast(u64, interval.nanoseconds) orelse
        std.math.maxInt(u64);
}

fn statelessResetRateLimited(
    last_sent_ns: ?u64,
    now_ns: u64,
    min_interval_ns: u64,
) bool {
    if (min_interval_ns == 0) return false;
    const last = last_sent_ns orelse return false;
    return now_ns -| last < min_interval_ns;
}

test "QUIC endpoint server stateless reset rate limit is stable" {
    try std.testing.expect(!statelessResetRateLimited(null, 10, 20));
    try std.testing.expect(statelessResetRateLimited(10, 29, 20));
    try std.testing.expect(!statelessResetRateLimited(10, 30, 20));
    try std.testing.expect(statelessResetRateLimited(30, 10, 20));
    try std.testing.expect(!statelessResetRateLimited(30, 30, 0));
    try std.testing.expectEqual(
        @as(u64, 20_000_000),
        statelessResetIntervalNs(.fromMilliseconds(20)),
    );
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

test "QUIC endpoint server records automatic CID maintenance failures" {
    var server: Server = undefined;
    server.options = .{
        .stateless_reset_key = [_]u8{0x5a} **
            quic.stateless_reset.static_key_len,
    };
    server.connections = .empty;
    server.connection_id_replenishment_failures = 0;

    server.maintainConnectionIds(99);
    try std.testing.expectEqual(
        @as(u64, 1),
        server.connectionIdReplenishmentFailures(),
    );
}
