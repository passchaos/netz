//! Endpoint-wide dispatch for established QUIC connections.
//!
//! A QUIC UDP socket has one receive owner. Datagrams are routed by Destination
//! Connection ID before they enter connection state, and the same owner keeps
//! the aggregate timer schedule synchronized after every receive/send turn.
//! This avoids the incorrect but tempting design where connection tasks race
//! to read a shared UDP socket and discard one another's packets.

const std = @import("std");
const builtin = @import("builtin");
const deadline_policy = @import("../internal/deadline.zig");
const quic = @import("mod.zig");
const connection_router = @import("connection_router.zig");
const endpoint_timers = @import("endpoint_timers.zig");
const handshake_inbox = @import("handshake_inbox.zig");
const one_rtt = @import("one_rtt.zig");
const runtime = @import("runtime.zig");

test {
    _ = @import("endpoint_dispatcher/tests.zig");
}

pub const ConnectionHandle = usize;
pub const PendingHandshakeHandle = usize;
pub const default_server_connection_id_len: usize = 16;

pub const Error = runtime.Error || one_rtt.Error ||
    connection_router.Error || endpoint_timers.Error || handshake_inbox.Error || error{
    DuplicateConnectionHandle,
    UnknownConnectionHandle,
    ConnectionEndpointMismatch,
    ConnectionIdMismatch,
    StaleConnectionRoute,
    PendingHandshakeLimitReached,
    PendingDatagramObserverBound,
};
pub const ReceiveError = Error || runtime.ReceiveTimeoutError;

const ConnectionEntry = struct {
    connection: *one_rtt.Connection,
    connection_ids: std.ArrayList(connection_router.ConnectionIdKey) = .empty,
    connection_id_revision: ?u64 = null,
    route_metadata: ?connection_router.Route = null,
    connection_id_sync_count: if (builtin.is_test) usize else void =
        if (builtin.is_test) 0 else {},

    fn deinit(self: *ConnectionEntry, allocator: std.mem.Allocator) void {
        self.connection_ids.deinit(allocator);
        self.* = undefined;
    }
};

const PendingHandshakeEntry = struct {
    inbox: *handshake_inbox.Inbox,
    connection_ids: std.ArrayList(connection_router.ConnectionIdKey) = .empty,

    fn deinit(
        self: *PendingHandshakeEntry,
        allocator: std.mem.Allocator,
    ) void {
        self.connection_ids.deinit(allocator);
        self.* = undefined;
    }
};

const PendingReady = struct {
    handles: std.ArrayList(ConnectionHandle) = .empty,
    head: usize = 0,

    fn deinit(self: *PendingReady, allocator: std.mem.Allocator) void {
        self.handles.deinit(allocator);
        self.* = undefined;
    }

    fn ensureCapacity(
        self: *PendingReady,
        allocator: std.mem.Allocator,
        capacity: usize,
    ) std.mem.Allocator.Error!void {
        self.compact();
        try self.handles.ensureTotalCapacity(allocator, capacity);
    }

    fn pushAssumeCapacity(context: *anyopaque, handle: usize) void {
        const self: *PendingReady = @ptrCast(@alignCast(context));
        // Direct connection users can consume the pending slot without going
        // through the dispatcher and later preload another datagram. Keep the
        // notification idempotent so that sequence still has one ready token.
        if (containsConnectionHandle(self.handles.items[self.head..], handle)) {
            return;
        }
        if (self.handles.items.len == self.handles.capacity) self.compact();
        std.debug.assert(self.handles.items.len < self.handles.capacity);
        self.handles.appendAssumeCapacity(handle);
    }

    fn pop(self: *PendingReady) ?ConnectionHandle {
        if (self.head == self.handles.items.len) return null;
        const handle = self.handles.items[self.head];
        self.head += 1;
        if (self.head == self.handles.items.len) {
            self.handles.clearRetainingCapacity();
            self.head = 0;
        }
        return handle;
    }

    fn remove(self: *PendingReady, handle: ConnectionHandle) void {
        var index = self.head;
        while (index < self.handles.items.len) : (index += 1) {
            if (self.handles.items[index] != handle) continue;
            _ = self.handles.orderedRemove(index);
            if (self.head == self.handles.items.len) {
                self.handles.clearRetainingCapacity();
                self.head = 0;
            }
            return;
        }
    }

    fn compact(self: *PendingReady) void {
        if (self.head == 0) return;
        const remaining = self.handles.items.len - self.head;
        std.mem.copyForwards(
            ConnectionHandle,
            self.handles.items[0..remaining],
            self.handles.items[self.head..],
        );
        self.handles.items.len = remaining;
        self.head = 0;
    }
};

pub const RoutedPacket = struct {
    connection_handle: ConnectionHandle,
    connection_id_sequence: u64,
    packet: one_rtt.ReceivedPacket,
};

pub const RoutedPacketView = struct {
    connection_handle: ConnectionHandle,
    connection_id_sequence: u64,
    packet: one_rtt.ReceivedPacketView,
};

pub const VisitEvent = union(enum) {
    consumed,
    packet: struct {
        connection_handle: ConnectionHandle,
        connection_id_sequence: u64,
    },
    timer: TimerEvent,
    discarded_long_header: ConnectionHandle,
    pending_handshake: PendingHandshakeHandle,
    new_initial: InitialDatagram,
    unrouted: UnroutedDatagram,

    pub fn deinit(self: *VisitEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .new_initial => |*event| event.datagram.deinit(allocator),
            .unrouted => |*event| event.datagram.deinit(allocator),
            .consumed,
            .packet,
            .timer,
            .discarded_long_header,
            .pending_handshake,
            => {},
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

pub const TimerEvent = struct {
    connection_handle: ConnectionHandle,
    timer: one_rtt.TimerDeadline,
};

pub const InitialDatagram = struct {
    datagram: runtime.OwnedBytes,
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    first_packet_len: usize,
};

pub const UnroutedKind = enum {
    unknown_short_header,
    non_initial_long_header,
    malformed_long_header,
    undersized_initial,
};

pub const UnroutedDatagram = struct {
    datagram: runtime.OwnedBytes,
    kind: UnroutedKind,
};

pub const Event = union(enum) {
    consumed,
    packet: RoutedPacket,
    timer: TimerEvent,
    /// Late Initial/Handshake packets routed to an established connection
    /// belong to discarded packet-number spaces and are consumed silently by
    /// the socket owner rather than mis-decoded as short-header packets.
    discarded_long_header: ConnectionHandle,
    /// A long-header datagram was transferred to a registered handshake inbox.
    pending_handshake: PendingHandshakeHandle,
    /// A structurally valid, minimum-sized client Initial with an unknown DCID.
    /// The endpoint owner can admit it into handshake state without reparsing
    /// untrusted invariant-header metadata.
    new_initial: InitialDatagram,
    /// Unknown short headers and non-admissible long headers remain available
    /// for stateless-reset/drop policy but never enter the handshake path.
    unrouted: UnroutedDatagram,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .packet => |*event| event.packet.deinit(allocator),
            .new_initial => |*event| event.datagram.deinit(allocator),
            .unrouted => |*event| event.datagram.deinit(allocator),
            .consumed,
            .timer,
            .discarded_long_header,
            .pending_handshake,
            => {},
        }
        self.* = undefined;
    }

    /// Transfer the datagram behind a new-connection event. The event becomes
    /// inert so its normal deferred deinit remains safe.
    pub fn takeNewInitial(self: *Event) ?runtime.OwnedBytes {
        if (self.* != .new_initial) return null;
        const datagram = self.new_initial.datagram;
        self.* = .consumed;
        return datagram;
    }
};

pub const Dispatcher = struct {
    allocator: std.mem.Allocator,
    endpoint: *runtime.Endpoint,
    router: connection_router.Router,
    timers: endpoint_timers.EndpointTimers,
    connections: std.AutoHashMapUnmanaged(
        ConnectionHandle,
        ConnectionEntry,
    ) = .empty,
    pending_router: connection_router.Router,
    pending_handshakes: std.AutoHashMapUnmanaged(
        PendingHandshakeHandle,
        PendingHandshakeEntry,
    ) = .empty,
    /// Owning FIFO for datagrams already read in a batch but deferred across
    /// a route-publishing event such as server Initial admission/promotion.
    buffered_datagrams: std.ArrayList(runtime.OwnedBytes) = .empty,
    /// Registered connections can retain at most one preloaded application
    /// datagram. Track ready handles directly so an idle endpoint does not
    /// scan every connection. The indirection keeps observer pointers stable
    /// when this dispatcher value moves.
    pending_ready: ?*PendingReady = null,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *runtime.Endpoint,
    ) Dispatcher {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .router = .init(allocator),
            .timers = .init(allocator),
            .pending_router = .init(allocator),
        };
    }

    /// Release dispatcher metadata without deinitializing caller-owned QUIC
    /// connections or the shared UDP endpoint. Connections must be unregistered
    /// before their storage moves or is destroyed.
    pub fn deinit(self: *Dispatcher) void {
        const pending_ready = self.pending_ready;
        var iterator = self.connections.iterator();
        while (iterator.next()) |entry| {
            if (pending_ready) |ready| {
                _ = entry.value_ptr.connection.unbindPendingDatagramObserver(
                    ready,
                    entry.key_ptr.*,
                );
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.connections.deinit(self.allocator);
        var pending_iterator = self.pending_handshakes.valueIterator();
        while (pending_iterator.next()) |entry| {
            entry.inbox.close();
            entry.deinit(self.allocator);
        }
        self.pending_handshakes.deinit(self.allocator);
        for (self.buffered_datagrams.items) |*datagram| {
            datagram.deinit(self.allocator);
        }
        self.buffered_datagrams.deinit(self.allocator);
        if (pending_ready) |ready| {
            ready.deinit(self.allocator);
            self.allocator.destroy(ready);
        }
        self.pending_router.deinit();
        self.router.deinit();
        self.timers.deinit();
        self.* = undefined;
    }

    /// Register every CID accepted by one pending handshake inbox. The inbox
    /// remains caller-owned and must outlive registration.
    pub fn registerPendingHandshake(
        self: *Dispatcher,
        handle: PendingHandshakeHandle,
        inbox: *handshake_inbox.Inbox,
    ) Error!void {
        const connection_ids = inbox.connectionIds();
        for (connection_ids) |connection_id| {
            if ((try self.router.lookup(connection_id.slice())) != null or
                (try self.pending_router.lookup(connection_id.slice())) != null)
            {
                return error.DuplicateConnectionId;
            }
        }
        try self.pending_router.ensureCapacity(
            self.pending_router.count() + connection_ids.len,
        );
        const slot = try self.pending_handshakes.getOrPut(
            self.allocator,
            handle,
        );
        if (slot.found_existing) return error.DuplicateConnectionHandle;
        slot.value_ptr.* = .{ .inbox = inbox };
        errdefer {
            var removed = self.pending_handshakes.fetchRemove(handle).?.value;
            for (removed.connection_ids.items) |*key| {
                _ = self.pending_router.unregister(key.slice()) catch false;
            }
            removed.deinit(self.allocator);
        }
        try slot.value_ptr.connection_ids.ensureTotalCapacity(
            self.allocator,
            connection_ids.len,
        );
        for (connection_ids) |key| {
            try self.pending_router.register(key.slice(), .{
                .connection_index = handle,
                .peer_address = inbox.peer,
                .active_migration_disabled = true,
            });
            slot.value_ptr.connection_ids.appendAssumeCapacity(key);
        }
    }

    pub fn unregisterPendingHandshake(
        self: *Dispatcher,
        handle: PendingHandshakeHandle,
    ) Error!bool {
        const entry = self.pending_handshakes.getPtr(handle) orelse
            return false;
        var stale_route = false;
        for (entry.connection_ids.items) |*key| {
            if (!try self.pending_router.unregister(key.slice())) {
                stale_route = true;
            }
        }
        var removed = self.pending_handshakes.fetchRemove(handle).?.value;
        removed.inbox.close();
        removed.deinit(self.allocator);
        if (stale_route) return error.StaleConnectionRoute;
        return true;
    }

    /// Atomically replace pending-handshake routes with the established
    /// connection's local CID set. The connection and inbox remain owned by
    /// the caller; successful promotion closes the inbox to wake any waiter.
    pub fn promotePendingHandshake(
        self: *Dispatcher,
        pending_handle: PendingHandshakeHandle,
        connection_handle: ConnectionHandle,
        connection: *one_rtt.Connection,
    ) Error!void {
        const pending = self.pending_handshakes.getPtr(pending_handle) orelse
            return error.UnknownConnectionHandle;
        if (connection.endpoint != self.endpoint) {
            return error.ConnectionEndpointMismatch;
        }
        for (pending.connection_ids.items) |*key| {
            const route = (try self.pending_router.lookup(key.slice())) orelse
                return error.StaleConnectionRoute;
            if (route.connection_index != pending_handle) {
                return error.StaleConnectionRoute;
            }
        }

        var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
        const active = try connection.localConnectionIdsInto(&active_storage);
        for (active) |id| {
            if ((try self.router.lookup(id.connection_id)) != null) {
                return error.DuplicateConnectionId;
            }
            if (try self.pending_router.lookup(id.connection_id)) |route| {
                if (route.connection_index != pending_handle) {
                    return error.DuplicateConnectionId;
                }
            }
        }
        if (self.connections.contains(connection_handle)) {
            return error.DuplicateConnectionHandle;
        }

        // Reserve every operation that can allocate before removing pending
        // routes. Once removal begins, the rest of promotion is infallible
        // unless the dispatcher's internal route metadata is already stale.
        try self.timers.ensureCapacity(self.connections.count() + 1);
        const connection_capacity = std.math.add(
            usize,
            self.connections.count(),
            1,
        ) catch return error.OutOfMemory;
        const route_capacity = std.math.mul(
            usize,
            connection_capacity,
            quic.connection_id.max_pool_size,
        ) catch return error.OutOfMemory;
        try self.router.ensureCapacity(route_capacity);
        try self.buffered_datagrams.ensureUnusedCapacity(
            self.allocator,
            pending.inbox.applicationCount(),
        );
        const pending_ready = try self.ensurePendingReady(connection_capacity);
        if (!connection.canBindPendingDatagramObserver(
            pending_ready,
            connection_handle,
            PendingReady.pushAssumeCapacity,
        )) return error.PendingDatagramObserverBound;
        const slot = try self.connections.getOrPut(
            self.allocator,
            connection_handle,
        );
        std.debug.assert(!slot.found_existing);
        slot.value_ptr.* = .{ .connection = connection };
        errdefer {
            var removed = self.connections.fetchRemove(
                connection_handle,
            ).?.value;
            removed.deinit(self.allocator);
        }
        try slot.value_ptr.connection_ids.ensureTotalCapacity(
            self.allocator,
            quic.connection_id.max_pool_size,
        );
        // The connection entry is fully initialized but intentionally not yet
        // routable. No packet can observe it until all pending aliases have
        // been withdrawn below.

        // `fetchRemove` below can invalidate `pending`, so retain the only
        // caller-owned pointer needed after route removal.
        const pending_inbox = pending.inbox;
        for (pending.connection_ids.items) |*key| {
            std.debug.assert(try self.pending_router.unregister(key.slice()));
        }
        var removed_pending = self.pending_handshakes.fetchRemove(
            pending_handle,
        ).?.value;
        defer removed_pending.deinit(self.allocator);
        pending_inbox.close();

        for (active) |id| {
            const key = try connection_router.ConnectionIdKey.init(
                id.connection_id,
            );
            // Capacity and CID validity were checked above, so these cannot
            // fail in a consistent dispatcher.
            self.router.register(id.connection_id, connection.route(
                connection_handle,
                id.sequence_number,
            )) catch unreachable;
            slot.value_ptr.connection_ids.appendAssumeCapacity(key);
        }
        slot.value_ptr.connection_id_revision =
            connection.localConnectionIdRevision();
        slot.value_ptr.route_metadata = connection.route(
            connection_handle,
            0,
        );
        connection.bindPendingDatagramObserver(
            pending_ready,
            connection_handle,
            PendingReady.pushAssumeCapacity,
        ) catch unreachable;
        pending_inbox.drainApplicationInto(&self.buffered_datagrams);
        self.timers.armFromConnection(
            connection_handle,
            connection,
        ) catch unreachable;
    }

    pub fn registerConnection(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection: *one_rtt.Connection,
    ) Error!void {
        if (connection.endpoint != self.endpoint) {
            return error.ConnectionEndpointMismatch;
        }
        var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
        const active = try connection.localConnectionIdsInto(&active_storage);
        for (active) |id| {
            if ((try self.pending_router.lookup(id.connection_id)) != null) {
                return error.DuplicateConnectionId;
            }
        }
        if (self.connections.contains(handle)) {
            return error.DuplicateConnectionHandle;
        }
        // Reserve the timer slot before publishing the connection. Packet
        // processing is stateful, so its later timer refresh must not discover
        // OOM after the packet has already committed transport state.
        try self.timers.ensureCapacity(self.connections.count() + 1);
        const connection_capacity = std.math.add(
            usize,
            self.connections.count(),
            1,
        ) catch return error.OutOfMemory;
        const route_capacity = std.math.mul(
            usize,
            connection_capacity,
            quic.connection_id.max_pool_size,
        ) catch return error.OutOfMemory;
        try self.router.ensureCapacity(route_capacity);
        const pending_ready = try self.ensurePendingReady(connection_capacity);
        if (!connection.canBindPendingDatagramObserver(
            pending_ready,
            handle,
            PendingReady.pushAssumeCapacity,
        )) return error.PendingDatagramObserverBound;
        const slot = try self.connections.getOrPut(self.allocator, handle);
        std.debug.assert(!slot.found_existing);
        slot.value_ptr.* = .{ .connection = connection };
        errdefer {
            var removed = self.connections.fetchRemove(handle).?.value;
            for (removed.connection_ids.items) |*key| {
                _ = self.router.unregister(key.slice()) catch false;
            }
            removed.deinit(self.allocator);
        }
        try slot.value_ptr.connection_ids.ensureTotalCapacity(
            self.allocator,
            quic.connection_id.max_pool_size,
        );
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, connection);
        connection.bindPendingDatagramObserver(
            pending_ready,
            handle,
            PendingReady.pushAssumeCapacity,
        ) catch unreachable;
    }

    /// Replace the storage address for an already registered connection.
    ///
    /// Stateful protocol wrappers often promote a pending value by moving the
    /// embedded `Connection` into stable application storage. CID routes and
    /// timer identity remain unchanged, so replacing the pointer atomically is
    /// safer than an unregister/register gap in the sole receive loop.
    pub fn replaceConnection(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection: *one_rtt.Connection,
    ) Error!void {
        if (connection.endpoint != self.endpoint) {
            return error.ConnectionEndpointMismatch;
        }
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        const pending_ready = self.pending_ready orelse
            return error.PendingDatagramObserverBound;
        if (!connection.canBindPendingDatagramObserver(
            pending_ready,
            handle,
            PendingReady.pushAssumeCapacity,
        )) {
            return error.PendingDatagramObserverBound;
        }
        var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
        const active = try connection.localConnectionIdsInto(&active_storage);
        if (active.len != entry.connection_ids.items.len) {
            return error.ConnectionIdMismatch;
        }
        for (active) |id| {
            const key = try connection_router.ConnectionIdKey.init(
                id.connection_id,
            );
            if (!containsConnectionId(entry.connection_ids.items, key)) {
                return error.ConnectionIdMismatch;
            }
        }
        const previous_connection = entry.connection;
        entry.connection = connection;
        errdefer {
            entry.connection = previous_connection;
            self.syncConnectionIds(handle) catch {};
            self.timers.armFromConnection(
                handle,
                previous_connection,
            ) catch {};
        }
        // The replacement can carry updated peer/path metadata even when its
        // CID set is identical. Rewrite every existing route before caching
        // the new revision so later conditional syncs cannot mask stale data.
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, connection);
        std.debug.assert(previous_connection.unbindPendingDatagramObserver(
            pending_ready,
            handle,
        ));
        connection.bindPendingDatagramObserver(
            pending_ready,
            handle,
            PendingReady.pushAssumeCapacity,
        ) catch unreachable;
    }

    pub fn sendNewConnectionId(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        try self.ensureConnectionIdAvailable(handle, connection_id);
        try entry.connection.sendNewConnectionId(
            connection_id,
            stateless_reset_token,
        );
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, entry.connection);
    }

    pub fn sendNewConnectionIdWithDerivedToken(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection_id: []const u8,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        try self.ensureConnectionIdAvailable(handle, connection_id);
        try entry.connection.sendNewConnectionIdWithDerivedToken(connection_id);
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, entry.connection);
    }

    pub fn sendNewConnectionIdWithDerivedTokenRetiringPriorTo(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection_id: []const u8,
        retire_prior_to: u64,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        try self.ensureConnectionIdAvailable(handle, connection_id);
        try entry.connection
            .sendNewConnectionIdWithDerivedTokenRetiringPriorTo(
            connection_id,
            retire_prior_to,
        );
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, entry.connection);
    }

    pub fn sendNewConnectionIdRetiringPriorTo(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
        retire_prior_to: u64,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        try self.ensureConnectionIdAvailable(handle, connection_id);
        try entry.connection.sendNewConnectionIdRetiringPriorTo(
            connection_id,
            stateless_reset_token,
            retire_prior_to,
        );
        try self.syncConnectionIds(handle);
        try self.timers.armFromConnection(handle, entry.connection);
    }

    /// Reconcile socket routes with the connection's authoritative local CID
    /// pool. Registration reserves the fixed QUIC pool maximum, so packet-time
    /// retirement and route refresh do not allocate after state has committed.
    pub fn syncConnectionIds(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        var active_storage: [quic.connection_id.max_pool_size]quic.connection_id.LocalPool.ActiveId = undefined;
        const active = try entry.connection.localConnectionIdsInto(
            &active_storage,
        );

        // Reject a collision before modifying any route. Existing routes for
        // this handle are updated below because migration policy and peer path
        // metadata can change while the CID remains stable.
        for (active) |id| {
            if (try self.router.lookup(id.connection_id)) |route| {
                if (route.connection_index != handle) {
                    return error.DuplicateConnectionId;
                }
            }
            if ((try self.pending_router.lookup(id.connection_id)) != null) {
                return error.DuplicateConnectionId;
            }
        }

        for (active) |id| {
            const key = try connection_router.ConnectionIdKey.init(
                id.connection_id,
            );
            const known = containsConnectionId(
                entry.connection_ids.items,
                key,
            );
            try self.router.registerOrReplace(
                id.connection_id,
                entry.connection.route(handle, id.sequence_number),
            );
            if (!known) entry.connection_ids.appendAssumeCapacity(key);
        }

        var index = entry.connection_ids.items.len;
        while (index != 0) {
            index -= 1;
            const registered = entry.connection_ids.items[index];
            if (containsActiveId(active, registered)) continue;
            if (!try self.router.unregister(registered.slice())) {
                return error.StaleConnectionRoute;
            }
            _ = entry.connection_ids.swapRemove(index);
        }
        entry.connection_id_revision =
            entry.connection.localConnectionIdRevision();
        entry.route_metadata = entry.connection.route(handle, 0);
        if (comptime builtin.is_test) entry.connection_id_sync_count +|= 1;
    }

    /// Reconcile routes only when the local CID set or route metadata changed.
    /// Event loops may call this after arbitrary connection work without
    /// paying the full fixed-pool scan on ordinary STREAM/ACK packets.
    pub fn syncConnectionIdsIfChanged(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        if (entry.connection_id_revision ==
            entry.connection.localConnectionIdRevision() and
            routeMetadataEqual(
                entry.route_metadata,
                entry.connection.route(handle, 0),
            )) return;
        try self.syncConnectionIds(handle);
    }

    fn ensureConnectionIdAvailable(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection_id: []const u8,
    ) Error!void {
        if (try self.router.lookup(connection_id)) |route| {
            if (route.connection_index != handle) {
                return error.DuplicateConnectionId;
            }
        }
        if ((try self.pending_router.lookup(connection_id)) != null) {
            return error.DuplicateConnectionId;
        }
    }

    /// Remove every route and timer before the caller destroys the connection.
    pub fn unregisterConnection(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!bool {
        const entry = self.connections.getPtr(handle) orelse return false;
        var stale_route = false;
        for (entry.connection_ids.items) |*key| {
            if (!try self.router.unregister(key.slice())) stale_route = true;
        }
        _ = self.timers.disarmConnection(handle);
        if (self.pending_ready) |ready| {
            ready.remove(handle);
            _ = entry.connection.unbindPendingDatagramObserver(ready, handle);
        }
        var removed = self.connections.fetchRemove(handle).?.value;
        defer removed.deinit(self.allocator);
        // Even a corrupted/misused dispatcher must remove every remaining
        // route and the connection entry. Returning after the first missing
        // route would leave later CIDs pointing at freed connection storage.
        if (stale_route) return error.StaleConnectionRoute;
        return true;
    }

    pub fn connectionCount(self: *const Dispatcher) usize {
        return self.connections.count();
    }

    pub fn routeCount(self: *const Dispatcher) usize {
        return self.router.count();
    }

    pub fn pendingHandshakeCount(self: *const Dispatcher) usize {
        return self.pending_handshakes.count();
    }

    /// Allocate and register a bounded pending-handshake inbox using a fresh
    /// random server CID. The returned inbox accepts the admitted original
    /// DCID as well, which is required for retransmitted or fragmented Initial
    /// flights. The caller owns the returned stable allocation after success
    /// and must unregister it before deinitializing and destroying it.
    pub fn admitPendingHandshake(
        self: *Dispatcher,
        handle: PendingHandshakeHandle,
        initial: InitialDatagram,
        max_pending_handshakes: usize,
        inbox_capacity: usize,
    ) Error!*handshake_inbox.Inbox {
        if (max_pending_handshakes == 0 or
            self.pending_handshakes.count() >= max_pending_handshakes)
        {
            return error.PendingHandshakeLimitReached;
        }
        var server_connection_id: [default_server_connection_id_len]u8 =
            undefined;
        // Collision probability is negligible, but lookup makes this a hard
        // endpoint invariant rather than a probabilistic API contract.
        while (true) {
            try std.Io.randomSecure(self.endpoint.io, &server_connection_id);
            if ((try self.router.lookup(&server_connection_id)) == null and
                (try self.pending_router.lookup(&server_connection_id)) == null)
            {
                break;
            }
        }
        const inbox = try self.allocator.create(handshake_inbox.Inbox);
        errdefer self.allocator.destroy(inbox);
        inbox.* = try handshake_inbox.Inbox.init(
            self.allocator,
            self.endpoint.io,
            &.{ initial.destination_connection_id, &server_connection_id },
            initial.datagram.from,
            inbox_capacity,
        );
        errdefer inbox.deinit();
        try self.registerPendingHandshake(handle, inbox);
        return inbox;
    }

    /// Refresh timer state after application code sends or otherwise mutates a
    /// connection outside `receive`.
    pub fn refreshConnectionTimer(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!void {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        try self.timers.armFromConnection(handle, entry.connection);
    }

    pub fn nextTimerDeadline(
        self: *const Dispatcher,
    ) ?endpoint_timers.EndpointTimerDeadline {
        return self.timers.earliestDeadline();
    }

    /// Reserve one bidirectional stream when the registered connection has
    /// peer credit. This operation never reads the shared UDP socket, waits,
    /// or emits STREAMS_BLOCKED; `null` asks the endpoint loop to drive more
    /// packet/timer progress before polling again.
    pub fn pollOpenStream(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!?u64 {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        const result = entry.connection.pollOpenStream();
        try self.timers.armFromConnection(handle, entry.connection);
        return result;
    }

    /// Socket-free unidirectional counterpart to `pollOpenStream`.
    pub fn pollOpenUnidirectionalStream(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!?u64 {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        const result = entry.connection.pollOpenUnidirectionalStream();
        try self.timers.armFromConnection(handle, entry.connection);
        return result;
    }

    pub fn pollOpenUniStream(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!?u64 {
        return self.pollOpenUnidirectionalStream(handle);
    }

    /// Return one event from state already buffered while the handshake was
    /// promoted. A client's Finished datagram can carry its first 1-RTT
    /// packet, so an event loop must drain this before blocking on UDP again.
    pub fn pollConnectionPacket(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!?RoutedPacket {
        const entry = self.connections.getPtr(handle) orelse
            return error.UnknownConnectionHandle;
        var packet = (try entry.connection.receivePendingPacket()) orelse
            return null;
        if (self.pending_ready) |ready| ready.remove(handle);
        errdefer packet.deinit(self.allocator);
        _ = try entry.connection.retransmitPacketThresholdLosses(
            one_rtt.max_batch_packets,
        );
        try self.syncConnectionIdsIfChanged(handle);
        try self.timers.armFromConnection(handle, entry.connection);
        return .{
            .connection_handle = handle,
            .connection_id_sequence = 0,
            .packet = packet,
        };
    }

    /// Poll all registered connections once for data retained during their
    /// handshake. This is the endpoint-loop companion to `receive`: callers
    /// should drain it before blocking for another UDP datagram.
    pub fn pollPendingPacket(self: *Dispatcher) Error!?RoutedPacket {
        const pending_ready = self.pending_ready orelse return null;
        while (pending_ready.pop()) |handle| {
            if (try self.pollConnectionPacketReady(handle)) |packet| {
                return packet;
            }
        }
        return null;
    }

    fn ensurePendingReady(
        self: *Dispatcher,
        capacity: usize,
    ) Error!*PendingReady {
        if (self.pending_ready) |ready| {
            try ready.ensureCapacity(self.allocator, capacity);
            return ready;
        }
        const ready = try self.allocator.create(PendingReady);
        ready.* = .{};
        errdefer self.allocator.destroy(ready);
        errdefer ready.deinit(self.allocator);
        try ready.ensureCapacity(self.allocator, capacity);
        self.pending_ready = ready;
        return ready;
    }

    fn pollConnectionPacketReady(
        self: *Dispatcher,
        handle: ConnectionHandle,
    ) Error!?RoutedPacket {
        const entry = self.connections.getPtr(handle) orelse return null;
        var packet = (try entry.connection.receivePendingPacket()) orelse
            return null;
        errdefer packet.deinit(self.allocator);
        _ = try entry.connection.retransmitPacketThresholdLosses(
            one_rtt.max_batch_packets,
        );
        try self.syncConnectionIdsIfChanged(handle);
        try self.timers.armFromConnection(handle, entry.connection);
        return .{
            .connection_handle = handle,
            .connection_id_sequence = 0,
            .packet = packet,
        };
    }

    /// Service at most one due connection timer. Returning null means there is
    /// no due work at `now_ns`; callers can arm their socket wait from
    /// `nextTimerDeadline`.
    pub fn serviceNextTimerAt(
        self: *Dispatcher,
        now_ns: u64,
    ) Error!?TimerEvent {
        const scheduled = self.timers.earliestDeadline() orelse return null;
        if (now_ns < scheduled.timer.deadline_ns) return null;
        const entry = self.connections.getPtr(
            @intCast(scheduled.connection_id),
        ) orelse {
            _ = self.timers.disarmConnection(scheduled.connection_id);
            return error.StaleConnectionRoute;
        };
        const serviced = (try self.timers.serviceConnection(
            scheduled.connection_id,
            entry.connection,
            now_ns,
        )) orelse return null;
        return .{
            .connection_handle = @intCast(serviced.connection_id),
            .timer = serviced.timer,
        };
    }

    /// Service a bounded snapshot of connections due at `now_ns`. A
    /// connection that rearms another immediately-due timer is not revisited
    /// in this batch, preserving a fair opportunity for UDP receive and other
    /// connections on the next event-loop turn.
    pub fn serviceDueTimersAt(
        self: *Dispatcher,
        now_ns: u64,
        output: []TimerEvent,
    ) Error!usize {
        if (output.len == 0 or self.timers.count() == 0) return 0;
        var stack_handles: [32]ConnectionHandle = undefined;
        const handles = if (output.len <= stack_handles.len)
            stack_handles[0..output.len]
        else
            try self.allocator.alloc(ConnectionHandle, output.len);
        defer if (handles.ptr != stack_handles[0..].ptr) {
            self.allocator.free(handles);
        };
        const due_count = self.timers.dueConnectionIdsInto(
            now_ns,
            handles,
        );
        var count: usize = 0;
        for (handles[0..due_count]) |handle| {
            const entry = self.connections.getPtr(handle) orelse {
                _ = self.timers.disarmConnection(handle);
                return error.StaleConnectionRoute;
            };
            const serviced = (try self.timers.serviceConnection(
                handle,
                entry.connection,
                now_ns,
            )) orelse continue;
            output[count] = .{
                .connection_handle = handle,
                .timer = serviced.timer,
            };
            count += 1;
        }
        return count;
    }

    /// Own the next UDP receive, answer unsupported versions, and either route
    /// an established packet or transfer an unknown-CID datagram to admission.
    /// The caller owns the returned event and must call `Event.deinit`.
    pub fn receive(
        self: *Dispatcher,
        supported_versions: []const u32,
    ) ReceiveError!Event {
        return self.receiveUntil(supported_versions, null);
    }

    /// `receive` with an additional endpoint-loop wakeup deadline. Connection
    /// transport timers still take precedence when they expire first. This is
    /// used by supervisors that must also poll handshake completions without
    /// introducing another UDP receiver.
    pub fn receiveTimeout(
        self: *Dispatcher,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) ReceiveError!Event {
        return self.receiveUntil(
            supported_versions,
            timeout.toTimestamp(self.endpoint.io),
        );
    }

    /// Receive under one caller-owned awake-clock budget. Transport timers can
    /// wake the dispatcher earlier, but processing them never renews this
    /// absolute deadline. Rejecting other clocks also prevents incomparable
    /// timestamps from being ordered against QUIC's awake-clock timers.
    pub fn receiveWithDeadline(
        self: *Dispatcher,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveError!Event {
        return self.receiveUntil(
            supported_versions,
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
        );
    }

    /// Allocation-free established-packet receive for non-GRO endpoint loops.
    /// Packet/frame views are valid only during `visitor`. Handshake and
    /// unrouted datagrams retain the owning `VisitEvent` variants required for
    /// admission or diagnostics.
    pub fn receiveVisiting(
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!VisitEvent {
        return self.receiveVisitingUntil(
            supported_versions,
            storage,
            null,
            context,
            visitor,
        );
    }

    pub fn receiveVisitingTimeout(
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!VisitEvent {
        return self.receiveVisitingUntil(
            supported_versions,
            storage,
            timeout.toTimestamp(self.endpoint.io),
            context,
            visitor,
        );
    }

    pub fn receiveVisitingWithDeadline(
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!VisitEvent {
        return self.receiveVisitingUntil(
            supported_versions,
            storage,
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
            context,
            visitor,
        );
    }

    /// Receive and dispatch a bounded batch of independent UDP datagrams.
    /// Established packet contents are borrowed only during `visitor`; the
    /// returned events contain stable routing summaries or own the exceptional
    /// handshake/unrouted datagrams that must survive this call.
    ///
    /// If processing fails after an earlier callback succeeded, transport and
    /// callback side effects remain committed, while every owning event built
    /// for this batch is released before the error is returned.
    pub fn receiveManyVisitingTimeout(
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!usize {
        if (output.len == 0 or
            output.len > runtime.max_receive_batch_messages)
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
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!usize {
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
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        output: []VisitEvent,
        caller_deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!usize {
        while (true) {
            if (self.buffered_datagrams.items.len != 0) {
                output[0] = try self.visitOwnedEvent(
                    try self.dispatch(self.buffered_datagrams.orderedRemove(0)),
                    context,
                    visitor,
                );
                if (output[0] == .discarded_long_header) continue;
                return 1;
            }
            if (try self.pollPendingPacket()) |packet| {
                output[0] = try self.visitOwnedEvent(
                    .{ .packet = packet },
                    context,
                    visitor,
                );
                return 1;
            }
            if (try self.serviceDueTimer()) |timer| {
                output[0] = .{ .timer = timer };
                return 1;
            }

            const receive_timeout = earliestReceiveTimeout(
                self.endpoint.io,
                self.timers.earliestDeadline(),
                caller_deadline,
            );
            var datagrams: [runtime.max_receive_batch_messages]runtime.ReceivedBytesView = undefined;
            const datagram_count = self.endpoint.receiveManyBytesIntoTimeout(
                storage,
                datagrams[0..output.len],
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

            var count: usize = 0;
            errdefer for (output[0..count]) |*event| {
                event.deinit(self.allocator);
            };
            for (datagrams[0..datagram_count], 0..) |datagram, index| {
                const version_negotiated = self.endpoint
                    .sendVersionNegotiationIfUnsupported(
                    datagram.from,
                    datagram.bytes,
                    supported_versions,
                ) catch |err| {
                    try self.bufferDatagramViews(
                        datagrams[index + 1 .. datagram_count],
                    );
                    return err;
                };
                if (version_negotiated) continue;
                const event = self.dispatchVisiting(
                    datagram,
                    context,
                    visitor,
                ) catch |err| {
                    try self.bufferDatagramViews(
                        datagrams[index + 1 .. datagram_count],
                    );
                    return err;
                };
                if (event == .discarded_long_header) continue;
                output[count] = event;
                count += 1;
                if (event == .new_initial) {
                    // Admission publishes the pending CID route above this
                    // call. Preserve every already-received suffix until that
                    // happens so retransmitted/fragmented Initials or eager
                    // application packets cannot be misclassified as another
                    // connection.
                    try self.bufferDatagramViews(
                        datagrams[index + 1 .. datagram_count],
                    );
                    break;
                }
            }
            if (count != 0) return count;
        }
    }

    fn bufferDatagramViews(
        self: *Dispatcher,
        datagrams: []const runtime.ReceivedBytesView,
    ) Error!void {
        if (datagrams.len == 0) return;
        try self.buffered_datagrams.ensureUnusedCapacity(
            self.allocator,
            datagrams.len,
        );
        const original_len = self.buffered_datagrams.items.len;
        errdefer {
            for (self.buffered_datagrams.items[original_len..]) |*datagram| {
                datagram.deinit(self.allocator);
            }
            self.buffered_datagrams.items.len = original_len;
        }
        for (datagrams) |datagram| {
            self.buffered_datagrams.appendAssumeCapacity(
                try self.copyView(datagram),
            );
        }
    }

    fn receiveVisitingUntil(
        self: *Dispatcher,
        supported_versions: []const u32,
        storage: []u8,
        caller_deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (ReceiveError || callbackErrorSet(visitor))!VisitEvent {
        while (true) {
            if (self.buffered_datagrams.items.len != 0) {
                // Route-changing and error suffixes are rare and already
                // owned; preserve their FIFO lifetime guarantees.
                return self.visitOwnedEvent(
                    try self.dispatch(self.buffered_datagrams.orderedRemove(0)),
                    context,
                    visitor,
                );
            }
            if (try self.pollPendingPacket()) |packet| {
                return self.visitOwnedEvent(
                    .{ .packet = packet },
                    context,
                    visitor,
                );
            }
            if (try self.serviceDueTimer()) |timer| {
                return .{ .timer = timer };
            }
            const receive_timeout = earliestReceiveTimeout(
                self.endpoint.io,
                self.timers.earliestDeadline(),
                caller_deadline,
            );
            const datagram = if (receive_timeout == .none)
                try self.endpoint.receiveBytesInto(storage)
            else
                self.endpoint.receiveBytesIntoTimeout(
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
                    // Blocking here would starve an active transport or
                    // caller deadline on backends without timed net waits.
                    error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
                    else => |other| return other,
                };
            if (try self.endpoint.sendVersionNegotiationIfUnsupported(
                datagram.from,
                datagram.bytes,
                supported_versions,
            )) continue;
            const event = try self.dispatchVisiting(
                datagram,
                context,
                visitor,
            );
            if (event == .discarded_long_header) continue;
            return event;
        }
    }

    fn dispatchVisiting(
        self: *Dispatcher,
        datagram: runtime.ReceivedBytesView,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        if (datagram.bytes.len != 0) {
            const pending = self.pending_router.routeDatagramFrom(
                datagram.from,
                datagram.bytes,
            ) catch |err| switch (err) {
                error.InvalidPacket, error.InvalidConnectionId => null,
                else => |other| return other,
            };
            if (pending) |_| {
                return self.eventFromOwned(
                    try self.copyView(datagram),
                    context,
                    visitor,
                );
            }
        }
        const routed = self.router.routeDatagramFrom(
            datagram.from,
            datagram.bytes,
        ) catch |err| switch (err) {
            error.InvalidPacket, error.InvalidConnectionId => return self.eventFromOwned(
                try self.copyView(datagram),
                context,
                visitor,
            ),
            else => |other| return other,
        } orelse return self.eventFromOwned(
            try self.copyView(datagram),
            context,
            visitor,
        );
        const entry = self.connections.getPtr(
            routed.route.connection_index,
        ) orelse return error.StaleConnectionRoute;
        if ((datagram.bytes[0] & 0x80) != 0) {
            return .{ .discarded_long_header = routed.route.connection_index };
        }
        const Adapter = struct {
            connection: *one_rtt.Connection,
            context: @TypeOf(context),
            handle: ConnectionHandle,
            sequence: u64,
            entered: bool = false,

            fn visit(
                adapter: *@This(),
                packet: one_rtt.ReceivedPacketView,
            ) (Error || callbackErrorSet(visitor))!void {
                adapter.entered = true;
                _ = try adapter.connection.retransmitPacketThresholdLosses(
                    one_rtt.max_batch_packets,
                );
                try visitor(adapter.context, .{
                    .connection_handle = adapter.handle,
                    .connection_id_sequence = adapter.sequence,
                    .packet = packet,
                });
            }
        };
        var adapter = Adapter{
            .connection = entry.connection,
            .context = context,
            .handle = routed.route.connection_index,
            .sequence = routed.route.sequence_number,
        };
        const processed = entry.connection.visitRoutedDatagramOrDropAfterCloseAt(.{
            .datagram = datagram,
            .route = routed.route,
            .destination_connection_id = routed.destination_connection_id,
        }, monotonicNowNs(self.endpoint.io), &adapter, Adapter.visit) catch |err| {
            // The transport commits frames before invoking the application
            // visitor. Preserve any resulting CID retirement even when the
            // callback rejects its upper-layer payload.
            try self.syncConnectionIdsIfChanged(
                routed.route.connection_index,
            );
            try self.timers.armFromConnection(
                routed.route.connection_index,
                entry.connection,
            );
            if (!adapter.entered and
                isDiscardedShortPacketError(err)) return .consumed;
            return err;
        };
        if (!processed) {
            try self.timers.armFromConnection(
                routed.route.connection_index,
                entry.connection,
            );
            return .consumed;
        }
        try self.syncConnectionIdsIfChanged(routed.route.connection_index);
        try self.timers.armFromConnection(
            routed.route.connection_index,
            entry.connection,
        );
        return .{ .packet = .{
            .connection_handle = routed.route.connection_index,
            .connection_id_sequence = routed.route.sequence_number,
        } };
    }

    fn copyView(
        self: *Dispatcher,
        datagram: runtime.ReceivedBytesView,
    ) Error!runtime.OwnedBytes {
        return .{
            .from = datagram.from,
            .bytes = try self.allocator.dupe(u8, datagram.bytes),
            .ecn = datagram.ecn,
        };
    }

    fn eventFromOwned(
        self: *Dispatcher,
        datagram: runtime.OwnedBytes,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        return self.visitOwnedEvent(
            try self.dispatch(datagram),
            context,
            visitor,
        );
    }

    fn visitOwnedEvent(
        self: *Dispatcher,
        event_value: Event,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!VisitEvent {
        var event = event_value;
        defer event.deinit(self.allocator);
        return switch (event) {
            .consumed => .consumed,
            .packet => |*packet| blk: {
                visitor(context, .{
                    .connection_handle = packet.connection_handle,
                    .connection_id_sequence = packet.connection_id_sequence,
                    .packet = .{
                        .from = packet.packet.from,
                        .packet_number = packet.packet.packet.packet_number,
                        .frames = packet.packet.frames,
                        .peer_initiated_key_update = packet.packet.peer_initiated_key_update,
                    },
                }) catch |err| {
                    try self.syncConnectionIdsIfChanged(
                        packet.connection_handle,
                    );
                    try self.timers.armFromConnection(
                        packet.connection_handle,
                        self.connections.getPtr(packet.connection_handle).?
                            .connection,
                    );
                    return err;
                };
                try self.syncConnectionIdsIfChanged(packet.connection_handle);
                try self.timers.armFromConnection(
                    packet.connection_handle,
                    self.connections.getPtr(packet.connection_handle).?
                        .connection,
                );
                break :blk .{ .packet = .{
                    .connection_handle = packet.connection_handle,
                    .connection_id_sequence = packet.connection_id_sequence,
                } };
            },
            .timer => |timer| .{ .timer = timer },
            .discarded_long_header => |handle| .{ .discarded_long_header = handle },
            .pending_handshake => |handle| .{ .pending_handshake = handle },
            .new_initial => |initial| blk: {
                event = .consumed;
                break :blk .{ .new_initial = initial };
            },
            .unrouted => |unrouted| blk: {
                event = .consumed;
                break :blk .{ .unrouted = unrouted };
            },
        };
    }

    fn receiveUntil(
        self: *Dispatcher,
        supported_versions: []const u32,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveError!Event {
        while (true) {
            if (self.buffered_datagrams.items.len != 0) {
                const datagram = self.buffered_datagrams.orderedRemove(0);
                return self.dispatch(datagram);
            }
            if (try self.pollPendingPacket()) |packet| {
                return .{ .packet = packet };
            }
            if (try self.serviceDueTimer()) |timer| {
                return .{ .timer = timer };
            }
            const receive_timeout = earliestReceiveTimeout(
                self.endpoint.io,
                self.timers.earliestDeadline(),
                caller_deadline,
            );
            var datagram = self.endpoint.receiveBytesTimeout(
                receive_timeout,
            ) catch |err|
                switch (err) {
                    error.Timeout => {
                        if (caller_deadline) |deadline| {
                            if (deadline.durationFromNow(self.endpoint.io)
                                .raw.nanoseconds <= 0)
                            {
                                return error.Timeout;
                            }
                        }
                        continue;
                    },
                    // A backend without timed network waits remains usable
                    // when no transport timer is armed. Once a connection has
                    // a deadline, falling back to an unbounded receive would
                    // silently starve PTO/ACK/idle work.
                    error.ConcurrencyUnavailable => if (receive_timeout == .none)
                        try self.endpoint.receiveBytes()
                    else
                        return error.ConcurrencyUnavailable,
                    else => |other| return other,
                };
            if (try self.endpoint.sendVersionNegotiationIfUnsupported(
                datagram.from,
                datagram.bytes,
                supported_versions,
            )) {
                datagram.deinit(self.allocator);
                continue;
            }
            // Ownership transfers unconditionally: `dispatch` either returns
            // it through an event, queues it, or releases it before erroring.
            const event = try self.dispatch(datagram);
            if (event == .discarded_long_header) continue;
            return event;
        }
    }

    fn serviceDueTimer(self: *Dispatcher) Error!?TimerEvent {
        const timestamp = std.Io.Clock.awake.now(self.endpoint.io).nanoseconds;
        const now_ns = if (timestamp <= 0)
            0
        else
            std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
        return self.serviceNextTimerAt(now_ns);
    }

    /// Route a datagram already read by an external socket/event-loop owner.
    /// This is the integration point for batched recv loops and handshake
    /// admission queues; established connection tasks never read the socket.
    pub fn dispatch(
        self: *Dispatcher,
        datagram: runtime.OwnedBytes,
    ) Error!Event {
        var owned = datagram;
        var owns_datagram = true;
        errdefer if (owns_datagram) owned.deinit(self.allocator);
        // Pending handshakes are deliberately checked first. Long headers
        // carry the server CID explicitly. Short headers are prefix-routed and
        // retained separately until promotion, preventing an eager client
        // request from being misclassified as an unknown connection.
        if (owned.bytes.len != 0) {
            const pending = self.pending_router.routeDatagramFrom(
                owned.from,
                owned.bytes,
            ) catch |err| switch (err) {
                error.InvalidPacket, error.InvalidConnectionId => null,
                else => |other| return other,
            };
            if (pending) |routed_pending| {
                const entry = self.pending_handshakes.getPtr(
                    routed_pending.route.connection_index,
                ) orelse return error.StaleConnectionRoute;
                const push_result = if ((owned.bytes[0] & 0x80) != 0)
                    entry.inbox.push(owned)
                else
                    entry.inbox.pushApplicationRouted(owned);
                push_result catch |err| switch (err) {
                    // A bounded or concurrently closed handshake must not
                    // terminate the sole endpoint receive loop. The inbox did
                    // not take ownership on failure, so drop the datagram here.
                    error.Full,
                    error.Closed,
                    error.PeerMismatch,
                    error.ConnectionIdMismatch,
                    => {
                        owned.deinit(self.allocator);
                        owns_datagram = false;
                        return .consumed;
                    },
                    else => |other| return other,
                };
                owns_datagram = false;
                return .{
                    .pending_handshake = routed_pending.route.connection_index,
                };
            }
        }
        const routed = self.router.routeDatagramFrom(
            owned.from,
            owned.bytes,
        ) catch |err| switch (err) {
            // Header parsing happens before a route exists. Malformed unknown
            // input is policy data, not a fatal endpoint-loop error.
            error.InvalidPacket, error.InvalidConnectionId => {
                owns_datagram = false;
                return .{ .unrouted = .{
                    .datagram = owned,
                    .kind = .malformed_long_header,
                } };
            },
            else => |other| return other,
        } orelse {
            owns_datagram = false;
            return classifyUnrouted(owned);
        };
        const entry = self.connections.getPtr(
            routed.route.connection_index,
        ) orelse return error.StaleConnectionRoute;
        if ((owned.bytes[0] & 0x80) != 0) {
            owned.deinit(self.allocator);
            owns_datagram = false;
            return .{
                .discarded_long_header = routed.route.connection_index,
            };
        }
        var routed_datagram = runtime.RoutedBytes{
            .datagram = owned,
            .route = routed.route,
            .destination_connection_id = routed.destination_connection_id,
        };
        var packet = entry.connection.receiveRoutedDatagramOrDropAfterClose(
            routed_datagram,
        ) catch |err| {
            // Frame/transport validation can install closing or draining state
            // before returning the triggering error. Preserve that diagnostic
            // while making its close deadline visible to the endpoint loop.
            try self.timers.armFromConnection(
                routed.route.connection_index,
                entry.connection,
            );
            if (isDiscardedShortPacketError(err)) {
                // A short-header CID is visible before packet authentication.
                // Invalid ciphertext and pre-authentication format failures
                // addressed to an active CID are ordinary untrusted network
                // input and must not terminate the sole receive loop. Only an
                // AuthenticationFailed value has touched the connection's
                // AEAD integrity counter. AeadLimitReached and authenticated
                // protocol violations remain observable above.
                routed_datagram.datagram.deinit(self.allocator);
                owns_datagram = false;
                return .consumed;
            }
            return err;
        } orelse {
            // Closing and draining connections retain their CID routes until
            // the three-PTO expiry, but their packets must not escape as fatal
            // ConnectionClosed errors from the shared receive owner.
            routed_datagram.datagram.deinit(self.allocator);
            owns_datagram = false;
            try self.timers.armFromConnection(
                routed.route.connection_index,
                entry.connection,
            );
            return .consumed;
        };
        errdefer packet.deinit(self.allocator);
        routed_datagram.datagram.deinit(self.allocator);
        owns_datagram = false;
        try self.syncConnectionIdsIfChanged(routed.route.connection_index);
        // Match the blocking and visitor receive paths: ACK processing can
        // declare several older packets lost by the RFC 9002 packet threshold.
        _ = entry.connection.retransmitPacketThresholdLosses(
            one_rtt.max_batch_packets,
        ) catch |err| {
            try self.timers.armFromConnection(
                routed.route.connection_index,
                entry.connection,
            );
            return err;
        };
        try self.timers.armFromConnection(
            routed.route.connection_index,
            entry.connection,
        );
        return .{ .packet = .{
            .connection_handle = routed.route.connection_index,
            .connection_id_sequence = routed.route.sequence_number,
            .packet = packet,
        } };
    }
};

fn isDiscardedShortPacketError(err: anyerror) bool {
    return switch (err) {
        error.AuthenticationFailed,
        error.InvalidInitialPacket,
        error.InvalidHeaderProtectionSample,
        error.InvalidPacketNumber,
        error.InvalidPacketNumberLength,
        => true,
        else => false,
    };
}

fn earliestReceiveTimeout(
    io: std.Io,
    scheduled: ?endpoint_timers.EndpointTimerDeadline,
    caller_deadline: ?std.Io.Clock.Timestamp,
) std.Io.Timeout {
    const timer_deadline: ?std.Io.Clock.Timestamp = if (scheduled) |value| .{
        .clock = .awake,
        .raw = .fromNanoseconds(
            std.math.cast(i96, value.timer.deadline_ns) orelse
                std.math.maxInt(i96),
        ),
    } else null;
    if (timer_deadline) |timer| {
        if (caller_deadline) |caller| {
            // Relative `std.Io.Timeout` callers may choose another clock.
            // Compare remaining durations rather than unrelated timestamp
            // epochs, while the explicit deadline API stays awake-only.
            return .{ .deadline = if (timer.durationFromNow(io).raw.nanoseconds <
                caller.durationFromNow(io).raw.nanoseconds)
                timer
            else
                caller };
        }
        return .{ .deadline = timer };
    }
    return if (caller_deadline) |deadline|
        .{ .deadline = deadline }
    else
        .none;
}

fn monotonicNowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

fn containsConnectionId(
    registered: []const connection_router.ConnectionIdKey,
    candidate: connection_router.ConnectionIdKey,
) bool {
    for (registered) |key| {
        if (connection_router.Context.eql(.{}, key, candidate)) return true;
    }
    return false;
}

fn containsConnectionHandle(
    handles: []const ConnectionHandle,
    handle: ConnectionHandle,
) bool {
    for (handles) |candidate| {
        if (candidate == handle) return true;
    }
    return false;
}

fn routeMetadataEqual(
    cached: ?connection_router.Route,
    current: connection_router.Route,
) bool {
    const previous = cached orelse return false;
    return previous.connection_index == current.connection_index and
        previous.sequence_number == current.sequence_number and
        std.meta.eql(previous.peer_address, current.peer_address) and
        previous.active_migration_disabled ==
            current.active_migration_disabled and
        previous.accept_zero_fixed_bit == current.accept_zero_fixed_bit;
}

fn containsActiveId(
    active: []const quic.connection_id.LocalPool.ActiveId,
    registered: connection_router.ConnectionIdKey,
) bool {
    for (active) |id| {
        if (std.mem.eql(u8, id.connection_id, registered.slice())) return true;
    }
    return false;
}

fn classifyUnrouted(datagram: runtime.OwnedBytes) Event {
    if (datagram.bytes.len == 0 or (datagram.bytes[0] & 0x80) == 0) {
        return .{ .unrouted = .{
            .datagram = datagram,
            .kind = .unknown_short_header,
        } };
    }
    const info = quic.protection.peekProtectedLongPacketInfo(
        datagram.bytes,
    ) catch return .{ .unrouted = .{
        .datagram = datagram,
        .kind = .malformed_long_header,
    } };
    if (info.packet_type != .initial) {
        return .{ .unrouted = .{
            .datagram = datagram,
            .kind = .non_initial_long_header,
        } };
    }
    // RFC 9000 requires the UDP datagram containing a client Initial to be at
    // least 1200 bytes and the first Initial DCID to contain at least 8 bytes.
    // Enforce both before an attacker can consume handshake/admission state.
    if (datagram.bytes.len < quic.initial_exchange.min_initial_udp_datagram_size or
        info.destination_connection_id.len < 8)
    {
        return .{ .unrouted = .{
            .datagram = datagram,
            .kind = .undersized_initial,
        } };
    }
    return .{ .new_initial = .{
        .datagram = datagram,
        .version = info.version,
        .destination_connection_id = info.destination_connection_id,
        .source_connection_id = info.source_connection_id,
        .first_packet_len = info.len,
    } };
}
