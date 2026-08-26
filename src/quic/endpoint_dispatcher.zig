//! Endpoint-wide dispatch for established QUIC connections.
//!
//! A QUIC UDP socket has one receive owner. Datagrams are routed by Destination
//! Connection ID before they enter connection state, and the same owner keeps
//! the aggregate timer schedule synchronized after every receive/send turn.
//! This avoids the incorrect but tempting design where connection tasks race
//! to read a shared UDP socket and discard one another's packets.

const std = @import("std");
const quic = @import("mod.zig");
const connection_router = @import("connection_router.zig");
const endpoint_timers = @import("endpoint_timers.zig");
const one_rtt = @import("one_rtt.zig");
const runtime = @import("runtime.zig");

test {
    _ = @import("endpoint_dispatcher/tests.zig");
}

pub const ConnectionHandle = usize;

pub const Error = runtime.Error || one_rtt.Error ||
    connection_router.Error || endpoint_timers.Error || error{
    DuplicateConnectionHandle,
    UnknownConnectionHandle,
    ConnectionEndpointMismatch,
    StaleConnectionRoute,
};
pub const ReceiveError = Error || runtime.ReceiveTimeoutError;

const ConnectionEntry = struct {
    connection: *one_rtt.Connection,
    connection_ids: std.ArrayList(connection_router.ConnectionIdKey) = .empty,

    fn deinit(self: *ConnectionEntry, allocator: std.mem.Allocator) void {
        self.connection_ids.deinit(allocator);
        self.* = undefined;
    }
};

pub const RoutedPacket = struct {
    connection_handle: ConnectionHandle,
    connection_id_sequence: u64,
    packet: one_rtt.ReceivedPacket,
};

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
            .consumed, .timer, .discarded_long_header => {},
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

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *runtime.Endpoint,
    ) Dispatcher {
        return .{
            .allocator = allocator,
            .endpoint = endpoint,
            .router = .init(allocator),
            .timers = .init(allocator),
        };
    }

    /// Release dispatcher metadata without deinitializing caller-owned QUIC
    /// connections or the shared UDP endpoint. Connections must be unregistered
    /// before their storage moves or is destroyed.
    pub fn deinit(self: *Dispatcher) void {
        var iterator = self.connections.valueIterator();
        while (iterator.next()) |entry| entry.deinit(self.allocator);
        self.connections.deinit(self.allocator);
        self.router.deinit();
        self.timers.deinit();
        self.* = undefined;
    }

    pub fn registerConnection(
        self: *Dispatcher,
        handle: ConnectionHandle,
        connection: *one_rtt.Connection,
    ) Error!void {
        if (connection.endpoint != self.endpoint) {
            return error.ConnectionEndpointMismatch;
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
        const slot = try self.connections.getOrPut(self.allocator, handle);
        if (slot.found_existing) return error.DuplicateConnectionHandle;
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

    /// Own the next UDP receive, answer unsupported versions, and either route
    /// an established packet or transfer an unknown-CID datagram to admission.
    /// The caller owns the returned event and must call `Event.deinit`.
    pub fn receive(
        self: *Dispatcher,
        supported_versions: []const u32,
    ) ReceiveError!Event {
        while (true) {
            if (try self.serviceDueTimer()) |timer| {
                return .{ .timer = timer };
            }
            const timeout: std.Io.Timeout = if (self.timers.earliestDeadline()) |scheduled| .{ .deadline = .{
                .clock = .awake,
                .raw = .fromNanoseconds(
                    std.math.cast(i96, scheduled.timer.deadline_ns) orelse
                        std.math.maxInt(i96),
                ),
            } } else .none;
            var datagram = self.endpoint.receiveBytesTimeout(timeout) catch |err|
                switch (err) {
                    error.Timeout => continue,
                    // A backend without timed network waits remains usable
                    // when no transport timer is armed. Once a connection has
                    // a deadline, falling back to an unbounded receive would
                    // silently starve PTO/ACK/idle work.
                    error.ConcurrencyUnavailable => if (timeout == .none)
                        try self.endpoint.receiveBytes()
                    else
                        return error.ConcurrencyUnavailable,
                    else => |other| return other,
                };
            errdefer datagram.deinit(self.allocator);
            if (try self.endpoint.sendVersionNegotiationIfUnsupported(
                datagram.from,
                datagram.bytes,
                supported_versions,
            )) {
                datagram.deinit(self.allocator);
                continue;
            }
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
        var packet = try entry.connection.receiveRoutedDatagram(
            routed_datagram,
        );
        errdefer packet.deinit(self.allocator);
        routed_datagram.datagram.deinit(self.allocator);
        owns_datagram = false;
        try self.syncConnectionIds(routed.route.connection_index);
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

fn containsConnectionId(
    registered: []const connection_router.ConnectionIdKey,
    candidate: connection_router.ConnectionIdKey,
) bool {
    for (registered) |key| {
        if (connection_router.Context.eql(.{}, key, candidate)) return true;
    }
    return false;
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
