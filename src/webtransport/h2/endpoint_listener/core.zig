//! Listener, connection-slot, admission-queue, and worker ownership core.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const h2_state = @import("../state.zig");
const runtime = @import("../runtime.zig");
const endpoint = @import("../endpoint_server.zig");
const timed_mutex = @import("../../../internal/timed_mutex.zig");

pub const Event = endpoint.Event;
pub const KeyingMaterial = endpoint.KeyingMaterial;
pub const Error = endpoint.Error || error{
    ListenerClosed,
    StaleConnection,
    InvalidListenerOptions,
};

pub const Options = struct {
    max_connections: usize = 64,
    max_pending_requests: usize = 256,
    accept_workers: usize = 4,
    accept_failure_backoff: std.Io.Duration = .fromMilliseconds(10),
    endpoint: endpoint.Options = .{},

    pub fn validate(self: Options) Error!void {
        if (self.max_connections == 0 or
            self.max_connections > std.math.maxInt(u32) or
            self.max_pending_requests == 0 or
            self.accept_workers == 0 or
            self.accept_workers > self.max_connections or
            self.accept_failure_backoff.nanoseconds <= 0)
        {
            return error.InvalidListenerOptions;
        }
        try self.endpoint.validate();
    }
};

pub const ConnectionHandle = struct {
    index: u32,
    generation: u64,
};

pub const Handle = struct {
    connection: ConnectionHandle,
    session: endpoint.Handle,
};

pub const Accepted = struct {
    allocator: std.mem.Allocator,
    handle: Handle,
    selected_protocol: ?[]u8,

    pub fn applicationProtocol(self: Accepted) ?[]const u8 {
        return self.selected_protocol;
    }

    pub fn deinit(self: *Accepted) void {
        if (self.selected_protocol) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

pub const OwnedListener = union(enum) {
    cleartext: http2.runtime.Server,
    tls: http2.runtime.TlsServer,

    pub fn io(self: *const OwnedListener) std.Io {
        return switch (self.*) {
            .cleartext => |*value| value.io,
            .tls => |*value| value.io,
        };
    }

    pub fn address(self: *const OwnedListener) std.Io.net.IpAddress {
        return switch (self.*) {
            .cleartext => |value| value.address(),
            .tls => |value| value.address(),
        };
    }

    fn accept(self: *OwnedListener) http2.runtime.Error!http2.runtime.Connection {
        return switch (self.*) {
            .cleartext => |*value| value.accept(),
            .tls => |*value| value.accept(),
        };
    }

    pub fn deinit(self: *OwnedListener) void {
        switch (self.*) {
            .cleartext => |*value| value.deinit(),
            .tls => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

pub const ManagedConnection = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    server: endpoint.EndpointServer,

    fn create(
        allocator: std.mem.Allocator,
        connection: http2.runtime.Connection,
        options: endpoint.Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*ManagedConnection {
        var owned_connection = connection;
        var connection_owned = true;
        errdefer if (connection_owned) owned_connection.closeWithoutCloseNotify();
        _ = try @import("../../../internal/deadline.zig").usableAwake(owned_connection.io, deadline);
        try owned_connection.io.checkCancel();
        const self = try allocator.create(ManagedConnection);
        errdefer allocator.destroy(self);
        connection_owned = false;
        const server = try endpoint.EndpointServer.initWithDeadline(
            allocator,
            owned_connection,
            options,
            deadline,
        );
        self.* = .{
            .allocator = allocator,
            .server = server,
        };
        return self;
    }

    fn retain(self: *ManagedConnection) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *ManagedConnection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.server.deinit();
        self.allocator.destroy(self);
    }
};

pub const ConnectionSlot = struct {
    generation: u64 = 1,
    reserved: bool = false,
    connection: ?*ManagedConnection = null,
};

pub const QueuedRequest = struct {
    connection_handle: ConnectionHandle,
    connection: *ManagedConnection,
    request: endpoint.PendingRequest,

    fn deinit(self: *QueuedRequest) void {
        self.request.deinit();
        self.connection.release();
        self.* = undefined;
    }
};

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    refs: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    group: std.Io.Group = .init,
    listener: OwnedListener,
    connections: []ConnectionSlot,
    requests: []?QueuedRequest,
    request_head: usize = 0,
    request_tail: usize = 0,
    request_count: usize = 0,
    request_ready: std.Io.Event = .unset,
    request_space: std.Io.Event = .unset,
    capacity_ready: std.Io.Event = .unset,
    closed: bool = false,
    stopped: bool = false,

    const Reservation = struct {
        index: u32,
        generation: u64,
    };

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.stopped);
        std.debug.assert(self.request_count == 0);
        for (self.connections) |slot| {
            std.debug.assert(!slot.reserved and slot.connection == null);
        }
        self.allocator.free(self.requests);
        self.allocator.free(self.connections);
        self.allocator.destroy(self);
    }

    pub fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
    }

    pub fn unlock(self: *State) void {
        self.mutex.unlock(self.io);
    }

    fn reserveConnection(self: *State) Error!Reservation {
        while (true) {
            self.lock();
            if (self.closed) {
                self.unlock();
                return error.ListenerClosed;
            }
            for (self.connections, 0..) |*slot, index| {
                if (slot.reserved or slot.connection != null) continue;
                slot.reserved = true;
                const result = Reservation{
                    .index = @intCast(index),
                    .generation = slot.generation,
                };
                self.unlock();
                return result;
            }
            self.capacity_ready.reset();
            self.unlock();
            try self.capacity_ready.wait(self.io);
        }
    }

    fn releaseReservation(self: *State, reservation: Reservation) void {
        self.lock();
        const slot = &self.connections[reservation.index];
        if (slot.generation == reservation.generation and
            slot.reserved and slot.connection == null)
        {
            slot.reserved = false;
            slot.generation +%= 1;
            self.capacity_ready.set(self.io);
        }
        self.unlock();
    }

    fn installConnection(
        self: *State,
        reservation: Reservation,
        connection: *ManagedConnection,
    ) bool {
        self.lock();
        defer self.unlock();
        if (self.closed) return false;
        const slot = &self.connections[reservation.index];
        if (slot.generation != reservation.generation or
            !slot.reserved or slot.connection != null)
        {
            return false;
        }
        slot.reserved = false;
        slot.connection = connection;
        return true;
    }

    fn connectionStopped(
        self: *State,
        handle: ConnectionHandle,
        connection: *ManagedConnection,
    ) void {
        var removed = false;
        self.lock();
        const slot = &self.connections[handle.index];
        if (slot.generation == handle.generation and
            slot.connection == connection)
        {
            slot.connection = null;
            slot.reserved = false;
            slot.generation +%= 1;
            removed = true;
            self.capacity_ready.set(self.io);
        }
        const closing = self.closed;
        self.unlock();
        if (closing) connection.server.requestShutdown();
        if (removed) connection.release();
    }

    fn publishRequest(
        self: *State,
        handle: ConnectionHandle,
        connection: *ManagedConnection,
        request: endpoint.PendingRequest,
    ) Error!void {
        while (true) {
            self.lock();
            if (self.closed) {
                self.unlock();
                return error.ListenerClosed;
            }
            if (self.request_count < self.requests.len) {
                connection.retain();
                self.requests[self.request_tail] = .{
                    .connection_handle = handle,
                    .connection = connection,
                    .request = request,
                };
                self.request_tail = (self.request_tail + 1) % self.requests.len;
                self.request_count += 1;
                self.request_ready.set(self.io);
                self.unlock();
                return;
            }
            self.request_space.reset();
            self.unlock();
            try self.request_space.wait(self.io);
        }
    }

    pub fn takeRequest(
        self: *State,
        deadline: std.Io.Clock.Timestamp,
    ) Error!QueuedRequest {
        while (true) {
            try timed_mutex.lock(&self.mutex, self.io, deadline);
            self.io.checkCancel() catch |err| {
                self.unlock();
                return err;
            };
            if (self.closed) {
                self.unlock();
                return error.ListenerClosed;
            }
            if (self.request_count != 0) {
                const value = self.requests[self.request_head].?;
                self.requests[self.request_head] = null;
                self.request_head = (self.request_head + 1) % self.requests.len;
                self.request_count -= 1;
                if (self.request_count == 0) self.request_ready.reset();
                self.request_space.set(self.io);
                self.unlock();
                return value;
            }
            self.request_ready.reset();
            self.unlock();
            self.request_ready.waitTimeout(
                self.io,
                .{ .deadline = deadline },
            ) catch |err| {
                if (err == error.Timeout and
                    deadline.durationFromNow(self.io).raw.nanoseconds > 0)
                {
                    continue;
                }
                return err;
            };
        }
    }

    pub fn acquireConnection(
        self: *State,
        handle: ConnectionHandle,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*ManagedConnection {
        try timed_mutex.lock(&self.mutex, self.io, deadline);
        defer self.unlock();
        try self.io.checkCancel();
        if (self.closed) return error.ListenerClosed;
        if (handle.index >= self.connections.len) return error.StaleConnection;
        const slot = &self.connections[handle.index];
        if (slot.generation != handle.generation) return error.StaleConnection;
        const connection = slot.connection orelse return error.StaleConnection;
        connection.retain();
        return connection;
    }

    fn close(self: *State) void {
        self.lock();
        defer self.unlock();
        if (self.closed) return;
        self.closed = true;
        self.request_ready.set(self.io);
        self.request_space.set(self.io);
        self.capacity_ready.set(self.io);
        for (self.connections) |slot| {
            if (slot.connection) |connection| {
                connection.server.requestShutdown();
            }
        }
    }

    pub fn stop(self: *State) void {
        self.close();
        self.group.cancel(self.io);
        self.listener.deinit();
        while (true) {
            self.lock();
            if (self.request_count == 0) {
                self.stopped = true;
                self.unlock();
                break;
            }
            var request = self.requests[self.request_head].?;
            self.requests[self.request_head] = null;
            self.request_head = (self.request_head + 1) % self.requests.len;
            self.request_count -= 1;
            self.unlock();
            request.deinit();
        }
    }
};

pub fn acceptLoop(state: *State) std.Io.Cancelable!void {
    while (true) {
        const reservation = state.reserveConnection() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        var reserved = true;
        defer if (reserved) state.releaseReservation(reservation);
        const raw = state.listener.accept() catch |err| {
            state.releaseReservation(reservation);
            reserved = false;
            state.lock();
            const closed = state.closed;
            state.unlock();
            if (closed or err == error.Canceled) return;
            if (state.options.accept_failure_backoff.nanoseconds > 0) {
                try std.Io.sleep(
                    state.io,
                    state.options.accept_failure_backoff,
                    .awake,
                );
            }
            continue;
        };
        var raw_owned = true;
        errdefer if (raw_owned) {
            var abandoned = raw;
            abandoned.close();
        };
        const connection = ManagedConnection.create(
            state.allocator,
            raw,
            state.options.endpoint,
            .fromNow(state.io, .{ .clock = .awake, .raw = state.options.endpoint.operation_timeout }),
        ) catch |err| {
            raw_owned = false;
            state.releaseReservation(reservation);
            reserved = false;
            if (err == error.Canceled) return error.Canceled;
            continue;
        };
        raw_owned = false;
        if (!state.installConnection(reservation, connection)) {
            connection.release();
            state.releaseReservation(reservation);
            reserved = false;
            return;
        }
        reserved = false;
        const handle = ConnectionHandle{
            .index = reservation.index,
            .generation = reservation.generation,
        };
        connection.retain();
        state.group.concurrent(
            state.io,
            connectionLoop,
            .{ state, handle, connection },
        ) catch {
            state.connectionStopped(handle, connection);
            connection.release();
        };
    }
}

fn connectionLoop(
    state: *State,
    handle: ConnectionHandle,
    connection: *ManagedConnection,
) std.Io.Cancelable!void {
    defer {
        state.connectionStopped(handle, connection);
        connection.release();
    }
    while (true) {
        var request = connection.server.receiveRequestWithTimeout(
            .fromSeconds(24 * 60 * 60),
        ) catch |err| switch (err) {
            error.Timeout => continue,
            error.Canceled => return error.Canceled,
            else => return,
        };
        var owned = true;
        defer if (owned) request.deinit();
        state.publishRequest(handle, connection, request) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        owned = false;
    }
}
