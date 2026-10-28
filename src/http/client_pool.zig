//! Bounded authority-keyed pool for negotiated HTTP/1.1 and HTTP/2 clients.
//!
//! A connection is negotiated exactly once, then retained with its selected
//! protocol. The total budget covers idle, leased, and connecting sockets;
//! waiters use intrusive FIFO admission so a newly arriving caller cannot
//! bypass an older capacity wait.

const std = @import("std");
const client = @import("client.zig");
const deadline_policy = @import("../internal/deadline.zig");
const MutexGuard = @import("../internal/mutex_guard.zig").Guard;
const owned_admission = @import("../internal/owned_fifo_admission.zig");
const retired_capacity = @import("../internal/retired_capacity.zig");
const pool_returns = @import("../internal/pool_returns.zig");
const connection_budget = @import("../internal/connection_budget.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http3 = @import("../http3/mod.zig");
const origin_pool = @import("../http3/origin_pool.zig");
const request_ops = @import("client_pool/requests.zig");
const pool_tickets = @import("client_pool/tickets.zig");
const return_tickets = @import("../internal/pool_returns/tickets.zig");
const timed_mutex = @import("../internal/timed_mutex.zig");
const h3_support = @import("client_pool/http3.zig");
const http3_runtime = @import("../http3/runtime.zig");
const alt_svc_cache = @import("alt_svc_cache.zig");
const tls_stream = @import("../tls/mod.zig").stream;

pub const Error = client.Error || http3_runtime.Error ||
    http3_runtime.HandshakeClientPoolError ||
    http3_runtime.HandshakeClientPoolSharedError ||
    http3_runtime.SharedHandshakeClientPoolRequestError ||
    alt_svc_cache.Error || error{
    PoolClosed,
    ConnectionLimitReached,
    InvalidPoolOptions,
};
pub const OperationError = Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub const Options = struct {
    /// Maximum sockets owned by the pool, including idle entries, leases, and
    /// connection attempts in the TCP backend. Zero is unbounded.
    max_connections: usize = 64,
    /// Maximum connections across the TCP and optional HTTP/3 backends,
    /// including idle entries, leases, and connection attempts. Zero is
    /// unbounded. Per-backend limits still apply independently.
    max_total_connections: usize = 0,
    max_idle_connections: usize = 32,
    max_idle_per_origin: usize = 8,
    /// Null disables age-based eviction.
    idle_timeout: ?std.Io.Duration = .fromSeconds(90),
    client: client.Options = .{},
    /// Maximum cached RFC 5077 TLS 1.2 tickets across origin/ALPN keys.
    max_tls12_session_tickets: usize = 32,
    /// Maximum cached RFC 8446 TLS 1.3 tickets across origin/ALPN keys.
    max_tls13_session_tickets: usize = 32,
    /// Enable Alt-Svc-driven HTTP/3 with an explicit QUIC/TLS policy. Null
    /// preserves the H1/H2-only behavior and never creates a UDP socket.
    http3: ?h3_support.Options = null,
};

pub const Http3Options = h3_support.Options;
pub const Http3FallbackPolicy = h3_support.FallbackPolicy;
pub const Http3EarlyDataOptions = h3_support.EarlyDataOptions;
pub const Http3RememberedSettingsStats = h3_support.RememberedSettingsStats;

pub const Stats = origin_pool.Stats;
const ReturnPayload = struct {
    connection_value: client.Connection,
    origin_key: http3.OriginKey,
    reusable: bool,
    returned_at_ms: u64,
};
const ReturnQueue = pool_returns.Queue(ReturnPayload);
const IdleConnection = struct {
    connection_value: client.Connection,
    return_node: *ReturnQueue.Node,
    fn close(self: *IdleConnection) void {
        self.connection_value.close();
        self.return_node.destroy();
    }
};
const IdlePool = origin_pool.Pool(IdleConnection);

pub const Pool = struct {
    pub const RequestOperationError = OperationError;

    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: IdlePool,
    returns: ReturnQueue = .{},
    connections: usize = 0,
    retired_connections: retired_capacity.Retirements = .{},
    capacity_waiters: owned_admission.Queue = .{},
    shared_budget: *connection_budget.Budget,
    tickets: pool_tickets.Manager,
    http3: ?*h3_support.State,
    closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) Error!Pool {
        if (options.max_idle_per_origin > options.max_idle_connections) {
            return error.InvalidPoolOptions;
        }
        const idle_timeout_ms = if (options.idle_timeout) |timeout| blk: {
            if (timeout.nanoseconds <= 0) return error.InvalidPoolOptions;
            break :blk durationMillisecondsCeil(timeout);
        } else std.math.maxInt(u64);
        // Validate the nested one-shot options at pool construction rather
        // than after a capacity slot has already been reserved.
        var validator = try client.Client.init(allocator, io, options.client);
        validator.deinit();
        const shared_budget = try connection_budget.Budget.create(
            allocator,
            io,
            options.max_total_connections,
        );
        errdefer shared_budget.deinit();
        const http3_state = if (options.http3) |http3_options| blk: {
            var effective_http3 = http3_options;
            if (effective_http3.address_resolver == null) {
                effective_http3.address_resolver =
                    options.client.address_resolver;
            }
            effective_http3.socks5_proxy = options.client.socks5_proxy;
            break :blk try h3_support.State.create(
                allocator,
                io,
                effective_http3,
                shared_budget,
            );
        } else null;
        errdefer if (http3_state) |state| state.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .idle = IdlePool.init(allocator, .{
                .max_idle_per_origin = options.max_idle_per_origin,
                .max_idle_total = options.max_idle_connections,
                .idle_timeout_ms = idle_timeout_ms,
            }, dropConnection),
            .tickets = .init(
                allocator,
                io,
                options.client,
                options.max_tls12_session_tickets,
                options.max_tls13_session_tickets,
            ),
            .shared_budget = shared_budget,
            .http3 = http3_state,
        };
    }

    pub fn deinit(self: *Pool) void {
        // Leases and in-flight acquisitions retain a pointer to this pool and
        // must finish before destruction.
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count(self.io) == 0);
        self.idle.deinit();
        self.tickets.deinit();
        if (self.http3) |state| state.deinit();
        self.shared_budget.deinit();
        self.* = undefined;
    }

    /// Reject new acquisitions and close all idle connections. Existing
    /// leases remain valid but are closed instead of pooled when returned.
    pub fn close(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        self.closed = true;
        var returned = self.returns.close(self.io);
        var returned_count: usize = 0;
        while (returned) |node| {
            returned = node.next;
            var connection = node.value.connection_value;
            var key = node.value.origin_key;
            connection.close();
            key.deinit();
            node.destroy();
            self.connections -= 1;
            returned_count += 1;
        }
        var removed: usize = returned_count;
        while (self.idle.takeOldest()) |connection_value| {
            var connection = connection_value;
            connection.close();
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            removed += 1;
        }
        self.capacity_waiters.notifyAll(self.io);
        self.mutex.unlock(self.io);
        self.shared_budget.close();
        self.shared_budget.release(removed);
        self.tickets.clear();
        if (self.http3) |state| state.close();
    }

    pub fn acquireUri(self: *Pool, uri_text: []const u8) Error!Lease {
        return self.acquireUriWithOriginIsolation(uri_text, false);
    }

    /// Internal redirect hook: clear caller-supplied origin-bound resumption
    /// material before a new cross-origin connection. Per-origin pool caches
    /// remain eligible because their keys already include host and port.
    pub fn acquireUriWithOriginIsolation(
        self: *Pool,
        uri_text: []const u8,
        isolate_origin_state: bool,
    ) Error!Lease {
        var key = try originKeyForUri(self.allocator, uri_text);
        var key_owned = true;
        defer if (key_owned) key.deinit();
        while (true) {
            var blocked_on_shared = false;
            return self.acquireMaybeBefore(
                uri_text,
                &key,
                &key_owned,
                null,
                null,
                &blocked_on_shared,
                null,
                isolate_origin_state,
            ) catch |err| switch (err) {
                error.ConnectionLimitReached => {
                    if (blocked_on_shared and
                        self.reclaimHttp3IdleIfEligible(null))
                    {
                        continue;
                    }
                    return error.ConnectionLimitReached;
                },
                error.Timeout,
                error.Canceled,
                error.ConcurrencyUnavailable,
                => unreachable,
                else => |other| return @errorCast(other),
            };
        }
    }

    pub fn acquireUriWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        timeout: std.Io.Duration,
    ) OperationError!Lease {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acquireUriWithDeadline(
            uri_text,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn acquireUriWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) OperationError!Lease {
        return self.acquireUriWithDeadlineAndOriginIsolation(
            uri_text,
            deadline,
            false,
        );
    }

    pub fn acquireUriWithDeadlineAndOriginIsolation(
        self: *Pool,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
        isolate_origin_state: bool,
    ) OperationError!Lease {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var key = try originKeyForUri(self.allocator, uri_text);
        var key_owned = true;
        defer if (key_owned) key.deinit();
        var waiter: owned_admission.Queue.Waiter = .{};
        var shared_waiter: connection_budget.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);
        defer self.shared_budget.cancel(&shared_waiter);
        while (true) {
            var blocked_on_shared = false;
            return self.acquireMaybeBefore(
                uri_text,
                &key,
                &key_owned,
                &waiter,
                &shared_waiter,
                &blocked_on_shared,
                deadline,
                isolate_origin_state,
            ) catch |err| switch (err) {
                error.ConnectionLimitReached => {
                    if (blocked_on_shared and
                        self.reclaimHttp3IdleIfEligible(&shared_waiter))
                    {
                        continue;
                    }
                    const blocked_waiter = if (blocked_on_shared)
                        &shared_waiter
                    else
                        &waiter;
                    blocked_waiter.waitUntil(self.io, deadline) catch |wait_err| switch (wait_err) {
                        error.Timeout => return error.Timeout,
                        error.Canceled => return error.Canceled,
                    };
                    if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                        return error.Timeout;
                    }
                    continue;
                },
                else => |other| return other,
            };
        }
    }

    pub const requestUri = request_ops.requestUri;
    pub const requestUriWithTimeout = request_ops.requestUriWithTimeout;
    pub const requestUriWithDeadline = request_ops.requestUriWithDeadline;
    pub const requestUriFollowingRedirects =
        request_ops.requestUriFollowingRedirects;
    pub const requestUriFollowingRedirectsDetailed =
        request_ops.requestUriFollowingRedirectsDetailed;
    pub const requestUriFollowingRedirectsWithTimeout =
        request_ops.requestUriFollowingRedirectsWithTimeout;
    pub const requestUriFollowingRedirectsWithDeadline =
        request_ops.requestUriFollowingRedirectsWithDeadline;
    pub const requestUriFollowingRedirectsDetailedWithTimeout =
        request_ops.requestUriFollowingRedirectsDetailedWithTimeout;
    pub const requestUriFollowingRedirectsDetailedWithDeadline =
        request_ops.requestUriFollowingRedirectsDetailedWithDeadline;

    pub fn idleCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.idleCount();
    }

    pub fn idleCountForUri(self: *Pool, uri_text: []const u8) Error!usize {
        var key = try originKeyForUri(self.allocator, uri_text);
        defer key.deinit();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.idleCountForOrigin(key.origin());
    }

    pub fn connectionCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.connections;
    }

    /// Connections owned across TCP and HTTP/3, including idle entries,
    /// active leases, and in-progress connection attempts.
    pub fn totalConnectionCount(self: *Pool) usize {
        return self.shared_budget.connectionCount();
    }

    pub fn waitingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.capacity_waiters.count(self.io);
    }

    pub fn totalWaitingCount(self: *Pool) usize {
        return self.shared_budget.waitingCount();
    }

    pub const Internal = struct {
        /// Split-module HTTP/3 admission hook. The callback target is valid for
        /// one Pool request, during which moving the Pool is forbidden by the
        /// same lease ownership contract as every other operation.
        pub fn tcpIdleReclaimer(
            self: *Pool,
        ) connection_budget.Reclaimer {
            return .{
                .context = self,
                .reclaim = reclaimOldestTcpIdleErased,
            };
        }
    };

    pub fn stats(self: *Pool) Stats {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.stats();
    }

    pub fn pruneExpired(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        return self.pruneExpiredLocked(nowMilliseconds(self.io));
    }

    pub fn altSvcStats(self: *Pool) ?alt_svc_cache.Stats {
        const state = self.http3 orelse return null;
        return state.cache.stats();
    }

    pub fn http3ConnectionCount(self: *Pool) usize {
        const state = self.http3 orelse return 0;
        return state.connectionCount();
    }

    pub fn http3IdleCount(self: *Pool) usize {
        const state = self.http3 orelse return 0;
        return state.idleCount();
    }

    pub fn http3RememberedSettingsStats(
        self: *const Pool,
    ) ?Http3RememberedSettingsStats {
        const state = self.http3 orelse return null;
        return state.rememberedSettingsStats();
    }

    fn acquireMaybeBefore(
        self: *Pool,
        uri_text: []const u8,
        key: *http3.OriginKey,
        key_owned: *bool,
        waiter: ?*owned_admission.Queue.Waiter,
        shared_waiter: ?*connection_budget.Waiter,
        blocked_on_shared: *bool,
        deadline: ?std.Io.Clock.Timestamp,
        isolate_origin_state: bool,
    ) OperationError!Lease {
        blocked_on_shared.* = false;
        var displaced: ?IdleConnection = null;
        var admission_lock = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer admission_lock.unlock();
        try self.collectReturnsBeforeLocked(deadline);
        if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        if (self.closed) {
            if (waiter) |queued| _ = self.capacity_waiters.remove(queued);
            if (shared_waiter) |queued| self.shared_budget.cancel(queued);
            admission_lock.unlock();
            return error.PoolClosed;
        }
        if (!self.capacity_waiters.mayAttempt(waiter, self.io)) {
            if (shared_waiter) |queued| self.shared_budget.cancel(queued);
            if (waiter) |queued| {
                if (!queued.linked) {
                    try self.capacity_waiters.enqueue(queued, self.allocator, self.io);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            try self.collectReturnsBeforeLocked(deadline);
            self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
            admission_lock.unlock();
            return error.ConnectionLimitReached;
        }
        _ = self.pruneExpiredBeforeLocked(nowMilliseconds(self.io), deadline);
        const idle_connection = blk: {
            const drop = self.idle.drop_fn;
            if (deadline != null) self.idle.drop_fn = dropConnectionWithoutCloseNotify;
            defer self.idle.drop_fn = drop;
            break :blk self.idle.acquire(key.origin(), nowMilliseconds(self.io));
        };
        if (idle_connection) |connection| {
            if (shared_waiter) |queued| self.shared_budget.cancel(queued);
            self.finishAdmissionLocked(waiter);
            admission_lock.unlock();
            const owned_key = key.*;
            key_owned.* = false;
            return .{
                .pool = self,
                .connection_value = connection.connection_value,
                .return_node = connection.return_node,
                .origin_key = owned_key,
                .was_reused = true,
            };
        }
        if (self.options.max_connections != 0 and
            self.connections >= self.options.max_connections)
        {
            if (shared_waiter) |queued| self.shared_budget.cancel(queued);
            if (self.idle.idleCount() == 0) {
                if (waiter) |queued| {
                    if (!queued.linked) {
                        try self.capacity_waiters.enqueue(queued, self.allocator, self.io);
                    } else {
                        queued.rearm();
                    }
                }
                try self.collectReturnsBeforeLocked(deadline);
                self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
                admission_lock.unlock();
                return error.ConnectionLimitReached;
            }
            displaced = self.idle.takeOldest();
        } else {
            self.shared_budget.tryReserveBefore(shared_waiter, deadline) catch |err| switch (err) {
                error.ConnectionLimitReached => {
                    if (self.idle.takeOldest()) |connection| {
                        if (shared_waiter) |queued| {
                            self.shared_budget.cancel(queued);
                        }
                        displaced = connection;
                    } else {
                        blocked_on_shared.* = true;
                        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
                        admission_lock.unlock();
                        return error.ConnectionLimitReached;
                    }
                },
                error.PoolClosed, error.OutOfMemory, error.Timeout, error.Canceled => {
                    admission_lock.unlock();
                    return err;
                },
            };
            if (displaced == null) {
                self.connections += 1;
            }
        }
        self.finishAdmissionLocked(waiter);
        admission_lock.unlock();
        if (displaced) |connection_value| {
            var connection = connection_value;
            if (deadline != null) {
                connection.connection_value.closeWithoutCloseNotify();
                connection.return_node.destroy();
            } else connection.close();
        }
        var reserved = true;
        errdefer if (reserved) self.releaseConnectionSlot();
        const return_node = try ReturnQueue.Node.create(self.allocator);
        errdefer return_node.destroy();

        const secure = std.ascii.eqlIgnoreCase(key.scheme, "https");
        var tls12_ticket = if (secure and
            self.options.client.tls.protocol_policy.offersTls12())
            try self.tickets.cloneTls12(key.host, key.port)
        else
            null;
        defer if (tls12_ticket) |*ticket| ticket.deinit();
        var tls13_ticket = if (secure and
            self.options.client.tls.protocol_policy.offersTls13() and
            self.options.client.tls.request_tls13_session_ticket)
            try self.tickets.cloneTls13(key.host, key.port)
        else
            null;
        defer if (tls13_ticket) |*ticket| ticket.deinit();
        var connection_options = clientOptionsForOriginIsolation(
            self.options.client,
            isolate_origin_state,
        );
        if (tls12_ticket) |*ticket| {
            connection_options.tls.tls12_ticket_resumption = ticket;
        }
        if (tls13_ticket) |*ticket| {
            connection_options.tls.tls13_ticket_resumption = ticket;
        }
        var connector = try client.Client.init(
            self.allocator,
            self.io,
            connection_options,
        );
        defer connector.deinit();
        var connection = if (deadline) |absolute|
            try connector.connectUriWithDeadline(uri_text, absolute)
        else
            try connector.connectUri(uri_text);
        errdefer connection.close();
        if (secure) {
            self.tickets.rememberTls12(
                key.host,
                key.port,
                &connection,
            );
            const remembered_tls13 = try self.tickets.rememberTls13(
                key.host,
                key.port,
                &connection,
            );
            if (!remembered_tls13 and tls13_ticket != null and
                connection.negotiatedTlsProtocol() == .tls13 and
                !(connection.wasTlsSessionResumed() orelse false))
            {
                self.tickets.removeTls13ForConnection(
                    key.host,
                    key.port,
                    &connection,
                );
            }
        }
        const owned_key = key.*;
        key_owned.* = false;
        reserved = false;
        return .{
            .pool = self,
            .connection_value = connection,
            .return_node = return_node,
            .origin_key = owned_key,
        };
    }

    fn release(
        self: *Pool,
        connection_value: client.Connection,
        origin_key_value: http3.OriginKey,
        reusable: bool,
        return_node: *ReturnQueue.Node,
    ) void {
        return_node.value = .{ .connection_value = connection_value, .origin_key = origin_key_value, .reusable = reusable, .returned_at_ms = nowMilliseconds(self.io) };
        if (self.returns.publish(return_node, self.io)) {
            self.capacity_waiters.notifyRetry(self.io);
            self.shared_budget.notify();
            return;
        }
        var connection = connection_value;
        var key = origin_key_value;
        connection.closeWithoutCloseNotify();
        key.deinit();
        return_node.destroy();
        self.releaseConnectionSlot();
    }

    fn collectReturnsLocked(self: *Pool) void {
        self.collectReturnsBeforeLocked(null) catch unreachable;
    }

    fn collectReturnsBeforeLocked(self: *Pool, deadline: ?std.Io.Clock.Timestamp) timed_mutex.Error!void {
        var current = self.returns.take();
        errdefer self.returns.restore(current);
        while (current) |node| {
            if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
            const payload = &node.value;
            if (std.ascii.eqlIgnoreCase(payload.origin_key.scheme, "https")) {
                try return_tickets.remember(&self.tickets.tls13, &payload.connection_value, payload.origin_key.host, payload.origin_key.port, true, self.io, deadline);
            }
            const next = node.next;
            self.releaseReturnedLocked(payload.connection_value, payload.origin_key, payload.reusable, node, payload.returned_at_ms, deadline);
            current = next;
        }
    }

    fn releaseReturnedLocked(
        self: *Pool,
        connection_value: client.Connection,
        origin_key_value: http3.OriginKey,
        reusable: bool,
        return_node: *ReturnQueue.Node,
        returned_at_ms: u64,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        var connection = connection_value;
        var origin_key = origin_key_value;
        const drop = self.idle.drop_fn;
        if (deadline != null) self.idle.drop_fn = dropConnectionWithoutCloseNotify;
        defer self.idle.drop_fn = drop;
        if (!reusable) {
            if (deadline != null) connection.closeWithoutCloseNotify() else connection.close();
            return_node.destroy();
            origin_key.deinit();
            self.connections -= 1;
            self.shared_budget.release(1);
            self.notifyCapacityWaiterLocked();
            return;
        }
        if (self.closed) {
            self.tickets.removeForConnection(
                origin_key.host,
                origin_key.port,
                &connection,
            );
            if (deadline != null) connection.closeWithoutCloseNotify() else connection.close();
            return_node.destroy();
            origin_key.deinit();
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            self.shared_budget.release(1);
            return;
        }
        const before = self.idle.idleCount();
        self.idle.releaseKey(
            .{ .connection_value = connection, .return_node = return_node },
            origin_key,
            returned_at_ms,
        ) catch {
            if (deadline != null) connection.closeWithoutCloseNotify() else connection.close();
            return_node.destroy();
            const after = self.idle.idleCount();
            const closed_count = before + 1 - after;
            std.debug.assert(self.connections >= closed_count);
            self.connections -= closed_count;
            self.notifyCapacityWaiterLocked();
            self.shared_budget.release(closed_count);
            return;
        };
        const after = self.idle.idleCount();
        const closed_count = before + 1 - after;
        std.debug.assert(self.connections >= closed_count);
        self.connections -= closed_count;
        if (closed_count != 0 or self.hasCapacityLocked()) {
            self.notifyCapacityWaiterLocked();
        }
        if (closed_count != 0) {
            self.shared_budget.release(closed_count);
        } else {
            self.shared_budget.notify();
        }
    }

    fn releaseConnectionSlot(self: *Pool) void {
        self.retired_connections.release(&self.connections, &self.capacity_waiters, &self.mutex, self.io, 1);
        self.shared_budget.release(1);
    }

    fn finishAdmissionLocked(
        self: *Pool,
        waiter: ?*owned_admission.Queue.Waiter,
    ) void {
        if (waiter) |queued| {
            if (queued.linked) {
                std.debug.assert(self.capacity_waiters.remove(queued));
            }
            queued.deinit();
        }
        if (self.hasCapacityLocked()) self.notifyCapacityWaiterLocked();
    }

    fn cancelCapacityWaiter(
        self: *Pool,
        waiter: *owned_admission.Queue.Waiter,
    ) void {
        if (!self.capacity_waiters.abandon(waiter, self.io)) return;
        if (self.mutex.tryLock()) {
            self.capacity_waiters.pruneAbandoned(self.io);
            self.mutex.unlock(self.io);
        }
    }

    fn hasCapacityLocked(self: *const Pool) bool {
        return self.closed or self.idle.idleCount() != 0 or
            self.options.max_connections == 0 or
            self.connections < self.options.max_connections;
    }

    fn notifyCapacityWaiterLocked(self: *Pool) void {
        self.capacity_waiters.notifyHead(self.io);
    }

    fn pruneExpiredLocked(self: *Pool, now_ms: u64) usize {
        return self.pruneExpiredBeforeLocked(now_ms, null);
    }

    fn pruneExpiredBeforeLocked(self: *Pool, now_ms: u64, deadline: ?std.Io.Clock.Timestamp) usize {
        const drop = self.idle.drop_fn;
        if (deadline != null) self.idle.drop_fn = dropConnectionWithoutCloseNotify;
        defer self.idle.drop_fn = drop;
        const removed = self.idle.pruneExpired(now_ms);
        std.debug.assert(self.connections >= removed);
        self.connections -= removed;
        if (removed != 0) self.notifyCapacityWaiterLocked();
        self.shared_budget.release(removed);
        return removed;
    }

    fn reclaimOldestTcpIdleErased(context: *anyopaque) bool {
        const self: *Pool = @ptrCast(@alignCast(context));
        self.mutex.lockUncancelable(self.io);
        self.collectReturnsLocked();
        if (self.closed) {
            self.mutex.unlock(self.io);
            return false;
        }
        const connection_value = self.idle.takeOldest() orelse {
            self.mutex.unlock(self.io);
            return false;
        };
        std.debug.assert(self.connections != 0);
        self.connections -= 1;
        self.notifyCapacityWaiterLocked();
        self.mutex.unlock(self.io);

        var connection = connection_value;
        connection.close();
        self.shared_budget.release(1);
        return true;
    }

    fn reclaimHttp3IdleIfEligible(
        self: *Pool,
        waiter: ?*connection_budget.Waiter,
    ) bool {
        if (!self.shared_budget.mayReclaimFor(waiter)) return false;
        const state = self.http3 orelse return false;
        return state.evictOldestIdle();
    }
};

pub const Lease = struct {
    pool: *Pool,
    return_node: *ReturnQueue.Node,
    connection_value: client.Connection,
    origin_key: http3.OriginKey,
    was_reused: bool = false,
    active: bool = true,

    pub fn connection(self: *Lease) *client.Connection {
        std.debug.assert(self.active);
        return &self.connection_value;
    }

    pub fn protocol(self: *const Lease) client.Protocol {
        std.debug.assert(self.active);
        return self.connection_value.protocol();
    }

    pub fn release(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.pool.release(
            self.connection_value,
            self.origin_key,
            self.connection_value.isReusable(),
            self.return_node,
        );
        self.connection_value = undefined;
        self.origin_key = undefined;
    }

    pub fn discard(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.connection_value.close();
        self.return_node.destroy();
        self.origin_key.deinit();
        self.pool.releaseConnectionSlot();
        self.connection_value = undefined;
        self.origin_key = undefined;
    }
};

fn dropConnection(_: std.mem.Allocator, connection_value: IdleConnection) void {
    var connection = connection_value;
    connection.close();
}

fn dropConnectionWithoutCloseNotify(_: std.mem.Allocator, connection_value: IdleConnection) void {
    var connection = connection_value;
    connection.connection_value.closeWithoutCloseNotify();
    connection.return_node.destroy();
}

fn originKeyForUri(
    allocator: std.mem.Allocator,
    uri_text: []const u8,
) Error!http3.OriginKey {
    const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
    const scheme: []const u8 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        "https"
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "http"))
        "http"
    else
        return error.UnsupportedScheme;
    var endpoint = try http1_runtime.uriEndpoint(
        allocator,
        uri,
        if (std.mem.eql(u8, scheme, "https")) 443 else 80,
    );
    defer endpoint.deinit();
    const owned_scheme = try allocator.dupe(u8, scheme);
    errdefer allocator.free(owned_scheme);
    const owned_host = try allocator.alloc(u8, endpoint.tls_host.len);
    errdefer allocator.free(owned_host);
    for (endpoint.tls_host, owned_host) |byte, *out| {
        out.* = std.ascii.toLower(byte);
    }
    return .{
        .allocator = allocator,
        .scheme = owned_scheme,
        .host = owned_host,
        .port = endpoint.port,
    };
}

fn durationMillisecondsCeil(duration: std.Io.Duration) u64 {
    const ns: u128 = @intCast(duration.nanoseconds);
    const milliseconds = (ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
    return @intCast(@min(milliseconds, std.math.maxInt(u64)));
}

fn nowMilliseconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(io).toMilliseconds()));
}

fn clientOptionsForOriginIsolation(
    options: client.Options,
    isolate_origin_state: bool,
) client.Options {
    if (!isolate_origin_state) return options;
    var isolated = options;
    isolated.tls.tls12_ticket_resumption = null;
    isolated.tls.tls13_ticket_resumption = null;
    return isolated;
}

test "unified HTTP pool validates idle limits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(error.InvalidPoolOptions, Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{ .max_idle_connections = 1, .max_idle_per_origin = 2 },
    ));
}

test "unified HTTP pool isolates explicit TLS tickets across origins" {
    var tls12: tls_stream.Tls12SessionTicket = undefined;
    var tls13: tls_stream.Tls13SessionTicket = undefined;
    const options: client.Options = .{ .tls = .{
        .tls12_ticket_resumption = &tls12,
        .tls13_ticket_resumption = &tls13,
    } };
    const same_origin = clientOptionsForOriginIsolation(options, false);
    try std.testing.expect(same_origin.tls.tls12_ticket_resumption != null);
    try std.testing.expect(same_origin.tls.tls13_ticket_resumption != null);
    const cross_origin = clientOptionsForOriginIsolation(options, true);
    try std.testing.expect(cross_origin.tls.tls12_ticket_resumption == null);
    try std.testing.expect(cross_origin.tls.tls13_ticket_resumption == null);
}
