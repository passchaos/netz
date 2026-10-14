//! Bounded authority-keyed pool for negotiated HTTP/1.1 and HTTP/2 clients.
//!
//! A connection is negotiated exactly once, then retained with its selected
//! protocol. The total budget covers idle, leased, and connecting sockets;
//! waiters use intrusive FIFO admission so a newly arriving caller cannot
//! bypass an older capacity wait.

const std = @import("std");
const client = @import("client.zig");
const deadline_policy = @import("../internal/deadline.zig");
const fifo_admission = @import("../internal/fifo_admission.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http3 = @import("../http3/mod.zig");
const origin_pool = @import("../http3/origin_pool.zig");
const request_ops = @import("client_pool/requests.zig");
const pool_tickets = @import("client_pool/tickets.zig");
const h3_support = @import("client_pool/http3.zig");
const http3_runtime = @import("../http3/runtime.zig");
const alt_svc_cache = @import("alt_svc_cache.zig");
const tls_stream = @import("../tls/mod.zig").stream;

pub const Error = client.Error || http3_runtime.Error ||
    http3_runtime.HandshakeClientPoolError || alt_svc_cache.Error || error{
    PoolClosed,
    ConnectionLimitReached,
    InvalidPoolOptions,
};
pub const OperationError = Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub const Options = struct {
    /// Maximum sockets owned by the pool, including idle entries, leases, and
    /// connection attempts. Zero is unbounded.
    max_connections: usize = 64,
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

pub const Stats = origin_pool.Stats;
const IdlePool = origin_pool.Pool(client.Connection);

pub const Pool = struct {
    pub const RequestOperationError = OperationError;

    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: IdlePool,
    connections: usize = 0,
    capacity_waiters: fifo_admission.Queue = .{},
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
        const http3_state = if (options.http3) |http3_options|
            try h3_support.State.create(allocator, io, http3_options)
        else
            null;
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
            .http3 = http3_state,
        };
    }

    pub fn deinit(self: *Pool) void {
        // Leases and in-flight acquisitions retain a pointer to this pool and
        // must finish before destruction.
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count() == 0);
        self.idle.deinit();
        self.tickets.deinit();
        if (self.http3) |state| state.deinit();
        self.* = undefined;
    }

    /// Reject new acquisitions and close all idle connections. Existing
    /// leases remain valid but are closed instead of pooled when returned.
    pub fn close(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        self.closed = true;
        while (self.idle.takeOldest()) |connection_value| {
            var connection = connection_value;
            connection.close();
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
        }
        self.capacity_waiters.notifyAll(self.io);
        self.mutex.unlock(self.io);
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
        return self.acquireMaybeBefore(
            uri_text,
            &key,
            &key_owned,
            null,
            null,
            isolate_origin_state,
        ) catch |err| switch (err) {
            error.Timeout,
            error.Canceled,
            error.ConcurrencyUnavailable,
            => unreachable,
            else => |other| return @errorCast(other),
        };
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
        var waiter: fifo_admission.Queue.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);
        while (true) {
            return self.acquireMaybeBefore(
                uri_text,
                &key,
                &key_owned,
                &waiter,
                deadline,
                isolate_origin_state,
            ) catch |err| switch (err) {
                error.ConnectionLimitReached => {
                    waiter.waitUntil(self.io, deadline) catch |wait_err| switch (wait_err) {
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
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.idleCount();
    }

    pub fn idleCountForUri(self: *Pool, uri_text: []const u8) Error!usize {
        var key = try originKeyForUri(self.allocator, uri_text);
        defer key.deinit();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.idleCountForOrigin(key.origin());
    }

    pub fn connectionCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.connections;
    }

    pub fn waitingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.capacity_waiters.count();
    }

    pub fn stats(self: *Pool) Stats {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        return self.idle.stats();
    }

    pub fn pruneExpired(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pruneExpiredLocked(nowMilliseconds(self.io));
    }

    pub fn altSvcStats(self: *Pool) ?alt_svc_cache.Stats {
        const state = self.http3 orelse return null;
        return state.cache.stats();
    }

    pub fn http3ConnectionCount(self: *Pool) usize {
        const state = self.http3 orelse return 0;
        return state.pool.connectionCount();
    }

    pub fn http3IdleCount(self: *Pool) usize {
        const state = self.http3 orelse return 0;
        return state.pool.idleCount();
    }

    fn acquireMaybeBefore(
        self: *Pool,
        uri_text: []const u8,
        key: *http3.OriginKey,
        key_owned: *bool,
        waiter: ?*fifo_admission.Queue.Waiter,
        deadline: ?std.Io.Clock.Timestamp,
        isolate_origin_state: bool,
    ) OperationError!Lease {
        var displaced: ?client.Connection = null;
        self.mutex.lockUncancelable(self.io);
        if (self.closed) {
            if (waiter) |queued| _ = self.capacity_waiters.remove(queued);
            self.mutex.unlock(self.io);
            return error.PoolClosed;
        }
        if (!self.capacity_waiters.mayAttempt(waiter)) {
            if (waiter) |queued| {
                if (!queued.linked) {
                    self.capacity_waiters.enqueue(queued);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            self.mutex.unlock(self.io);
            return error.ConnectionLimitReached;
        }
        _ = self.pruneExpiredLocked(nowMilliseconds(self.io));
        if (self.idle.acquire(key.origin(), nowMilliseconds(self.io))) |connection| {
            self.finishAdmissionLocked(waiter);
            self.mutex.unlock(self.io);
            const owned_key = key.*;
            key_owned.* = false;
            return .{
                .pool = self,
                .connection_value = connection,
                .origin_key = owned_key,
                .was_reused = true,
            };
        }
        if (self.options.max_connections != 0 and
            self.connections >= self.options.max_connections)
        {
            if (self.idle.idleCount() == 0) {
                if (waiter) |queued| {
                    if (!queued.linked) {
                        self.capacity_waiters.enqueue(queued);
                    } else {
                        queued.rearm();
                    }
                }
                self.mutex.unlock(self.io);
                return error.ConnectionLimitReached;
            }
            displaced = self.idle.takeOldest();
        } else {
            self.connections += 1;
        }
        self.finishAdmissionLocked(waiter);
        self.mutex.unlock(self.io);
        if (displaced) |connection_value| {
            var connection = connection_value;
            connection.close();
        }
        var reserved = true;
        errdefer if (reserved) self.releaseConnectionSlot();

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
            .origin_key = owned_key,
        };
    }

    fn release(
        self: *Pool,
        connection_value: client.Connection,
        origin_key_value: http3.OriginKey,
        reusable: bool,
    ) void {
        var connection = connection_value;
        var origin_key = origin_key_value;
        if (std.ascii.eqlIgnoreCase(origin_key.scheme, "https")) {
            _ = self.tickets.rememberTls13(
                origin_key.host,
                origin_key.port,
                &connection,
            ) catch {
                self.tickets.removeTls13ForConnection(
                    origin_key.host,
                    origin_key.port,
                    &connection,
                );
            };
        }
        if (!reusable) {
            connection.close();
            origin_key.deinit();
            self.releaseConnectionSlot();
            return;
        }
        self.mutex.lockUncancelable(self.io);
        if (self.closed) {
            self.tickets.removeForConnection(
                origin_key.host,
                origin_key.port,
                &connection,
            );
            connection.close();
            origin_key.deinit();
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);
            return;
        }
        const before = self.idle.idleCount();
        self.idle.releaseKey(
            connection,
            origin_key,
            nowMilliseconds(self.io),
        ) catch {
            connection.close();
            const after = self.idle.idleCount();
            const closed_count = before + 1 - after;
            std.debug.assert(self.connections >= closed_count);
            self.connections -= closed_count;
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);
            return;
        };
        const after = self.idle.idleCount();
        const closed_count = before + 1 - after;
        std.debug.assert(self.connections >= closed_count);
        self.connections -= closed_count;
        if (closed_count != 0 or self.hasCapacityLocked()) {
            self.notifyCapacityWaiterLocked();
        }
        self.mutex.unlock(self.io);
    }

    fn releaseConnectionSlot(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.connections != 0);
        self.connections -= 1;
        self.notifyCapacityWaiterLocked();
        self.mutex.unlock(self.io);
    }

    fn finishAdmissionLocked(
        self: *Pool,
        waiter: ?*fifo_admission.Queue.Waiter,
    ) void {
        if (waiter) |queued| {
            if (queued.linked) {
                std.debug.assert(self.capacity_waiters.remove(queued));
            }
        }
        if (self.hasCapacityLocked()) self.notifyCapacityWaiterLocked();
    }

    fn cancelCapacityWaiter(
        self: *Pool,
        waiter: *fifo_admission.Queue.Waiter,
    ) void {
        self.mutex.lockUncancelable(self.io);
        self.capacity_waiters.cancel(waiter, self.io);
        self.mutex.unlock(self.io);
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
        const removed = self.idle.pruneExpired(now_ms);
        std.debug.assert(self.connections >= removed);
        self.connections -= removed;
        if (removed != 0) self.notifyCapacityWaiterLocked();
        return removed;
    }
};

pub const Lease = struct {
    pool: *Pool,
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
        );
        self.connection_value = undefined;
        self.origin_key = undefined;
    }

    pub fn discard(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.connection_value.close();
        self.origin_key.deinit();
        self.pool.releaseConnectionSlot();
        self.connection_value = undefined;
        self.origin_key = undefined;
    }
};

fn dropConnection(_: std.mem.Allocator, connection_value: client.Connection) void {
    var connection = connection_value;
    connection.close();
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
