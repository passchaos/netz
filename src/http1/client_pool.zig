//! Bounded reusable HTTP/1 client connection pool.
//!
//! The pool has one mutex-protected slot table and leases exclusive Clients to
//! callers for complete request/response exchanges. A total connection budget
//! covers idle, leased, and connecting sockets. Idle connections are keyed by
//! scheme + canonical host + effective port, and stale/non-reusable clients are
//! retired rather than returned to the pool.

const std = @import("std");
const owned_admission = @import("../internal/owned_fifo_admission.zig");
const retired_capacity = @import("../internal/retired_capacity.zig");
const deadline_policy = @import("../internal/deadline.zig");
const MutexGuard = @import("../internal/mutex_guard.zig").Guard;
const tls_stream = @import("../tls/mod.zig").stream;
const tls_ticket_cache = @import("../tls/stream/client_ticket_cache.zig");
const http1 = @import("mod.zig");
const runtime = @import("runtime.zig");
const uri_redirect = @import("runtime/redirect.zig");

pub const Error = runtime.Error || error{
    PoolClosed,
    ConnectionLimitReached,
    InvalidPoolOptions,
};
pub const AcquireTimeoutError = Error || std.Io.Timeout.Error;

pub const Options = struct {
    /// Maximum sockets owned by the pool, including idle entries, checked-out
    /// leases, and connection attempts in progress. Zero keeps the historical
    /// unbounded behavior.
    max_connections: usize = 64,
    max_idle_connections: usize = 32,
    max_idle_per_authority: usize = 8,
    /// Retire connections idle for at least this monotonic duration. Null
    /// disables age-based eviction.
    idle_timeout: ?std.Io.Duration = .fromSeconds(90),
    limits: runtime.Limits = .{},
    tls: runtime.TlsClientOptions = .{},
    /// Select the vail TLS 1.2/1.3 transport for HTTPS pool connections.
    /// Null preserves the standard-library TLS client path.
    vail_tls: ?runtime.VailTlsClientOptions = null,
    /// Maximum cached RFC 5077 TLS 1.2 tickets across HTTPS authorities.
    /// Zero disables automatic ticket retention and resumption.
    max_tls12_session_tickets: usize = 32,
    /// Maximum cached RFC 8446 TLS 1.3 tickets across HTTPS authorities.
    /// Zero disables automatic ticket retention and resumption.
    max_tls13_session_tickets: usize = 32,
};

const Transport = enum { cleartext, tls };

const Slot = struct {
    client: runtime.Client,
    transport: Transport,
    tls_host: []u8,
    port: u16,
    last_used: u64,
    idle_since_ns: i96,

    fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
        self.client.close();
        allocator.free(self.tls_host);
        self.* = undefined;
    }
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: std.ArrayList(Slot) = .empty,
    sequence: u64 = 0,
    connections: usize = 0,
    retired_connections: retired_capacity.Retirements = .{},
    capacity_waiters: owned_admission.Queue = .{},
    tls12_tickets: tls_ticket_cache.Cache,
    tls13_tickets: tls_ticket_cache.Tls13Cache,
    closed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) Error!Pool {
        if (options.max_idle_per_authority > options.max_idle_connections) {
            return error.InvalidPoolOptions;
        }
        if (options.idle_timeout) |timeout| {
            if (timeout.nanoseconds <= 0) return error.InvalidPoolOptions;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .tls12_tickets = .init(
                allocator,
                io,
                options.max_tls12_session_tickets,
            ),
            .tls13_tickets = .init(
                allocator,
                io,
                options.max_tls13_session_tickets,
            ),
        };
    }

    pub fn deinit(self: *Pool) void {
        // All leases must be returned and acquisitions must have finished;
        // both retain a pointer to this object, so destroying it concurrently
        // would violate ownership.
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count(self.io) == 0);
        self.idle.deinit(self.allocator);
        self.tls12_tickets.deinit();
        self.tls13_tickets.deinit();
        self.* = undefined;
    }

    /// Reject new acquisitions and close all currently idle connections.
    /// Outstanding leases remain valid and are closed when returned.
    pub fn close(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        self.closed = true;
        for (self.idle.items) |*slot| slot.deinit(self.allocator);
        std.debug.assert(self.connections >= self.idle.items.len);
        self.connections -= self.idle.items.len;
        self.idle.clearRetainingCapacity();
        self.capacity_waiters.notifyAll(self.io);
        self.mutex.unlock(self.io);
        self.tls12_tickets.clear();
        self.tls13_tickets.clear();
    }

    pub fn requestUri(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
    ) Error!runtime.OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        const default_port: u16 = if (transport == .tls) 443 else 80;
        var endpoint = try runtime.uriEndpoint(
            self.allocator,
            uri,
            default_port,
        );
        defer endpoint.deinit();
        const target = try uriTargetAlloc(self.allocator, uri);
        defer self.allocator.free(target);

        var retry_stale = true;
        while (true) {
            var lease = try self.acquire(transport, endpoint, null);
            defer if (lease.active) lease.discard();
            var options = request_options;
            options.target = target;
            if (options.host == null) options.host = endpoint.authority;
            const response = lease.client().request(options) catch |err| {
                const was_reused = lease.was_reused;
                lease.discard();
                if (retry_stale and was_reused and
                    request_options.method.idempotent() and
                    retryableStaleConnectionError(err))
                {
                    retry_stale = false;
                    continue;
                }
                return err;
            };
            lease.release();
            return response;
        }
    }

    /// Bound capacity admission, any new DNS/TCP/TLS connection, and the
    /// complete HTTP/1 response with one caller-owned deadline. A stale idle
    /// retry reuses the original timestamp rather than receiving a fresh budget.
    pub fn requestUriWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        timeout: std.Io.Duration,
    ) AcquireTimeoutError!runtime.OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriWithDeadline(
            uri_text,
            request_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!runtime.OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        const target = try uriTargetAlloc(self.allocator, uri);
        defer self.allocator.free(target);
        var waiter: owned_admission.Queue.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);

        var retry_stale = true;
        while (true) {
            var lease = try self.acquireUntil(
                transport,
                endpoint,
                &waiter,
                deadline,
            );
            defer if (lease.active) lease.discard();
            var options = request_options;
            options.target = target;
            if (options.host == null) options.host = endpoint.authority;
            const response = lease.client().requestWithDeadline(
                options,
                deadline,
            ) catch |err| {
                const was_reused = lease.was_reused;
                lease.discard();
                if (retry_stale and was_reused and
                    request_options.method.idempotent() and
                    retryableStaleConnectionError(err))
                {
                    retry_stale = false;
                    continue;
                }
                return err;
            };
            lease.release();
            return response;
        }
    }

    pub fn requestUriFollowingRedirects(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
    ) Error!runtime.OwnedResponse {
        var result = try self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request_options,
            policy,
            null,
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailed(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
    ) Error!runtime.RedirectedResponse {
        return self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request_options,
            policy,
            null,
        );
    }

    pub fn requestUriFollowingRedirectsWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!runtime.OwnedResponse {
        var result = try self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request_options,
            policy,
            try deadline_policy.usableAwake(self.io, deadline),
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailedWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!runtime.RedirectedResponse {
        return self.requestUriFollowingRedirectsDetailedBefore(
            uri_text,
            request_options,
            policy,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    pub fn requestUriFollowingRedirectsWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
        timeout: std.Io.Duration,
    ) AcquireTimeoutError!runtime.OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsWithDeadline(
            uri_text,
            request_options,
            policy,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsDetailedWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
        timeout: std.Io.Duration,
    ) AcquireTimeoutError!runtime.RedirectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsDetailedWithDeadline(
            uri_text,
            request_options,
            policy,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn requestUriFollowingRedirectsDetailedBefore(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
        policy: runtime.RedirectPolicy,
        deadline: ?std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!runtime.RedirectedResponse {
        var chain = uri_redirect.Chain.init(self.allocator, policy);
        defer chain.deinit();
        try chain.recordInitial(uri_text);
        var current_uri = try self.allocator.dupe(u8, uri_text);
        defer self.allocator.free(current_uri);
        var hop_options = request_options;
        var owned_headers: ?[]http1.Header = null;
        defer if (owned_headers) |headers| self.allocator.free(headers);

        while (true) {
            var response = if (deadline) |absolute|
                try self.requestUriWithDeadline(
                    current_uri,
                    hop_options,
                    absolute,
                )
            else
                try self.requestUri(current_uri, hop_options);
            errdefer response.deinit(self.allocator);
            if (!uri_redirect.isRedirectStatus(response.response.status)) {
                return .{
                    .allocator = self.allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        self.allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            const location = try redirectLocation(response.response.headers);
            if (location == null) {
                return .{
                    .allocator = self.allocator,
                    .response = response,
                    .final_uri = try uri_redirect.canonicalize(
                        self.allocator,
                        current_uri,
                    ),
                    .redirect_count = chain.redirects,
                };
            }
            var next = try chain.follow(
                current_uri,
                location.?,
                response.response.status,
            );
            var next_owned = true;
            defer if (next_owned) next.deinit();
            if (next.cross_origin and self.options.vail_tls != null) {
                try uri_redirect.enforceClientIdentityPolicy(
                    policy,
                    true,
                    self.options.vail_tls.?.client_identity != null,
                );
            }
            const action = uri_redirect.methodAction(
                policy,
                response.response.status,
                hop_options.method,
            );
            const remove_credentials = next.cross_origin and
                !policy.forward_cross_origin_credentials;
            hop_options.headers = try redirectHeaders(
                self.allocator,
                hop_options.headers,
                remove_credentials,
                action == .rewrite_get,
                &owned_headers,
            );
            hop_options.host = null;
            if (action == .rewrite_get) {
                hop_options.method = .GET;
                hop_options.body = &.{};
                hop_options.trailers = &.{};
            } else if (remove_credentials) {
                hop_options.trailers = &.{};
            }
            response.deinit(self.allocator);
            self.allocator.free(current_uri);
            current_uri = next.uri;
            next_owned = false;
        }
    }

    /// Lease one connection for streaming or specialized request APIs. The
    /// caller must call `Lease.release`; incomplete writers make `isReusable`
    /// false and are therefore safely discarded.
    pub fn acquireUri(
        self: *Pool,
        uri_text: []const u8,
    ) Error!Lease {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        return self.acquire(transport, endpoint, null);
    }

    /// Wait for an idle connection or total-pool capacity within one relative
    /// timeout. One budget covers mutex admission, capacity waiting and
    /// connection setup; stricter configured phase limits still apply.
    pub fn acquireUriWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        timeout: std.Io.Duration,
    ) AcquireTimeoutError!Lease {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acquireUriUntil(
            uri_text,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Wait for an idle connection or total-pool capacity until an absolute
    /// awake-clock deadline. A released/discarded lease, failed connection
    /// attempt, idle eviction, or pool close wakes blocked acquirers.
    pub fn acquireUriWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acquireUriUntil(uri_text, deadline);
    }

    fn acquireUriUntil(
        self: *Pool,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        var waiter: owned_admission.Queue.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);
        return self.acquireUntil(transport, endpoint, &waiter, deadline);
    }

    fn acquireUntil(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
        waiter: *owned_admission.Queue.Waiter,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        while (true) {
            return self.acquireBefore(
                transport,
                endpoint,
                waiter,
                deadline,
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

    pub fn idleCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        return self.idle.items.len;
    }

    /// Return all live sockets and reserved connection attempts owned by this
    /// pool. The count includes idle and checked-out connections.
    pub fn connectionCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.connections;
    }

    pub fn waitingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.capacity_waiters.count(self.io);
    }

    pub fn idleCountForUri(
        self: *Pool,
        uri_text: []const u8,
    ) Error!usize {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        var count: usize = 0;
        for (self.idle.items) |slot| {
            count += @intFromBool(slot.transport == transport and
                slot.port == endpoint.port and
                hostEqual(slot.tls_host, endpoint.tls_host));
        }
        return count;
    }

    pub fn pruneExpired(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const before = self.idle.items.len;
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        return before - self.idle.items.len;
    }

    fn acquire(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
        waiter: ?*owned_admission.Queue.Waiter,
    ) Error!Lease {
        return self.acquireMaybeBefore(transport, endpoint, waiter, null);
    }

    fn acquireBefore(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
        waiter: ?*owned_admission.Queue.Waiter,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        return self.acquireMaybeBefore(
            transport,
            endpoint,
            waiter,
            deadline,
        );
    }

    fn acquireMaybeBefore(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
        waiter: ?*owned_admission.Queue.Waiter,
        deadline: ?std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        var displaced: ?Slot = null;
        var admission_lock = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer admission_lock.unlock();
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        if (self.closed) {
            if (waiter) |queued| _ = self.capacity_waiters.remove(queued);
            admission_lock.unlock();
            return error.PoolClosed;
        }
        if (!self.capacity_waiters.mayAttempt(waiter, self.io)) {
            if (waiter) |queued| {
                if (!queued.linked) {
                    try self.capacity_waiters.enqueue(queued, self.allocator, self.io);
                } else if (queued.isNotified()) {
                    queued.rearm();
                }
            }
            self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
            admission_lock.unlock();
            return error.ConnectionLimitReached;
        }
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            const slot = self.idle.items[index];
            if (slot.transport == transport and
                slot.port == endpoint.port and
                hostEqual(slot.tls_host, endpoint.tls_host))
            {
                if (!slot.client.isReusableForPool()) {
                    var stale = self.idle.swapRemove(index);
                    stale.deinit(self.allocator);
                    self.connections -= 1;
                    // swapRemove may move another same-authority candidate
                    // into this slot. Revisit it on the next reverse step.
                    if (index < self.idle.items.len) index += 1;
                    continue;
                }
                const owned = self.idle.swapRemove(index);
                self.finishAdmissionLocked(waiter);
                admission_lock.unlock();
                return .{
                    .pool = self,
                    .slot = owned,
                    .was_reused = true,
                };
            }
        }
        // Connection setup intentionally happens outside the pool lock. Two
        // producers targeting the same authority may connect concurrently;
        // reserve their slots under the lock first so simultaneous cache
        // misses cannot exceed the total socket budget.
        if (self.options.max_connections != 0 and
            self.connections >= self.options.max_connections)
        {
            if (self.idle.items.len == 0) {
                if (waiter) |queued| {
                    if (!queued.linked) {
                        try self.capacity_waiters.enqueue(queued, self.allocator, self.io);
                    } else {
                        queued.rearm();
                    }
                }
                self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
                admission_lock.unlock();
                return error.ConnectionLimitReached;
            }

            // An idle socket for another authority must not pin the entire
            // global budget. Detach the least-recently-used idle socket while
            // holding the lock, then close it after unlocking so TLS shutdown
            // cannot serialize unrelated pool operations. Its accounting slot
            // transfers directly to this connection attempt.
            displaced = self.idle.swapRemove(
                self.oldestIdleIndexLocked(),
            );
        } else {
            self.connections += 1;
        }
        self.finishAdmissionLocked(waiter);
        admission_lock.unlock();
        if (displaced) |*slot| slot.deinit(self.allocator);
        var connection_reserved = true;
        errdefer if (connection_reserved) self.releaseConnectionSlot();

        var tls12_ticket = if (transport == .tls and
            self.options.vail_tls != null and
            self.options.vail_tls.?.protocol_policy.offersTls12())
            try self.tls12_tickets.cloneFor(
                endpoint.tls_host,
                endpoint.port,
                realNowSeconds(self.io),
            )
        else
            null;
        defer if (tls12_ticket) |*ticket| ticket.deinit();
        var tls13_ticket = if (transport == .tls and
            self.options.vail_tls != null and
            self.options.vail_tls.?.protocol_policy.offersTls13() and
            self.options.vail_tls.?.request_tls13_session_ticket)
            try self.tls13_tickets.cloneFor(
                endpoint.tls_host,
                endpoint.port,
                realNowMilliseconds(self.io),
            )
        else
            null;
        defer if (tls13_ticket) |*ticket| ticket.deinit();
        var vail_tls_options = self.options.vail_tls;
        if (tls12_ticket) |*ticket| {
            vail_tls_options.?.tls12_ticket_resumption = ticket;
        }
        if (tls13_ticket) |*ticket| {
            vail_tls_options.?.tls13_ticket_resumption = ticket;
        }

        var client = switch (transport) {
            .cleartext => switch (endpoint.target) {
                .host => if (deadline) |absolute|
                    try runtime.Client.connectHostWithDeadline(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                        absolute,
                    )
                else
                    try runtime.Client.connectHost(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                    ),
                .ip => |address| blk: {
                    var value = if (deadline) |absolute|
                        try runtime.Client.connectWithDeadline(
                            self.allocator,
                            self.io,
                            address,
                            self.options.limits,
                            absolute,
                        )
                    else
                        try runtime.Client.connect(
                            self.allocator,
                            self.io,
                            address,
                            self.options.limits,
                        );
                    value.default_host = try self.allocator.dupe(
                        u8,
                        endpoint.authority,
                    );
                    break :blk value;
                },
            },
            .tls => if (vail_tls_options) |tls_options|
                switch (endpoint.target) {
                    .host => if (deadline) |absolute|
                        try runtime.Client.connectVailTlsHostWithDeadline(
                            self.allocator,
                            self.io,
                            endpoint.tls_host,
                            endpoint.port,
                            self.options.limits,
                            tls_options,
                            absolute,
                        )
                    else
                        try runtime.Client.connectVailTlsHost(
                            self.allocator,
                            self.io,
                            endpoint.tls_host,
                            endpoint.port,
                            self.options.limits,
                            tls_options,
                        ),
                    .ip => |address| if (deadline) |absolute|
                        try runtime.Client.connectVailTlsAddressWithDeadline(
                            self.allocator,
                            self.io,
                            address,
                            endpoint.tls_host,
                            self.options.limits,
                            tls_options,
                            absolute,
                        )
                    else
                        try runtime.Client.connectVailTlsAddress(
                            self.allocator,
                            self.io,
                            address,
                            endpoint.tls_host,
                            self.options.limits,
                            tls_options,
                        ),
                }
            else switch (endpoint.target) {
                .host => if (deadline) |absolute|
                    try runtime.Client.connectTlsHostWithDeadline(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                        self.options.tls,
                        absolute,
                    )
                else
                    try runtime.Client.connectTlsHost(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                        self.options.tls,
                    ),
                .ip => |address| if (deadline) |absolute|
                    try runtime.Client.connectTlsAddressWithDeadline(
                        self.allocator,
                        self.io,
                        address,
                        endpoint.tls_host,
                        endpoint.authority,
                        self.options.limits,
                        self.options.tls,
                        absolute,
                    )
                else
                    try runtime.Client.connectTlsAddress(
                        self.allocator,
                        self.io,
                        address,
                        endpoint.tls_host,
                        endpoint.authority,
                        self.options.limits,
                        self.options.tls,
                    ),
            },
        };
        errdefer client.close();
        if (transport == .tls and vail_tls_options != null) {
            self.rememberTls12SessionTicket(endpoint, &client);
            const remembered_tls13_ticket = try self.rememberTls13SessionTicket(
                endpoint.tls_host,
                endpoint.port,
                &client,
            );
            if (!remembered_tls13_ticket and tls13_ticket != null and
                client.negotiatedTlsProtocol() == .tls13 and
                !(client.wasTlsSessionResumed() orelse false))
            {
                _ = self.tls13_tickets.remove(
                    endpoint.tls_host,
                    endpoint.port,
                );
            }
        }
        const tls_host = try self.allocator.dupe(u8, endpoint.tls_host);
        connection_reserved = false;
        return .{ .pool = self, .slot = .{
            .client = client,
            .transport = transport,
            .tls_host = tls_host,
            .port = endpoint.port,
            .last_used = 0,
            .idle_since_ns = 0,
        } };
    }

    fn rememberTls12SessionTicket(
        self: *Pool,
        endpoint: runtime.UriEndpoint,
        client: *runtime.Client,
    ) void {
        if (client.takeTls12SessionTicket()) |ticket| {
            self.tls12_tickets.store(
                endpoint.tls_host,
                endpoint.port,
                ticket,
                realNowSeconds(self.io),
            );
            return;
        }
        if (client.negotiatedTlsProtocol() == .tls12 and
            !(client.wasTlsSessionResumed() orelse false))
        {
            _ = self.tls12_tickets.remove(
                endpoint.tls_host,
                endpoint.port,
            );
        }
    }

    fn rememberTls13SessionTicket(
        self: *Pool,
        tls_host: []const u8,
        port: u16,
        client: *runtime.Client,
    ) tls_stream.Error!bool {
        if (try client.takeTls13SessionTicket()) |ticket| {
            self.tls13_tickets.store(
                tls_host,
                port,
                ticket,
                realNowMilliseconds(self.io),
            );
            return true;
        }
        return false;
    }

    fn release(self: *Pool, slot_value: Slot, reusable: bool) void {
        var slot = slot_value;
        if (slot.transport == .tls and self.options.vail_tls != null) {
            _ = self.rememberTls13SessionTicket(
                slot.tls_host,
                slot.port,
                &slot.client,
            ) catch {
                _ = self.tls13_tickets.remove(slot.tls_host, slot.port);
            };
        }
        if (!reusable or self.options.max_idle_connections == 0 or
            self.options.max_idle_per_authority == 0)
        {
            slot.deinit(self.allocator);
            self.releaseConnectionSlot();
            return;
        }
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) {
            slot.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            return;
        }
        var same_authority: usize = 0;
        for (self.idle.items) |idle| {
            same_authority += @intFromBool(idle.transport == slot.transport and
                idle.port == slot.port and
                hostEqual(idle.tls_host, slot.tls_host));
        }
        if (same_authority >= self.options.max_idle_per_authority) {
            slot.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            return;
        }
        self.sequence +%= 1;
        slot.last_used = self.sequence;
        slot.idle_since_ns = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (self.idle.items.len >= self.options.max_idle_connections) {
            var oldest = self.idle.swapRemove(
                self.oldestIdleIndexLocked(),
            );
            oldest.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
        }
        self.idle.append(self.allocator, slot) catch {
            slot.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            return;
        };
        self.notifyCapacityWaiterLocked();
    }

    fn oldestIdleIndexLocked(self: *const Pool) usize {
        std.debug.assert(self.idle.items.len != 0);
        var oldest_index: usize = 0;
        for (self.idle.items[1..], 1..) |idle, index| {
            if (idle.last_used < self.idle.items[oldest_index].last_used) {
                oldest_index = index;
            }
        }
        return oldest_index;
    }

    fn releaseConnectionSlot(self: *Pool) void {
        self.retired_connections.release(&self.connections, &self.capacity_waiters, &self.mutex, self.io, 1);
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
        return self.closed or self.idle.items.len != 0 or
            self.options.max_connections == 0 or
            self.connections < self.options.max_connections;
    }

    fn notifyCapacityWaiterLocked(self: *Pool) void {
        self.capacity_waiters.notifyHead(self.io);
    }

    fn pruneExpiredLocked(self: *Pool, now_ns: i96) void {
        const timeout = self.options.idle_timeout orelse return;
        var index: usize = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            if (now_ns - self.idle.items[index].idle_since_ns <
                timeout.nanoseconds)
            {
                continue;
            }
            var expired = self.idle.swapRemove(index);
            expired.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
        }
    }
};

pub const Lease = struct {
    pool: *Pool,
    slot: Slot,
    was_reused: bool = false,
    active: bool = true,

    pub fn client(self: *Lease) *runtime.Client {
        std.debug.assert(self.active);
        return &self.slot.client;
    }

    pub fn release(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.pool.release(
            self.slot,
            self.slot.client.isReusableForPool(),
        );
        self.slot = undefined;
    }

    pub fn discard(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.slot.deinit(self.pool.allocator);
        self.pool.releaseConnectionSlot();
        self.slot = undefined;
    }
};

fn transportForScheme(scheme: []const u8) Error!Transport {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return .cleartext;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return .tls;
    return error.UnsupportedScheme;
}

fn hostEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn redirectLocation(headers: []const http1.Header) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

fn redirectHeaders(
    allocator: std.mem.Allocator,
    source: []const http1.Header,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http1.Header,
) std.mem.Allocator.Error![]const http1.Header {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(http1.Header, retained_count);
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectHeader(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}

fn uriTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    const path = switch (uri.path) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    };
    const effective_path = if (path.len == 0) "/" else path;
    if (uri.query) |query| {
        const bytes = switch (query) {
            .raw => |raw| raw,
            .percent_encoded => |encoded| encoded,
        };
        return std.fmt.allocPrint(
            allocator,
            "{s}?{s}",
            .{ effective_path, bytes },
        );
    }
    return allocator.dupe(u8, effective_path);
}

fn retryableStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.ReadFailed,
        error.SocketUnconnected,
        error.WriteFailed,
        => true,
        else => false,
    };
}

fn realNowSeconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
}

fn realNowMilliseconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toMilliseconds()));
}

test "HTTP/1 client pool validates idle limits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(error.InvalidPoolOptions, Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{ .max_idle_connections = 1, .max_idle_per_authority = 2 },
    ));
    try std.testing.expectEqual(
        @as(usize, 64),
        (Options{}).max_connections,
    );
}

test "HTTP/1 pool host keys normalize DNS case" {
    try std.testing.expect(hostEqual("Example.COM", "example.com"));
    try std.testing.expect(hostEqual("2001:DB8::1", "2001:db8::1"));
}

test {
    _ = @import("client_pool/redirect_tests.zig");
}
