//! Bounded reusable HTTP/2 client connection pool.
//!
//! Each lease owns one complete multiplexed connection exclusively. Callers
//! may use all of `runtime.Connection`'s batch and streaming APIs while leased;
//! release returns only quiescent, non-GOAWAY connections to the idle pool.

const std = @import("std");
const fifo_admission = @import("../internal/fifo_admission.zig");
const deadline_policy = @import("../internal/deadline.zig");
const http_method = @import("../internal/http_method.zig");
const http2 = @import("mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const uri_redirect = @import("../http1/runtime/redirect.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const tls_ticket_cache = @import("../tls/stream/client_ticket_cache.zig");
const runtime = @import("runtime.zig");
const batch = @import("client_pool/batch.zig");
const shared = @import("client_pool/shared.zig");

pub const Error = runtime.Error || error{
    PoolClosed,
    ConnectionLimitReached,
    InvalidPoolOptions,
    MixedBatchOrigins,
};
pub const AcquireTimeoutError = Error || std.Io.Timeout.Error;

pub const Options = struct {
    /// Maximum idle, leased, and connecting HTTP/2 sockets. Zero disables the
    /// total cap. Each lease remains exclusive even though its connection can
    /// multiplex many streams internally.
    max_connections: usize = 32,
    max_idle_connections: usize = 16,
    max_idle_per_authority: usize = 4,
    idle_timeout: ?std.Io.Duration = .fromSeconds(90),
    limits: runtime.Limits = .{},
    tls: runtime.TlsConnectOptions = .{},
    /// Maximum cached RFC 5077 TLS 1.2 tickets across HTTPS authorities.
    /// Zero disables automatic ticket retention and resumption.
    max_tls12_session_tickets: usize = 32,
    /// Maximum cached RFC 8446 TLS 1.3 tickets across HTTPS authorities.
    /// Zero disables automatic ticket retention and resumption.
    max_tls13_session_tickets: usize = 32,
};

pub const UriBatchRequest = batch.UriRequest;

const Transport = enum { cleartext, tls };

const Slot = struct {
    connection: runtime.Connection,
    transport: Transport,
    tls_host: []u8,
    port: u16,
    last_used: u64,
    idle_since_ns: i96,

    fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
        self.connection.close();
        allocator.free(self.tls_host);
        self.* = undefined;
    }
};

pub const Pool = struct {
    pub const SharedRequestError = Error || shared.Error ||
        std.Io.Timeout.Error || std.Io.Cancelable;

    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: std.ArrayList(Slot) = .empty,
    sequence: u64 = 0,
    connections: usize = 0,
    capacity_waiters: fifo_admission.Queue = .{},
    tls12_tickets: tls_ticket_cache.Cache,
    tls13_tickets: tls_ticket_cache.Tls13Cache,
    closed: bool = false,

    pub const requestUriBatch = batch.requestUriBatch;
    pub const requestUriBatchWithTimeout = batch.requestUriBatchWithTimeout;
    pub const requestUriBatchWithDeadline = batch.requestUriBatchWithDeadline;

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
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count() == 0);
        self.idle.deinit(self.allocator);
        self.tls12_tickets.deinit();
        self.tls13_tickets.deinit();
        self.* = undefined;
    }

    /// Reject new leases and close all idle connections. Checked-out leases
    /// remain valid, but are closed rather than pooled when returned.
    pub fn close(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
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

    /// Acquire an exclusive persistent HTTP/2 connection for one URI origin.
    pub fn acquireUri(self: *Pool, uri_text: []const u8) Error!Lease {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        return self.acquire(transport, endpoint, null);
    }

    /// Wait for an idle connection or total-pool capacity within one relative
    /// timeout. The budget covers queueing only; dialing and HTTP/2 handshake
    /// deadlines remain controlled by `Options.limits` and `Options.tls`.
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
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        var waiter: fifo_admission.Queue.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);
        return self.acquireUntil(transport, endpoint, &waiter, deadline);
    }

    fn acquireUntil(
        self: *Pool,
        transport: Transport,
        endpoint: http1_runtime.UriEndpoint,
        waiter: *fifo_admission.Queue.Waiter,
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

    /// Send a complete request through an exclusive lease and return the
    /// connection to the pool only when its HTTP/2 state is quiescent.
    pub fn requestUri(
        self: *Pool,
        uri_text: []const u8,
        request_options: runtime.RequestOptions,
    ) Error!runtime.OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const target = try uriTargetAlloc(self.allocator, uri);
        defer self.allocator.free(target);
        var retry_stale = true;
        while (true) {
            var lease = try self.acquireUri(uri_text);
            defer if (lease.active) lease.discard();
            var options = request_options;
            options.path = target;
            var response = lease.connection().request(options) catch |err| {
                const was_reused = lease.was_reused;
                lease.discard();
                if (retry_stale and was_reused and
                    http_method.isIdempotent(request_options.method) and
                    retryableStaleConnectionError(err))
                {
                    retry_stale = false;
                    continue;
                }
                return err;
            };
            errdefer response.deinit(self.allocator);
            lease.release();
            return response;
        }
    }

    /// Apply one absolute deadline to FIFO admission, connection setup, the
    /// HTTP/2 bootstrap, stale-idempotent retry, and the complete response.
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
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        const target = try uriTargetAlloc(self.allocator, uri);
        defer self.allocator.free(target);
        var waiter: fifo_admission.Queue.Waiter = .{};
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
            options.path = target;
            var response = lease.connection().requestWithDeadline(
                options,
                deadline,
            ) catch |err| {
                const was_reused = lease.was_reused;
                lease.discard();
                if (retry_stale and was_reused and
                    http_method.isIdempotent(request_options.method) and
                    retryableStaleConnectionError(err))
                {
                    retry_stale = false;
                    continue;
                }
                return err;
            };
            errdefer response.deinit(self.allocator);
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
        var owned_headers: ?[]http2.Hpack.HeaderField = null;
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
            if (!uri_redirect.isRedirectStatus(response.status)) {
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
            const location = try redirectLocation(response.headers);
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
            var next = try chain.follow(current_uri, location.?, response.status);
            var next_owned = true;
            defer if (next_owned) next.deinit();
            if (next.cross_origin) {
                try uri_redirect.enforceClientIdentityPolicy(
                    policy,
                    true,
                    self.options.tls.client_identity != null,
                );
            }
            const action = uri_redirect.methodActionBytes(
                policy,
                response.status,
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
            hop_options.authority = null;
            hop_options.scheme = null;
            if (action == .rewrite_get) {
                hop_options.method = "GET";
                hop_options.protocol = null;
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

    pub fn idleCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        return self.idle.items.len;
    }

    pub fn idleCountForUri(
        self: *Pool,
        uri_text: []const u8,
    ) Error!usize {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try http1_runtime.uriEndpoint(
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
            count += @intFromBool(
                slot.transport == transport and slot.port == endpoint.port and
                    std.ascii.eqlIgnoreCase(slot.tls_host, endpoint.tls_host),
            );
        }
        return count;
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
        endpoint: http1_runtime.UriEndpoint,
        waiter: ?*fifo_admission.Queue.Waiter,
    ) Error!Lease {
        return self.acquireMaybeBefore(transport, endpoint, waiter, null);
    }

    fn acquireBefore(
        self: *Pool,
        transport: Transport,
        endpoint: http1_runtime.UriEndpoint,
        waiter: ?*fifo_admission.Queue.Waiter,
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
        endpoint: http1_runtime.UriEndpoint,
        waiter: ?*fifo_admission.Queue.Waiter,
        deadline: ?std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        var displaced: ?Slot = null;
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
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            const slot = self.idle.items[index];
            if (slot.transport == transport and slot.port == endpoint.port and
                std.ascii.eqlIgnoreCase(slot.tls_host, endpoint.tls_host))
            {
                const owned = self.idle.swapRemove(index);
                self.finishAdmissionLocked(waiter);
                self.mutex.unlock(self.io);
                return .{ .pool = self, .slot = owned, .was_reused = true };
            }
        }
        if (self.options.max_connections != 0 and
            self.connections >= self.options.max_connections)
        {
            if (self.idle.items.len == 0) {
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

            // An unrelated idle authority must not strand a caller behind the
            // global connection cap. Detach the least-recently-used socket
            // under the lock, close it after unlocking, and transfer its
            // accounting slot directly to this connection attempt. Leased
            // connections remain protected from eviction.
            displaced = self.idle.swapRemove(
                self.oldestIdleIndexLocked(),
            );
        } else {
            self.connections += 1;
        }
        self.finishAdmissionLocked(waiter);
        self.mutex.unlock(self.io);
        if (displaced) |*slot| slot.deinit(self.allocator);
        var reserved = true;
        errdefer if (reserved) self.releaseConnectionSlot();

        var tls12_ticket = if (transport == .tls and
            self.options.tls.protocol_policy.offersTls12())
            try self.tls12_tickets.cloneFor(
                endpoint.tls_host,
                endpoint.port,
                realNowSeconds(self.io),
            )
        else
            null;
        defer if (tls12_ticket) |*ticket| ticket.deinit();
        var tls13_ticket = if (transport == .tls and
            self.options.tls.protocol_policy.offersTls13() and
            self.options.tls.request_tls13_session_ticket)
            try self.tls13_tickets.cloneFor(
                endpoint.tls_host,
                endpoint.port,
                realNowMilliseconds(self.io),
            )
        else
            null;
        defer if (tls13_ticket) |*ticket| ticket.deinit();
        var tls_options = self.options.tls;
        if (tls12_ticket) |*ticket| {
            tls_options.tls12_ticket_resumption = ticket;
        }
        if (tls13_ticket) |*ticket| {
            tls_options.tls13_ticket_resumption = ticket;
        }

        var connection = switch (transport) {
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
                .ip => |address| if (deadline) |absolute|
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
                    ),
            },
            .tls => switch (endpoint.target) {
                .host => if (deadline) |absolute|
                    try runtime.Client.connectTlsHostWithDeadline(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                        tls_options,
                        absolute,
                    )
                else
                    try runtime.Client.connectTlsHost(
                        self.allocator,
                        self.io,
                        endpoint.tls_host,
                        endpoint.port,
                        self.options.limits,
                        tls_options,
                    ),
                .ip => |address| if (deadline) |absolute|
                    try runtime.Client.connectTlsAddressWithDeadline(
                        self.allocator,
                        self.io,
                        address,
                        endpoint.tls_host,
                        endpoint.authority,
                        self.options.limits,
                        tls_options,
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
                        tls_options,
                    ),
            },
        };
        errdefer connection.close();
        if (transport == .tls) {
            self.rememberTls12SessionTicket(endpoint, &connection);
            const remembered_tls13_ticket = try self.rememberTls13SessionTicket(
                endpoint.tls_host,
                endpoint.port,
                &connection,
            );
            if (!remembered_tls13_ticket and tls13_ticket != null and
                connection.negotiatedTlsProtocol() == .tls13 and
                !(connection.wasTlsSessionResumed() orelse false))
            {
                _ = self.tls13_tickets.remove(
                    endpoint.tls_host,
                    endpoint.port,
                );
            }
        }
        if (connection.default_authority) |authority| {
            self.allocator.free(authority);
        }
        connection.default_authority = try self.allocator.dupe(
            u8,
            endpoint.authority,
        );
        connection.default_scheme = if (transport == .tls) "https" else "http";
        const tls_host = try self.allocator.dupe(u8, endpoint.tls_host);
        reserved = false;
        return .{ .pool = self, .slot = .{
            .connection = connection,
            .transport = transport,
            .tls_host = tls_host,
            .port = endpoint.port,
            .last_used = 0,
            .idle_since_ns = 0,
        } };
    }

    fn rememberTls12SessionTicket(
        self: *Pool,
        endpoint: http1_runtime.UriEndpoint,
        connection: *runtime.Connection,
    ) void {
        if (connection.takeTls12SessionTicket()) |ticket| {
            self.tls12_tickets.store(
                endpoint.tls_host,
                endpoint.port,
                ticket,
                realNowSeconds(self.io),
            );
            return;
        }
        if (connection.negotiatedTlsProtocol() == .tls12 and
            !(connection.wasTlsSessionResumed() orelse false))
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
        connection: *runtime.Connection,
    ) tls_stream.Error!bool {
        if (try connection.takeTls13SessionTicket()) |ticket| {
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
        if (slot.transport == .tls) {
            _ = self.rememberTls13SessionTicket(
                slot.tls_host,
                slot.port,
                &slot.connection,
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
            same_authority += @intFromBool(
                idle.transport == slot.transport and
                    idle.port == slot.port and
                    std.ascii.eqlIgnoreCase(idle.tls_host, slot.tls_host),
            );
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
        return self.closed or self.idle.items.len != 0 or
            self.options.max_connections == 0 or
            self.connections < self.options.max_connections;
    }

    fn notifyCapacityWaiterLocked(self: *Pool) void {
        self.capacity_waiters.notifyHead(self.io);
    }

    fn pruneExpiredLocked(self: *Pool, now_ns: i96) void {
        const timeout = self.options.idle_timeout orelse return;
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            if (now_ns - self.idle.items[index].idle_since_ns <
                timeout.nanoseconds) continue;
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

    pub fn connection(self: *Lease) *runtime.Connection {
        std.debug.assert(self.active);
        return &self.slot.connection;
    }

    pub fn release(self: *Lease) void {
        if (!self.active) return;
        self.active = false;
        self.pool.release(self.slot, self.slot.connection.isReusable());
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

pub const SharedDispatcher = shared.Dispatcher(Pool);
pub const SharedSender = SharedDispatcher.Sender;
pub const SharedOptions = shared.Options;
pub const SharedError = shared.Error;
pub const SharedStats = shared.Stats;

fn transportForScheme(scheme: []const u8) Error!Transport {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return .cleartext;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return .tls;
    return error.UnsupportedScheme;
}

fn redirectLocation(
    headers: []const http2.Hpack.HeaderField,
) Error!?[]const u8 {
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
    source: []const http2.Hpack.HeaderField,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http2.Hpack.HeaderField,
) std.mem.Allocator.Error![]const http2.Hpack.HeaderField {
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
    const headers = try allocator.alloc(
        http2.Hpack.HeaderField,
        retained_count,
    );
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

fn retryableStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.SocketUnconnected,
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

fn uriTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    const path = switch (uri.path) {
        .raw, .percent_encoded => |value| value,
    };
    const effective_path = if (path.len == 0) "/" else path;
    if (uri.query) |query| {
        const bytes = switch (query) {
            .raw, .percent_encoded => |value| value,
        };
        return std.fmt.allocPrint(
            allocator,
            "{s}?{s}",
            .{ effective_path, bytes },
        );
    }
    return allocator.dupe(u8, effective_path);
}

test "HTTP/2 client pool validates idle limits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(error.InvalidPoolOptions, Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{ .max_idle_connections = 1, .max_idle_per_authority = 2 },
    ));
}

test "HTTP/2 stale retry policy accepts only idempotent methods" {
    try std.testing.expect(http_method.isIdempotent("GET"));
    try std.testing.expect(http_method.isIdempotent("HEAD"));
    try std.testing.expect(http_method.isIdempotent("PUT"));
    try std.testing.expect(http_method.isIdempotent("DELETE"));
    try std.testing.expect(http_method.isIdempotent("OPTIONS"));
    try std.testing.expect(http_method.isIdempotent("TRACE"));
    try std.testing.expect(http_method.isIdempotent("QUERY"));
    try std.testing.expect(!http_method.isIdempotent("POST"));
    try std.testing.expect(!http_method.isIdempotent("CONNECT"));
    try std.testing.expect(!http_method.isIdempotent("PATCH"));
}

test {
    _ = @import("client_pool/redirect_tests.zig");
}
