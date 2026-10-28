//! Bounded reusable HTTP/2 client connection pool.
//!
//! Each lease owns one complete multiplexed connection exclusively. Callers
//! may use all of `runtime.Connection`'s batch and streaming APIs while leased;
//! release returns only quiescent, non-GOAWAY connections to the idle pool.

const std = @import("std");
const client_authority = @import("runtime/client/authority.zig");
const owned_admission = @import("../internal/owned_fifo_admission.zig");
const retired_capacity = @import("../internal/retired_capacity.zig");
const pool_returns = @import("../internal/pool_returns.zig");
const authority_returns = @import("../internal/pool_returns/authority_returns.zig");
const setup_tickets = @import("../internal/pool_tickets/setup.zig");
const deadline_policy = @import("../internal/deadline.zig");
const MutexGuard = @import("../internal/mutex_guard.zig").Guard;
const http_method = @import("../internal/http_method.zig");
const netz_runtime = @import("../runtime.zig");
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
    /// Application contribution size used by pooled body-bearing URI batches.
    /// HTTP/2 frame splitting and flow-control limits remain authoritative.
    batch_body_chunk_size: usize = 16 * 1024,
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
    return_node: ?*ReturnQueue.Node = null,

    fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
        self.deinitBefore(allocator, null);
    }

    fn deinitBefore(self: *Slot, allocator: std.mem.Allocator, deadline: ?std.Io.Clock.Timestamp) void {
        if (deadline != null) self.connection.closeWithoutCloseNotify() else self.connection.close();
        allocator.free(self.tls_host);
        if (self.return_node) |node| node.destroy();
        self.* = undefined;
    }
};

const ReturnPayload = struct { slot: Slot, reusable: bool, returned_at_ns: i96 };
const ReturnQueue = pool_returns.Queue(ReturnPayload);

pub const Pool = struct {
    pub const SharedRequestError = Error || shared.Error ||
        std.Io.Timeout.Error || std.Io.Cancelable;

    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: std.ArrayList(Slot) = .empty,
    returns: ReturnQueue = .{},
    sequence: u64 = 0,
    connections: usize = 0,
    retired_connections: retired_capacity.Retirements = .{},
    capacity_waiters: owned_admission.Queue = .{},
    tls12_tickets: tls_ticket_cache.Cache,
    tls13_tickets: tls_ticket_cache.Tls13Cache,
    closed: bool = false,

    pub const requestUriBatch = batch.requestUriBatch;
    pub const requestUriBatchWithTimeout = batch.requestUriBatchWithTimeout;
    pub const requestUriBatchWithDeadline = batch.requestUriBatchWithDeadline;
    pub const requestUriBatchWithPerStreamDeadlines =
        batch.requestUriBatchWithPerStreamDeadlines;
    pub const requestUriBatchWithPerStreamDeadlinesAndCancellation =
        batch.requestUriBatchWithPerStreamDeadlinesAndCancellation;
    pub const requestUriBatchStreamingWithPerStreamDeadlines =
        batch.requestUriBatchStreamingWithPerStreamDeadlines;
    pub const requestUriBatchStreamingWithPerStreamDeadlinesAndCancellation =
        batch.requestUriBatchStreamingWithPerStreamDeadlinesAndCancellation;

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) Error!Pool {
        if (options.max_idle_per_authority > options.max_idle_connections) {
            return error.InvalidPoolOptions;
        }
        if (options.batch_body_chunk_size == 0) {
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
        std.debug.assert(self.capacity_waiters.count(self.io) == 0);
        self.idle.deinit(self.allocator);
        self.tls12_tickets.deinit();
        self.tls13_tickets.deinit();
        self.* = undefined;
    }

    /// Reject new leases and close all idle connections. Checked-out leases
    /// remain valid, but are closed rather than pooled when returned.
    pub const close = @import("../internal/pool_returns/close.zig").close;
    pub const closeWithDeadline = @import("../internal/pool_returns/close.zig").closeWithDeadline;
    pub const closeWithTimeout = @import("../internal/pool_returns/close.zig").closeWithTimeout;

    /// Acquire an exclusive persistent HTTP/2 connection for one URI origin.
    pub fn acquireUri(self: *Pool, uri_text: []const u8) Error!Lease {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        return self.acquireParsedUri(uri);
    }

    /// Parsed counterpart for URI pipelines that already validated and retain
    /// the borrowed source text for this complete call.
    pub fn acquireParsedUri(self: *Pool, uri: std.Uri) Error!Lease {
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();
        return self.acquire(transport, endpoint, null);
    }

    /// Take a matching idle connection without dialing or waiting for global
    /// capacity. Returns null when the normal admission path is required.
    pub fn tryAcquireIdleUri(
        self: *Pool,
        uri_text: []const u8,
    ) Error!?Lease {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        return self.tryAcquireIdleParsedUri(uri);
    }

    pub fn tryAcquireIdleParsedUri(
        self: *Pool,
        uri: std.Uri,
    ) Error!?Lease {
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try http1_runtime.uriEndpoint(
            self.allocator,
            uri,
            if (transport == .tls) 443 else 80,
        );
        defer endpoint.deinit();

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        if (self.closed) return error.PoolClosed;
        if (!self.capacity_waiters.mayAttempt(null, self.io)) return null;
        self.pruneExpiredLocked(self.awakeNowNs());
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            const slot = self.idle.items[index];
            if (slot.transport == transport and slot.port == endpoint.port and
                std.ascii.eqlIgnoreCase(slot.tls_host, endpoint.tls_host))
            {
                const owned = self.idle.swapRemove(index);
                return .{
                    .pool = self,
                    .slot = owned,
                    .was_reused = true,
                };
            }
        }
        return null;
    }

    /// Wait for an idle connection or total-pool capacity within one relative
    /// timeout. One budget covers mutex admission, capacity waiting, dialing
    /// and HTTP/2 bootstrap; stricter configured phase limits still apply.
    pub fn acquireUriWithTimeout(
        self: *Pool,
        uri_text: []const u8,
        timeout: std.Io.Duration,
    ) AcquireTimeoutError!Lease {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        return self.acquireParsedUriUntil(
            uri,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn acquireUriWithDeadline(
        self: *Pool,
        uri_text: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        return self.acquireParsedUriUntil(uri, deadline);
    }

    pub fn acquireParsedUriWithDeadline(
        self: *Pool,
        uri: std.Uri,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acquireParsedUriUntil(uri, deadline);
    }

    fn acquireParsedUriUntil(
        self: *Pool,
        uri: std.Uri,
        deadline: std.Io.Clock.Timestamp,
    ) AcquireTimeoutError!Lease {
        const transport = try transportForScheme(uri.scheme);
        var endpoint = try http1_runtime.uriEndpoint(
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
        endpoint: http1_runtime.UriEndpoint,
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
        self.collectReturnsLocked();
        self.pruneExpiredLocked(self.awakeNowNs());
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
        self.collectReturnsLocked();
        self.pruneExpiredLocked(self.awakeNowNs());
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
        self.collectReturnsLocked();
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.connections;
    }

    pub fn waitingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
        return self.capacity_waiters.count(self.io);
    }

    pub fn pruneExpired(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.collectReturnsLocked();
        const before = self.idle.items.len;
        self.pruneExpiredLocked(self.awakeNowNs());
        return before - self.idle.items.len;
    }

    fn acquire(
        self: *Pool,
        transport: Transport,
        endpoint: http1_runtime.UriEndpoint,
        waiter: ?*owned_admission.Queue.Waiter,
    ) Error!Lease {
        return self.acquireMaybeBefore(transport, endpoint, waiter, null);
    }

    fn acquireBefore(
        self: *Pool,
        transport: Transport,
        endpoint: http1_runtime.UriEndpoint,
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
        endpoint: http1_runtime.UriEndpoint,
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
        try self.collectReturnsBeforeLocked(deadline);
        if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);

        if (!self.capacity_waiters.mayAttempt(waiter, self.io)) {
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
        self.pruneExpiredBeforeLocked(self.awakeNowNs(), deadline);
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            const slot = self.idle.items[index];
            if (slot.transport == transport and slot.port == endpoint.port and
                std.ascii.eqlIgnoreCase(slot.tls_host, endpoint.tls_host))
            {
                const owned = self.idle.swapRemove(index);
                self.finishAdmissionLocked(waiter);
                admission_lock.unlock();
                return .{ .pool = self, .slot = owned, .was_reused = true };
            }
        }
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
                try self.collectReturnsBeforeLocked(deadline);
                self.retired_connections.apply(&self.connections, &self.capacity_waiters, self.io);
                admission_lock.unlock();
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
        admission_lock.unlock();
        if (displaced) |*slot| slot.deinitBefore(self.allocator, deadline);
        var reserved = true;
        errdefer if (reserved) self.releaseConnectionSlot();
        const return_node = try ReturnQueue.Node.create(self.allocator);
        errdefer return_node.destroy();

        var tls12_ticket = if (transport == .tls and
            self.options.tls.protocol_policy.offersTls12())
            try self.tls12_tickets.cloneForBefore(
                endpoint.tls_host,
                endpoint.port,
                realNowSeconds(self.io),
                deadline,
            )
        else
            null;
        defer if (tls12_ticket) |*ticket| ticket.deinit();
        var tls13_ticket = if (transport == .tls and
            self.options.tls.protocol_policy.offersTls13() and
            self.options.tls.request_tls13_session_ticket)
            try self.tls13_tickets.cloneForBefore(
                endpoint.tls_host,
                endpoint.port,
                realNowMilliseconds(self.io),
                deadline,
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
        errdefer if (deadline != null) connection.closeWithoutCloseNotify() else connection.close();

        try client_authority.replace(self.allocator, &connection.default_authority, endpoint.authority);
        connection.default_authority_is_ip = false;
        connection.default_scheme = if (transport == .tls) "https" else "http";
        const tls_host = try self.allocator.dupe(u8, endpoint.tls_host);
        errdefer self.allocator.free(tls_host);
        var publication = try MutexGuard.initBefore(&self.mutex, self.io, deadline);
        defer publication.unlock();
        if (self.closed) return error.PoolClosed;
        if (transport == .tls) {
            try setup_tickets.remember12(&self.tls12_tickets, &connection, endpoint.tls_host, endpoint.port, false, self.io, deadline);
            _ = try setup_tickets.remember13(&self.tls13_tickets, &connection, endpoint.tls_host, endpoint.port, false, tls13_ticket != null, self.io, deadline);
        }
        if (deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
        reserved = false;
        return .{ .pool = self, .slot = .{
            .connection = connection,
            .transport = transport,
            .tls_host = tls_host,
            .port = endpoint.port,
            .last_used = 0,
            .idle_since_ns = 0,
            .return_node = return_node,
        } };
    }

    const release = authority_returns.release;
    const collectReturnsLocked = authority_returns.collect;
    const collectReturnsBeforeLocked = authority_returns.collectBefore;

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
        self.pruneExpiredBeforeLocked(now_ns, null);
    }

    fn pruneExpiredBeforeLocked(self: *Pool, now_ns: i96, deadline: ?std.Io.Clock.Timestamp) void {
        const timeout = self.options.idle_timeout orelse return;
        var index = self.idle.items.len;
        while (index != 0) {
            index -= 1;
            if (now_ns - self.idle.items[index].idle_since_ns <
                timeout.nanoseconds) continue;
            var expired = self.idle.swapRemove(index);
            expired.deinitBefore(self.allocator, deadline);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
        }
    }

    /// Idle bookkeeping may share the event loop's timestamp for one scheduler
    /// scan. Foreign std.Io implementations retain ordinary awake-clock reads.
    fn awakeNowNs(self: *Pool) i96 {
        return netz_runtime.cachedAwakeNow(self.io).nanoseconds;
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

test "HTTP/2 parsed URI pool admission preserves validation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try Pool.init(std.testing.allocator, io, .{});
    defer pool.deinit();

    const ipv6 = try std.Uri.parse("http://[::1]:8080/path?x=1");
    try std.testing.expect(
        try pool.tryAcquireIdleParsedUri(ipv6) == null,
    );

    const unsupported = try std.Uri.parse("ftp://localhost/path");
    try std.testing.expectError(
        error.UnsupportedScheme,
        pool.tryAcquireIdleParsedUri(unsupported),
    );
    const userinfo = try std.Uri.parse("http://user@localhost/path");
    try std.testing.expectError(
        error.InvalidUri,
        pool.tryAcquireIdleParsedUri(userinfo),
    );
    try std.testing.expectError(
        error.Timeout,
        pool.acquireParsedUriWithDeadline(
            unsupported,
            .{ .raw = .zero, .clock = .awake },
        ),
    );
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
