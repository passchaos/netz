//! Bounded reusable HTTP/2 client connection pool.
//!
//! Each lease owns one complete multiplexed connection exclusively. Callers
//! may use all of `runtime.Connection`'s batch and streaming APIs while leased;
//! release returns only quiescent, non-GOAWAY connections to the idle pool.

const std = @import("std");
const fifo_admission = @import("../internal/fifo_admission.zig");
const http1_runtime = @import("../http1/runtime.zig");
const runtime = @import("runtime.zig");

pub const Error = runtime.Error || error{
    PoolClosed,
    ConnectionLimitReached,
    InvalidPoolOptions,
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
};

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
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    mutex: std.Io.Mutex = .init,
    idle: std.ArrayList(Slot) = .empty,
    sequence: u64 = 0,
    connections: usize = 0,
    capacity_waiters: fifo_admission.Queue = .{},
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
        return .{ .allocator = allocator, .io = io, .options = options };
    }

    pub fn deinit(self: *Pool) void {
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count() == 0);
        self.idle.deinit(self.allocator);
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
                    methodIsIdempotent(request_options.method) and
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
                    methodIsIdempotent(request_options.method) and
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
        errdefer connection.close();
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

    fn release(self: *Pool, slot_value: Slot, reusable: bool) void {
        var slot = slot_value;
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
        return &self.slot.connection;
    }

    pub fn release(self: *Lease) void {
        self.pool.release(self.slot, self.slot.connection.isReusable());
        self.active = false;
    }

    pub fn discard(self: *Lease) void {
        self.slot.deinit(self.pool.allocator);
        self.pool.releaseConnectionSlot();
        self.active = false;
    }
};

fn transportForScheme(scheme: []const u8) Error!Transport {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return .cleartext;
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return .tls;
    return error.UnsupportedScheme;
}

fn methodIsIdempotent(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "PUT") or
        std.mem.eql(u8, method, "DELETE") or
        std.mem.eql(u8, method, "OPTIONS") or
        std.mem.eql(u8, method, "TRACE");
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
    try std.testing.expect(methodIsIdempotent("GET"));
    try std.testing.expect(methodIsIdempotent("HEAD"));
    try std.testing.expect(methodIsIdempotent("PUT"));
    try std.testing.expect(methodIsIdempotent("DELETE"));
    try std.testing.expect(methodIsIdempotent("OPTIONS"));
    try std.testing.expect(methodIsIdempotent("TRACE"));
    try std.testing.expect(!methodIsIdempotent("POST"));
    try std.testing.expect(!methodIsIdempotent("CONNECT"));
    try std.testing.expect(!methodIsIdempotent("PATCH"));
}
