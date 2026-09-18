//! Bounded reusable HTTP/1 client connection pool.
//!
//! The pool has one mutex-protected slot table and leases exclusive Clients to
//! callers for complete request/response exchanges. A total connection budget
//! covers idle, leased, and connecting sockets. Idle connections are keyed by
//! scheme + canonical host + effective port, and stale/non-reusable clients are
//! retired rather than returned to the pool.

const std = @import("std");
const fifo_admission = @import("../internal/fifo_admission.zig");
const deadline_policy = @import("../internal/deadline.zig");
const runtime = @import("runtime.zig");

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
        // All leases must be returned and acquisitions must have finished;
        // both retain a pointer to this object, so destroying it concurrently
        // would violate ownership.
        self.close();
        std.debug.assert(self.connections == 0);
        std.debug.assert(self.capacity_waiters.count() == 0);
        self.idle.deinit(self.allocator);
        self.* = undefined;
    }

    /// Reject new acquisitions and close all currently idle connections.
    /// Outstanding leases remain valid and are closed when returned.
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
    /// timeout. The timer covers queueing only; connection setup and protocol
    /// I/O retain their existing independent deadlines.
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
        var waiter: fifo_admission.Queue.Waiter = .{};
        defer self.cancelCapacityWaiter(&waiter);
        return self.acquireUntil(transport, endpoint, &waiter, deadline);
    }

    fn acquireUntil(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
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
        return self.connections;
    }

    pub fn waitingCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.capacity_waiters.count();
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
        waiter: ?*fifo_admission.Queue.Waiter,
    ) Error!Lease {
        return self.acquireMaybeBefore(transport, endpoint, waiter, null);
    }

    fn acquireBefore(
        self: *Pool,
        transport: Transport,
        endpoint: runtime.UriEndpoint,
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
        endpoint: runtime.UriEndpoint,
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
                self.mutex.unlock(self.io);
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
                        self.capacity_waiters.enqueue(queued);
                    } else {
                        queued.rearm();
                    }
                }
                self.mutex.unlock(self.io);
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
        self.mutex.unlock(self.io);
        if (displaced) |*slot| slot.deinit(self.allocator);
        var connection_reserved = true;
        errdefer if (connection_reserved) self.releaseConnectionSlot();

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
        errdefer client.close();
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
