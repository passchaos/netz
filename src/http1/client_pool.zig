//! Bounded reusable HTTP/1 client connection pool.
//!
//! The pool has one mutex-protected slot table and leases exclusive Clients to
//! callers for complete request/response exchanges. A total connection budget
//! covers idle, leased, and connecting sockets. Idle connections are keyed by
//! scheme + canonical host + effective port, and stale/non-reusable clients are
//! retired rather than returned to the pool.

const std = @import("std");
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
    capacity_generation: std.atomic.Value(u32) = .init(1),
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
        self.mutex.unlock(self.io);
        self.notifyCapacityWaiters();
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
            var lease = try self.acquire(transport, endpoint);
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
        return self.acquire(transport, endpoint);
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
        while (true) {
            // Snapshot before trying the pool. If a release races after this
            // point, its generation bump prevents the futex wait from
            // sleeping. If it races before this point, `acquire` observes the
            // newly idle connection or free reservation directly.
            const generation = self.capacity_generation.load(.acquire);
            return self.acquire(transport, endpoint) catch |err| switch (err) {
                error.ConnectionLimitReached => {
                    if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                        return error.Timeout;
                    }
                    self.io.futexWaitTimeout(
                        u32,
                        &self.capacity_generation.raw,
                        generation,
                        .{ .deadline = deadline },
                    ) catch |wait_err| switch (wait_err) {
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
    ) Error!Lease {
        var displaced: ?Slot = null;
        self.mutex.lockUncancelable(self.io);
        if (self.closed) {
            self.mutex.unlock(self.io);
            return error.PoolClosed;
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
                const owned = self.idle.swapRemove(index);
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
        self.mutex.unlock(self.io);
        if (displaced) |*slot| slot.deinit(self.allocator);
        var connection_reserved = true;
        errdefer if (connection_reserved) self.releaseConnectionSlot();

        var client = switch (transport) {
            .cleartext => switch (endpoint.target) {
                .host => try runtime.Client.connectHost(
                    self.allocator,
                    self.io,
                    endpoint.tls_host,
                    endpoint.port,
                    self.options.limits,
                ),
                .ip => |address| blk: {
                    var value = try runtime.Client.connect(
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
                .host => try runtime.Client.connectTlsHost(
                    self.allocator,
                    self.io,
                    endpoint.tls_host,
                    endpoint.port,
                    self.options.limits,
                    self.options.tls,
                ),
                .ip => |address| try runtime.Client.connectTlsAddress(
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
            self.notifyCapacityWaiters();
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
            self.notifyCapacityWaiters();
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
            self.notifyCapacityWaiters();
        }
        self.idle.append(self.allocator, slot) catch {
            slot.deinit(self.allocator);
            self.connections -= 1;
            self.notifyCapacityWaiters();
            return;
        };
        // Idle entries are authority-specific. Wake all waiters so a waiter
        // for this authority is not stranded behind one for another host.
        self.notifyCapacityWaiters();
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
        self.mutex.unlock(self.io);
        self.notifyCapacityWaiters();
    }

    fn notifyCapacityWaiters(self: *Pool) void {
        _ = self.capacity_generation.fetchAdd(1, .release);
        self.io.futexWake(
            u32,
            &self.capacity_generation.raw,
            std.math.maxInt(u32),
        );
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
            self.notifyCapacityWaiters();
        }
    }
};

pub const Lease = struct {
    pool: *Pool,
    slot: Slot,
    was_reused: bool = false,
    active: bool = true,

    pub fn client(self: *Lease) *runtime.Client {
        return &self.slot.client;
    }

    pub fn release(self: *Lease) void {
        self.pool.release(self.slot, self.slot.client.isReusable());
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
