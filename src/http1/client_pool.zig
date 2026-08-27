//! Bounded reusable HTTP/1 client connection pool.
//!
//! The pool has one mutex-protected slot table and leases exclusive Clients to
//! callers for complete request/response exchanges. Idle connections are keyed
//! by scheme + authority, and stale/non-reusable clients are retired rather
//! than returned to the pool.

const std = @import("std");
const runtime = @import("runtime.zig");

pub const Error = runtime.Error || error{
    PoolClosed,
    InvalidPoolOptions,
};

pub const Options = struct {
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
    authority: []u8,
    tls_host: []u8,
    last_used: u64,
    idle_since_ns: i96,

    fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
        self.client.close();
        allocator.free(self.tls_host);
        allocator.free(self.authority);
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
        // All leases must be returned first; a Lease retains a pointer to this
        // object so destroying it concurrently would violate ownership.
        self.close();
        self.idle.deinit(self.allocator);
        self.* = undefined;
    }

    /// Reject new acquisitions and close all currently idle connections.
    /// Outstanding leases remain valid and are closed when returned.
    pub fn close(self: *Pool) void {
        self.mutex.lockUncancelable(self.io);
        self.closed = true;
        for (self.idle.items) |*slot| slot.deinit(self.allocator);
        self.idle.clearRetainingCapacity();
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

    pub fn idleCount(self: *Pool) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pruneExpiredLocked(std.Io.Clock.awake.now(self.io).nanoseconds);
        return self.idle.items.len;
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
                authorityEqual(slot.authority, endpoint.authority) and
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
        self.mutex.unlock(self.io);

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
        const authority = try self.allocator.dupe(u8, endpoint.authority);
        errdefer self.allocator.free(authority);
        const tls_host = try self.allocator.dupe(u8, endpoint.tls_host);
        return .{ .pool = self, .slot = .{
            .client = client,
            .transport = transport,
            .authority = authority,
            .tls_host = tls_host,
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
            return;
        }
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed) {
            slot.deinit(self.allocator);
            return;
        }
        var same_authority: usize = 0;
        for (self.idle.items) |idle| {
            same_authority += @intFromBool(idle.transport == slot.transport and
                authorityEqual(idle.authority, slot.authority) and
                hostEqual(idle.tls_host, slot.tls_host));
        }
        if (same_authority >= self.options.max_idle_per_authority) {
            slot.deinit(self.allocator);
            return;
        }
        self.sequence +%= 1;
        slot.last_used = self.sequence;
        slot.idle_since_ns = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (self.idle.items.len >= self.options.max_idle_connections) {
            var oldest_index: usize = 0;
            for (self.idle.items[1..], 1..) |idle, index| {
                if (idle.last_used < self.idle.items[oldest_index].last_used) {
                    oldest_index = index;
                }
            }
            var oldest = self.idle.swapRemove(oldest_index);
            oldest.deinit(self.allocator);
        }
        self.idle.append(self.allocator, slot) catch {
            slot.deinit(self.allocator);
        };
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

fn authorityEqual(a: []const u8, b: []const u8) bool {
    const a_parts = authorityParts(a);
    const b_parts = authorityParts(b);
    return std.mem.eql(u8, a_parts.port, b_parts.port) and hostEqual(
        a_parts.host,
        b_parts.host,
    );
}

fn authorityParts(authority: []const u8) struct {
    host: []const u8,
    port: []const u8,
} {
    if (authority.len != 0 and authority[0] == '[') {
        const end = std.mem.findScalar(u8, authority, ']') orelse
            return .{ .host = authority, .port = "" };
        return .{
            .host = authority[0 .. end + 1],
            .port = if (end + 1 < authority.len and authority[end + 1] == ':')
                authority[end + 2 ..]
            else
                "",
        };
    }
    const colon = std.mem.findScalarLast(u8, authority, ':') orelse
        return .{ .host = authority, .port = "" };
    return .{ .host = authority[0..colon], .port = authority[colon + 1 ..] };
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
}

test "HTTP/1 pool authority keys normalize DNS case only" {
    try std.testing.expect(authorityEqual(
        "Example.COM:443",
        "example.com:443",
    ));
    try std.testing.expect(!authorityEqual(
        "example.com:443",
        "example.com:444",
    ));
    try std.testing.expect(authorityEqual(
        "[2001:DB8::1]:443",
        "[2001:db8::1]:443",
    ));
}
