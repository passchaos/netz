//! Exclusive owning pool for authenticated HTTP/3 clients.
//!
//! Each lease owns one `HandshakeClient` and therefore remains its sole QUIC
//! receive driver. Idle clients retain QPACK/control state and their socket;
//! callers provide a connector so certificate policy, resumption, CID
//! generation, and shared-endpoint strategy remain deployment-owned.

const std = @import("std");
const http3 = @import("../mod.zig");

pub const Error = error{
    InvalidPoolOptions,
    ConnectionLimitReached,
    PoolClosed,
};

pub fn DefaultConnectorContext(comptime Runtime: type) type {
    return struct {
        options: Runtime.HandshakeClientOptions,

        pub fn connector(self: *@This()) Connector(Runtime) {
            return .{ .context = self, .connect = connect };
        }

        fn connect(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            std.Io.randomSecure(io, &original_dcid) catch
                return error.Unexpected;
            std.Io.randomSecure(io, &local_cid) catch
                return error.Unexpected;
            var options = self.options;
            options.handshake.original_destination_connection_id =
                &original_dcid;
            options.handshake.local_connection_id = &local_cid;
            return Runtime.HandshakeClient.connectUri(
                allocator,
                io,
                local_address,
                uri,
                limits,
                options,
            );
        }
    };
}

pub fn Connector(comptime Runtime: type) type {
    return struct {
        context: *anyopaque,
        connect: *const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient,
    };
}

pub fn Options(comptime Runtime: type) type {
    return struct {
        local_address: std.Io.net.IpAddress,
        limits: Runtime.Limits = .{},
        idle: http3.origin_pool.Config = .{},
        /// Maximum idle, leased, and connecting clients. Zero is unbounded.
        max_connections: usize = 32,
        connector: Connector(Runtime),
    };
}

pub fn Pool(comptime Runtime: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options(Runtime),
        mutex: std.Io.Mutex = .init,
        idle: IdlePool,
        leased: usize = 0,
        connections: usize = 0,
        capacity_generation: std.atomic.Value(u32) = .init(1),
        closed: bool = false,

        const Self = @This();
        const Client = Runtime.HandshakeClient;
        const IdlePool = http3.origin_pool.Pool(Client);

        pub const Lease = struct {
            pool: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
            was_reused: bool,
            active: bool = true,

            pub fn client(self: *Lease) *Client {
                return &self.client_value;
            }

            pub fn release(self: *Lease) std.mem.Allocator.Error!void {
                std.debug.assert(self.active);
                self.pool.release(
                    self.client_value,
                    self.origin_key,
                ) catch |err| {
                    // `Pool.release` consumes both owned values on every path,
                    // including an idle-pool allocation failure.
                    self.client_value = undefined;
                    self.origin_key = undefined;
                    self.active = false;
                    return err;
                };
                self.client_value = undefined;
                self.origin_key = undefined;
                self.active = false;
            }

            pub fn discard(self: *Lease) void {
                std.debug.assert(self.active);
                self.pool.discard(self.client_value, self.origin_key);
                self.client_value = undefined;
                self.origin_key = undefined;
                self.active = false;
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options(Runtime),
        ) Error!Self {
            if (options.idle.max_idle_per_origin >
                options.idle.max_idle_total)
            {
                return error.InvalidPoolOptions;
            }
            return .{
                .allocator = allocator,
                .io = io,
                .options = options,
                .idle = IdlePool.init(allocator, options.idle, dropClient),
            };
        }

        pub fn deinit(self: *Self) void {
            // Leases retain a pool pointer; the caller must return them before
            // destroying the pool just as with HTTP/1 and HTTP/2 pools.
            std.debug.assert(self.leased == 0);
            self.close();
            std.debug.assert(self.connections == self.idle.idleCount());
            self.idle.deinit();
            self.* = undefined;
        }

        /// Reject new acquisitions and close every idle client. Outstanding
        /// leases remain valid but are discarded when returned.
        pub fn close(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            if (!self.closed) {
                self.closed = true;
                const idle_count = self.idle.idleCount();
                self.idle.deinit();
                self.idle = IdlePool.init(
                    self.allocator,
                    self.options.idle,
                    dropClient,
                );
                std.debug.assert(self.connections >= idle_count);
                self.connections -= idle_count;
            }
            self.mutex.unlock(self.io);
            self.notifyCapacityWaiters();
        }

        pub fn acquireUri(
            self: *Self,
            uri_text: []const u8,
        ) (Runtime.Error || Error)!Lease {
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            const origin = try http3.requestOrigin(
                uri.scheme,
                endpoint.authority,
            );
            const origin_key = try http3.originKeyFromOrigin(
                self.allocator,
                origin,
            );

            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                return error.PoolClosed;
            }
            _ = self.pruneExpiredLocked();
            const reused = self.idle.acquire(origin, nowMillis(self.io));
            if (reused != null) {
                self.leased += 1;
            } else if (self.options.max_connections != 0 and
                self.connections >= self.options.max_connections)
            {
                // Only idle clients are eligible for replacement. Checked-out
                // leases and connection attempts retain their reservation.
                const displaced = self.idle.takeOldest() orelse {
                    self.mutex.unlock(self.io);
                    var key = origin_key;
                    key.deinit();
                    return error.ConnectionLimitReached;
                };
                // `connections` is intentionally unchanged: the evicted idle
                // client's slot becomes this in-progress reservation.
                self.mutex.unlock(self.io);
                var old = displaced;
                old.deinit();
                return self.connectReserved(uri, origin_key);
            } else {
                self.connections += 1;
            }
            self.mutex.unlock(self.io);
            if (reused) |client| {
                const lease: Lease = .{
                    .pool = self,
                    .client_value = client,
                    .origin_key = origin_key,
                    .was_reused = true,
                };
                return lease;
            }

            return self.connectReserved(uri, origin_key);
        }

        pub fn acquireUriWithTimeout(
            self: *Self,
            uri_text: []const u8,
            timeout: std.Io.Duration,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.acquireUriWithDeadline(
                uri_text,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn acquireUriWithDeadline(
            self: *Self,
            uri_text: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            while (true) {
                const generation = self.capacity_generation.load(.acquire);
                return self.acquireUri(uri_text) catch |err| switch (err) {
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

        fn connectReserved(
            self: *Self,
            uri: std.Uri,
            origin_key_value: http3.OriginKey,
        ) (Runtime.Error || Error)!Lease {
            var origin_key = origin_key_value;
            errdefer origin_key.deinit();
            var reservation_active = true;
            errdefer if (reservation_active) self.releaseReservation();
            var client = try self.options.connector.connect(
                self.options.connector.context,
                self.allocator,
                self.io,
                self.options.local_address,
                uri,
                self.options.limits,
            );
            errdefer client.deinit();
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                reservation_active = false;
                client.deinit();
                return error.PoolClosed;
            }
            self.leased += 1;
            self.mutex.unlock(self.io);
            reservation_active = false;
            const lease: Lease = .{
                .pool = self,
                .client_value = client,
                .origin_key = origin_key,
                .was_reused = false,
            };
            origin_key = undefined;
            return lease;
        }

        pub fn requestUri(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
        ) (Runtime.Error || Error)!Runtime.OwnedHandshakeResponse {
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            const path = try Runtime.uriRequestTargetAlloc(self.allocator, uri);
            defer self.allocator.free(path);

            var retry_stale = true;
            while (true) {
                var lease = try self.acquireUri(uri_text);
                defer if (lease.active) lease.discard();
                const response = lease.client().request(.{
                    .method = request_options.method,
                    .path = path,
                    .scheme = "https",
                    .authority = endpoint.authority,
                    .headers = request_options.headers,
                    .body = request_options.body,
                    .trailers = request_options.trailers,
                }) catch |err| {
                    const reused = lease.was_reused;
                    lease.discard();
                    if (retry_stale and reused and
                        methodIsIdempotent(request_options.method) and
                        retryableStaleConnectionError(err))
                    {
                        retry_stale = false;
                        continue;
                    }
                    return err;
                };
                var owned_response = response;
                errdefer owned_response.deinit(self.allocator);
                try lease.release();
                return owned_response;
            }
        }

        pub fn idleCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            _ = self.pruneExpiredLocked();
            return self.idle.idleCount();
        }

        pub fn stats(self: *Self) http3.origin_pool.Stats {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.idle.stats();
        }

        pub fn leasedCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.leased;
        }

        pub fn connectionCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.connections;
        }

        pub fn pruneExpired(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.pruneExpiredLocked();
        }

        fn release(
            self: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
        ) std.mem.Allocator.Error!void {
            var client = client_value;
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.leased != 0);
            self.leased -= 1;
            if (self.closed or !client.isReusable()) {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                client.deinit();
                self.notifyCapacityWaiters();
                return;
            }
            const idle_before = self.idle.idleCount();
            self.idle.releaseKey(
                client,
                origin_key,
                nowMillis(self.io),
            ) catch |err| {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                client.deinit();
                self.notifyCapacityWaiters();
                return err;
            };
            const idle_after = self.idle.idleCount();
            // The released lease already occupies one counted slot. A normal
            // append raises idle count by one. Anything less means the generic
            // idle pool dropped this client, an older client, or both under a
            // per-origin/global idle limit; mirror those closes in the owning
            // pool's total count.
            const expected_idle = idle_before +| 1;
            const dropped = expected_idle -| idle_after;
            std.debug.assert(self.connections >= dropped);
            self.connections -= dropped;
            self.mutex.unlock(self.io);
            self.notifyCapacityWaiters();
        }

        fn discard(
            self: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
        ) void {
            var client = client_value;
            var key = origin_key;
            key.deinit();
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.leased != 0);
            self.leased -= 1;
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.mutex.unlock(self.io);
            client.deinit();
            self.notifyCapacityWaiters();
        }

        fn dropClient(_: std.mem.Allocator, client_value: Client) void {
            var client = client_value;
            client.deinit();
        }

        fn releaseReservation(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.mutex.unlock(self.io);
            self.notifyCapacityWaiters();
        }

        fn pruneExpiredLocked(self: *Self) usize {
            const removed = self.idle.pruneExpired(nowMillis(self.io));
            std.debug.assert(self.connections >= removed);
            self.connections -= removed;
            if (removed != 0) self.notifyCapacityWaiters();
            return removed;
        }

        fn notifyCapacityWaiters(self: *Self) void {
            _ = self.capacity_generation.fetchAdd(1, .release);
            self.io.futexWake(
                u32,
                &self.capacity_generation.raw,
                std.math.maxInt(u32),
            );
        }

        test "HTTP/3 handshake client pool validates idle limits" {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var context: u8 = 0;
            const connector: Connector(Runtime) = .{
                .context = &context,
                .connect = struct {
                    fn connect(
                        _: *anyopaque,
                        _: std.mem.Allocator,
                        _: std.Io,
                        _: std.Io.net.IpAddress,
                        _: std.Uri,
                        _: Runtime.Limits,
                    ) Runtime.Error!Runtime.HandshakeClient {
                        return error.InvalidUri;
                    }
                }.connect,
            };
            try std.testing.expectError(
                error.InvalidPoolOptions,
                Self.init(std.testing.allocator, threaded.io(), .{
                    .local_address = .{ .ip4 = .loopback(0) },
                    .idle = .{
                        .max_idle_per_origin = 2,
                        .max_idle_total = 1,
                    },
                    .connector = connector,
                }),
            );
        }
    };
}

test "HTTP/3 handshake client pool reuses one authenticated connection" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            for (0..2) |index| {
                var request = session.receiveRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                const expected = if (index == 0) "/one" else "/two?x=1";
                if (!std.mem.eql(u8, request.request.path, expected)) {
                    self.err = error.InvalidUri;
                    return;
                }
                session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .body = if (index == 0) "one" else "two",
                }) catch |err| {
                    self.err = err;
                    return;
                };
                self.requests += 1;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const CountingConnector = struct {
        inner: DefaultConnectorContext(Runtime),
        connects: usize = 0,

        fn connect(
            context: *anyopaque,
            allocator_value: std.mem.Allocator,
            io_value: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connects += 1;
            return self.inner.connector().connect(
                &self.inner,
                allocator_value,
                io_value,
                local_address,
                uri,
                limits,
            );
        }
    };
    var connect_context = CountingConnector{ .inner = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = .{
            .context = &connect_context,
            .connect = CountingConnector.connect,
        },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/one",
        .{server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/two?x=1",
        .{server.address().ip4.port},
    );
    defer allocator.free(second_uri);

    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), connect_context.connects);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.requests);
}

test "HTTP/3 handshake client pool enforces checked-out capacity" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.quic_server.endpoint.io);
                return;
            };
            defer session.deinit();
            self.accepted.set(self.server.quic_server.endpoint.io);
            self.release.wait(self.server.quic_server.endpoint.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/held",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        pool.acquireUri(uri),
    );
    first.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool timeout and close wake waiters" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Runtime.HandshakeServer,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.quic_server.endpoint.io);
                return;
            };
            defer session.deinit();
            self.accepted.set(self.server.quic_server.endpoint.io);
            self.release.wait(self.server.quic_server.endpoint.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/wait",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(uri, .fromMilliseconds(5)),
    );
    const Waiter = struct {
        pool: *ClientPool,
        uri: []const u8,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var acquired = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            acquired.discard();
        }
    };
    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    pool.close();
    waiter_thread.join();
    try std.testing.expectEqual(error.PoolClosed, waiter.err.?);
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool discards GOAWAY leases" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            session.sendResponse(request.stream_id, .{
                .status = 204,
                .request_method = request.request.method,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var connect_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = .{
            .context = &connect_context,
            .connect = connect_context.connector().connect,
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/goaway",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    var response = try lease.client().request(.{
        .method = "GET",
        .path = "/goaway",
        .scheme = "https",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    lease.client().control.peer_goaway_id = lease.client().next_stream_id;
    try lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool releases failed reservations" {
    const Runtime = @import("../runtime.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Refusing = struct {
        calls: usize = 0,
        fn connect(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.ConnectionRefused;
        }
    };
    var refusing = Refusing{};
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 1,
        .connector = .{
            .context = &refusing,
            .connect = Refusing.connect,
        },
    });
    defer pool.deinit();

    inline for (0..2) |_| {
        try std.testing.expectError(
            error.ConnectionRefused,
            pool.acquireUri("https://localhost/"),
        );
        try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    }
    try std.testing.expectEqual(@as(usize, 2), refusing.calls);
}

test "HTTP/3 handshake client pool zero idle capacity releases totals" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Runtime.HandshakeServer,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            session.sendResponse(request.stream_id, .{
                .status = 204,
                .request_method = request.request.method,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .idle = .{
            .max_idle_per_origin = 0,
            .max_idle_total = 0,
        },
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/no-idle",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var response = try pool.requestUri(uri, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn nowMillis(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return @as(u64, @intCast(now)) / std.time.ns_per_ms;
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
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.GoAwayReceived,
        error.SocketUnconnected,
        error.HandshakeReceiveFailed,
        error.HandshakeSendFailed,
        => true,
        else => false,
    };
}
