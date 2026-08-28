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
            self.idle.deinit();
            self.* = undefined;
        }

        pub fn acquireUri(
            self: *Self,
            uri_text: []const u8,
        ) Runtime.Error!Lease {
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            const origin = try http3.requestOrigin(
                uri.scheme,
                endpoint.authority,
            );
            var origin_key = try http3.originKeyFromOrigin(
                self.allocator,
                origin,
            );
            errdefer origin_key.deinit();

            self.mutex.lockUncancelable(self.io);
            const reused = self.idle.acquire(origin, nowMillis(self.io));
            if (reused != null) self.leased += 1;
            self.mutex.unlock(self.io);
            if (reused) |client| {
                const lease: Lease = .{
                    .pool = self,
                    .client_value = client,
                    .origin_key = origin_key,
                    .was_reused = true,
                };
                origin_key = undefined;
                return lease;
            }

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
            self.leased += 1;
            self.mutex.unlock(self.io);
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
        ) Runtime.Error!Runtime.OwnedHandshakeResponse {
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
            _ = self.idle.pruneExpired(nowMillis(self.io));
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

        fn release(
            self: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
        ) std.mem.Allocator.Error!void {
            var client = client_value;
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.leased != 0);
            self.leased -= 1;
            if (!client.isReusable()) {
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                client.deinit();
                return;
            }
            self.idle.releaseKey(
                client,
                origin_key,
                nowMillis(self.io),
            ) catch |err| {
                self.mutex.unlock(self.io);
                client.deinit();
                return err;
            };
            self.mutex.unlock(self.io);
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
            self.mutex.unlock(self.io);
            client.deinit();
        }

        fn dropClient(_: std.mem.Allocator, client_value: Client) void {
            var client = client_value;
            client.deinit();
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
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.requests);
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
