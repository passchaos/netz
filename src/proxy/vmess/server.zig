//! VMess AEAD server with AES-GCM/ChaCha20-Poly1305 body support.

const std = @import("std");

const protocol = @import("protocol.zig");
const aead = @import("aead.zig");
const body = @import("body.zig");
const vmess_crypto = @import("crypto.zig");
const replay = @import("../shadowsocks/replay.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const tls_server = @import("../tls/server.zig");
const ws_transport = @import("../transport/ws.zig");
const tls_relay = @import("../internal/tls_relay.zig");
const quic_relay = @import("../internal/quic_relay.zig");
const udp_relay = @import("../internal/udp_relay.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const Config = struct {
    uuid: [16]u8,
    /// Required by the TCP/TLS transport. QUIC transports provide their own
    /// TLS layer and leave this null.
    tls: ?tls_server.Config = null,
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    relay_buffer_size: usize = 16 * 1024,
    allow_udp: bool = false,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
    replay: ?*replay.Cache = null,
    transport: Transport = .tls,
    ws_path: []const u8 = "/",
};

pub const Transport = enum { tls, ws, quic, h2, grpc };

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    AuthenticationFailed,
    UnsupportedCommand,
    InvalidHeader,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    listener: net.Server,
    limiter: limits.ConnectionLimiter,
    running: std.atomic.Value(bool) = .init(true),
    active_jobs: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        config: Config,
    ) !Server {
        const listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        var limiter = try limits.ConnectionLimiter.init(
            allocator,
            io,
            config.limits,
        );
        errdefer limiter.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .listener = listener,
            .limiter = limiter,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);
        while (self.active_jobs.load(.acquire) != 0) {
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch {};
        }
        self.limiter.deinit();
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn requestStop(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn serve(self: *Server) !void {
        while (self.running.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |err| switch (err) {
                error.SocketNotListening, error.Canceled => break,
                else => continue,
            };
            const peer = stream.socket.address;
            const job = self.allocator.create(Job) catch {
                stream.close(self.io);
                continue;
            };
            job.* = .{ .server = self, .stream = stream, .peer = peer };
            self.active_jobs.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
                self.active_jobs.fetchSub(1, .release);
                self.allocator.destroy(job);
                stream.close(self.io);
                continue;
            };
            thread.detach();
        }
    }

    const Job = struct {
        server: *Server,
        stream: net.Stream,
        peer: net.IpAddress,

        fn run(self: *Job) void {
            const server = self.server;
            defer server.active_jobs.fetchSub(1, .release);
            defer server.allocator.destroy(self);
            const tls_config = server.config.tls orelse {
                self.stream.close(server.io);
                return;
            };
            var connection = tls_server.Connection.accept(
                server.allocator,
                server.io,
                self.stream,
                tls_config,
            ) catch {
                self.stream.close(server.io);
                return;
            };
            defer connection.deinit();
            switch (server.config.transport) {
                .tls => processTlsConnection(
                    server.allocator,
                    server.io,
                    &connection,
                    self.peer,
                    server.config,
                    &server.limiter,
                ) catch {},
                .ws => {
                    var ws_stream = ws_transport.Stream(
                        @TypeOf(connection),
                    ).accept(
                        server.allocator,
                        server.io,
                        &connection,
                        .{ .path = server.config.ws_path },
                    ) catch return;
                    defer ws_stream.deinit();
                    processTlsConnection(
                        server.allocator,
                        server.io,
                        &ws_stream,
                        self.peer,
                        server.config,
                        &server.limiter,
                    ) catch {};
                },
                .quic, .h2, .grpc => {},
            }
        }
    };
};

pub fn processTlsConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    peer: net.IpAddress,
    config: Config,
    limiter: ?*limits.ConnectionLimiter,
) !void {
    if (config.rate_limiter) |value| {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        if (!value.allow(peer, 1, now)) return error.RateLimited;
    }
    if (limiter) |value| try value.acquire(peer);
    defer if (limiter) |value| value.release(peer);
    if (config.stats) |value| value.connectionOpened();
    defer if (config.stats) |value| value.connectionClosed();

    const now_seconds: i64 = @intCast(
        @divTrunc(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s),
    );
    var host_storage: [255]u8 = undefined;
    var prefix: [16]u8 = undefined;
    readExact(connection, &prefix) catch |err| {
        if (config.stats) |value| value.authFailure();
        return err;
    };

    var cmd_key: [16]u8 = undefined;
    vmess_crypto.cmdKey(config.uuid, &cmd_key);
    const auth_info = aead.decodeAuthID(cmd_key, prefix);
    const timestamp_delta = if (auth_info.timestamp > now_seconds)
        auth_info.timestamp - now_seconds
    else
        now_seconds - auth_info.timestamp;
    if (!auth_info.valid_checksum or timestamp_delta > 120) {
        if (config.stats) |value| value.authFailure();
        return error.AuthenticationFailed;
    }
    if (config.replay) |cache| {
        if (!cache.accept(&prefix)) return error.ReplayDetected;
    }
    const opened = aead.openHeader(
        allocator,
        cmd_key,
        prefix,
        connection,
    ) catch |err| {
        if (config.stats) |value| value.authFailure();
        return err;
    };
    defer allocator.free(opened.data);
    const decoded = protocol.parsePlainHeader(
        opened.data,
        &host_storage,
    ) catch |err| {
        if (config.stats) |value| value.authFailure();
        return err;
    };
    return connectAndRelay(
        allocator,
        io,
        connection,
        config,
        decoded,
    );
}

fn connectAndRelay(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    config: Config,
    decoded: protocol.DecodedRequest,
) !void {
    switch (decoded.request.command) {
        .tcp => {
            const target: destination.Target = switch (decoded.request.address) {
                .ip => |ip| .{ .ip = ip },
                .domain => |domain| .{ .domain = .{
                    .host = domain.host,
                    .port = domain.port,
                } },
            };
            const upstream = destination.connectTarget(
                allocator,
                io,
                reload.policyFor(config.acl, config.policy_store),
                target,
                .connect,
                config.connect_timeout,
            ) catch |err| {
                if (config.stats) |value| {
                    if (err == error.DestinationDenied) value.deniedRequest();
                }
                return err;
            };
            defer upstream.close(io);

            try aead.encodeResponseHeader(
                decoded.session.body_key,
                decoded.session.body_iv,
                decoded.session.response_header,
                connection,
            );

            if (decoded.session.security != protocol.security_none) {
                const keys = responseKeys(decoded.session);
                const algorithm: body.Algorithm =
                    if (decoded.session.security == protocol.security_aes128_gcm)
                        .aes_128_gcm
                    else
                        .chacha20_poly1305;
                var encryptor = body.Encryptor.init(
                    algorithm,
                    keys.key,
                    keys.iv,
                );
                defer encryptor.deinit();
                var decryptor = body.Decryptor.init(
                    algorithm,
                    decoded.session.body_key,
                    decoded.session.body_iv,
                );
                defer decryptor.deinit();
                return relayBody(
                    allocator,
                    io,
                    connection,
                    upstream,
                    config,
                    &decryptor,
                    &encryptor,
                );
            }

            if (comptime @hasDecl(@TypeOf(connection.*), "readTimeout")) {
                return quic_relay.relay(
                    allocator,
                    io,
                    connection,
                    upstream,
                    config.idle_timeout,
                    config.relay_buffer_size,
                );
            }
            return tls_relay.relay(
                allocator,
                io,
                connection,
                upstream,
                "",
                config.idle_timeout,
                config.relay_buffer_size,
                config.stats,
            );
        },
        .udp => {
            if (!config.allow_udp) return error.UnsupportedCommand;
            // Message-framed transports do not expose the blocking chunk
            // reader this UDP path needs; keep UDP on TLS/WS byte streams.
            if (comptime @hasDecl(@TypeOf(connection.*), "readTimeout")) {
                return error.UnsupportedCommand;
            }
            const target: destination.Target = switch (decoded.request.address) {
                .ip => |ip| .{ .ip = ip },
                .domain => |domain| .{ .domain = .{
                    .host = domain.host,
                    .port = domain.port,
                } },
            };
            const resolved = try destination.resolveTarget(
                allocator,
                io,
                reload.policyFor(config.acl, config.policy_store),
                target,
                .udp_associate,
                config.connect_timeout,
            );
            const bind_address = switch (resolved) {
                .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
                .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
            };
            const socket = try bind_address.bind(
                io,
                .{ .mode = .dgram, .protocol = .udp },
            );
            defer socket.close(io);

            try aead.encodeResponseHeader(
                decoded.session.body_key,
                decoded.session.body_iv,
                decoded.session.response_header,
                connection,
            );

            if (decoded.session.security == protocol.security_none) {
                return udp_relay.relayThreaded(
                    allocator,
                    io,
                    connection,
                    socket,
                    resolved,
                    config.idle_timeout,
                    config.relay_buffer_size,
                    config.stats,
                );
            }

            const keys = responseKeys(decoded.session);
            const algorithm: body.Algorithm =
                if (decoded.session.security == protocol.security_aes128_gcm)
                    .aes_128_gcm
                else
                    .chacha20_poly1305;
            var encryptor = body.Encryptor.init(
                algorithm,
                keys.key,
                keys.iv,
            );
            defer encryptor.deinit();
            var decryptor = body.Decryptor.init(
                algorithm,
                decoded.session.body_key,
                decoded.session.body_iv,
            );
            defer decryptor.deinit();
            return relayUdpBody(
                allocator,
                io,
                connection,
                socket,
                resolved,
                config,
                &decryptor,
                &encryptor,
            );
        },
    }
}

fn relayUdpBody(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    socket: net.Socket,
    target: net.IpAddress,
    config: Config,
    decryptor: anytype,
    encryptor: anytype,
) !void {
    const plain = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(plain);
    const wire = try allocator.alloc(
        u8,
        config.relay_buffer_size + 2 + body.tag_length,
    );
    defer allocator.free(wire);

    const Shared = struct {
        io: std.Io,
        connection: @TypeOf(connection),
        socket: net.Socket,
        receive_buffer: []u8,
        wire: []u8,
        encryptor: @TypeOf(encryptor),
        closed: std.atomic.Value(bool) = .init(false),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pump() catch |err| {
                self.err = err;
                self.closed.store(true, .release);
            };
        }

        fn pump(self: *@This()) !void {
            while (!self.closed.load(.acquire)) {
                const message = self.socket.receiveTimeout(
                    self.io,
                    self.receive_buffer,
                    .{ .duration = .{
                        .raw = .fromMilliseconds(100),
                        .clock = .awake,
                    } },
                ) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };
                if (message.flags.trunc) continue;
                const len = try self.encryptor.writeChunk(
                    self.wire,
                    message.data,
                );
                try self.connection.writeAll(self.wire[0..len]);
            }
        }
    };

    var shared = Shared{
        .io = io,
        .connection = connection,
        .socket = socket,
        .receive_buffer = plain,
        .wire = wire,
        .encryptor = encryptor,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.closed.store(true, .release);
        thread.join();
    };

    while (true) {
        const chunk = decryptor.readChunk(connection, plain) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (chunk == null) break;
        try socket.send(io, &target, chunk.?);
    }

    shared.closed.store(true, .release);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const len = encryptor.writeTermination(wire) catch return;
    connection.writeAll(wire[0..len]) catch {};
}

fn responseKeys(
    session: protocol.ServerSession,
) struct { key: [16]u8, iv: [16]u8 } {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&session.body_key, &key_digest, .{});
    var iv_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&session.body_iv, &iv_digest, .{});
    return .{ .key = key_digest[0..16].*, .iv = iv_digest[0..16].* };
}

fn relayBody(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    upstream: net.Stream,
    config: Config,
    decryptor: anytype,
    encryptor: anytype,
) !void {
    const plain = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(plain);
    const wire = try allocator.alloc(
        u8,
        config.relay_buffer_size + 2 + body.tag_length,
    );
    defer allocator.free(wire);
    const upstream_buffer = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(upstream_buffer);

    const Shared = struct {
        io: std.Io,
        connection: @TypeOf(connection),
        upstream: net.Stream,
        encryptor: @TypeOf(encryptor),
        buffer: []u8,
        wire: []u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pump() catch |err| {
                self.err = err;
                self.upstream.shutdown(self.io, .both) catch {};
            };
        }

        fn pump(self: *@This()) !void {
            while (true) {
                const count = io_helpers.readSome(
                    self.io,
                    self.upstream,
                    self.buffer,
                    null,
                ) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (count == 0) break;
                const len = try self.encryptor.writeChunk(
                    self.wire,
                    self.buffer[0..count],
                );
                try self.connection.writeAll(self.wire[0..len]);
            }
            const len = try self.encryptor.writeTermination(self.wire);
            self.connection.writeAll(self.wire[0..len]) catch {};
        }
    };

    var shared = Shared{
        .io = io,
        .connection = connection,
        .upstream = upstream,
        .encryptor = encryptor,
        .buffer = upstream_buffer,
        .wire = wire,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        upstream.shutdown(io, .both) catch {};
        thread.join();
    };

    while (true) {
        const chunk = try decryptor.readChunk(connection, plain);
        if (chunk == null) break;
        try io_helpers.writeAll(
            io,
            upstream,
            chunk.?,
            currentDeadline(io, config.idle_timeout),
        );
    }
    upstream.shutdown(io, .send) catch {};
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn currentDeadline(
    io: std.Io,
    timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, timeout) catch null;
}

fn readExact(connection: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.TruncatedRequest;
        offset += count;
    }
}
