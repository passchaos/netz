//! VLESS TLS server with UUID authentication and TCP relay.

const std = @import("std");

const protocol = @import("protocol.zig");
const codec = @import("../socks/codec.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const tls_server = @import("../tls/server.zig");
const tls_relay = @import("../internal/tls_relay.zig");
const ws_transport = @import("../transport/ws.zig");
const quic_relay = @import("../internal/quic_relay.zig");
const udp_relay = @import("../internal/udp_relay.zig");

const net = std.Io.net;

pub const Config = struct {
    uuid: protocol.Uuid,
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
    transport: Transport = .tls,
    ws_path: []const u8 = "/",
};

pub const Transport = enum { tls, ws, quic, h2, grpc };

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    InvalidRequest,
    AuthenticationFailed,
    UnsupportedCommand,
    TruncatedRequest,
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
        var listener = try address.listen(io, .{ .reuse_address = true });
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
            _ = self.active_jobs.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
                _ = self.active_jobs.fetchSub(1, .release);
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
            defer _ = server.active_jobs.fetchSub(1, .release);
            defer server.allocator.destroy(self);
            var connection = tls_server.Connection.accept(
                server.allocator,
                server.io,
                self.stream,
                server.config.tls orelse {
                    self.stream.close(server.io);
                    return;
                },
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

    var version: [1]u8 = undefined;
    try readExact(connection, &version);
    if (version[0] != 0) return error.InvalidRequest;

    var uuid: protocol.Uuid = undefined;
    try readExact(connection, &uuid);
    if (!protocol.uuidEql(config.uuid, uuid)) {
        if (config.stats) |value| value.authFailure();
        return error.AuthenticationFailed;
    }

    var addons_length: [1]u8 = undefined;
    try readExact(connection, &addons_length);
    var addons: [255]u8 = undefined;
    try readExact(connection, addons[0..@as(usize, addons_length[0])]);

    var command_byte: [1]u8 = undefined;
    try readExact(connection, &command_byte);
    const command = try protocol.Command.fromByte(command_byte[0]);

    var port_bytes: [2]u8 = undefined;
    try readExact(connection, &port_bytes);
    const port = std.mem.readInt(u16, &port_bytes, .big);

    var address_storage: [1 + 1 + 255 + 16]u8 = undefined;
    const decoded = try readAddress(connection, &address_storage, port);

    // VLESS response header: version 0 and an empty addon. Real clients
    // consume this prefix before the relayed payload.
    try writeAll(connection, &.{ 0, 0 });

    switch (command) {
        .tcp => {
            const target: destination.Target = switch (decoded.address) {
                .ip => |ip| .{ .ip = ip },
                .domain => |domain| .{ .domain = .{
                    .host = domain.host,
                    .port = domain.port,
                } },
            };
            const upstream = try destination.connectTarget(
                allocator,
                io,
                reload.policyFor(config.acl, config.policy_store),
                target,
                .connect,
                config.connect_timeout,
            );
            defer upstream.close(io);
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
            const target: destination.Target = switch (decoded.address) {
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
            if (comptime @hasDecl(@TypeOf(connection.*), "readTimeout")) {
                return udp_relay.relayPolled(
                    allocator,
                    io,
                    connection,
                    socket,
                    resolved,
                    config.relay_buffer_size,
                    config.stats,
                );
            }
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
        },
    }
}

fn readAddress(
    connection: anytype,
    storage: []u8,
    port: u16,
) !protocol.DecodedAddress {
    var address_type: [1]u8 = undefined;
    try readExact(connection, &address_type);
    storage[0] = address_type[0];
    switch (address_type[0]) {
        1 => {
            try readExact(connection, storage[1..5]);
            return protocol.decodeAddress(storage[0..5], 0, port);
        },
        2 => {
            var length: [1]u8 = undefined;
            try readExact(connection, &length);
            if (length[0] == 0) return error.InvalidRequest;
            storage[1] = length[0];
            const total = 2 + @as(usize, length[0]);
            try readExact(connection, storage[2..total]);
            return protocol.decodeAddress(storage[0..total], 0, port);
        },
        3 => {
            try readExact(connection, storage[1..17]);
            return protocol.decodeAddress(storage[0..17], 0, port);
        },
        else => return error.InvalidRequest,
    }
}

fn readExact(connection: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.TruncatedRequest;
        offset += count;
    }
}

fn writeAll(connection: anytype, bytes: []const u8) !void {
    try connection.writeAll(bytes);
}

test "VLESS server rejects an unsupported command before connecting" {
    try std.testing.expectEqual(
        error.UnsupportedCommand,
        protocol.Command.fromByte(0xff),
    );
}
