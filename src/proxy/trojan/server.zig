//! Trojan TLS server with password authentication and CONNECT relay.

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
const ws_transport = @import("../transport/ws.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const Config = struct {
    password: []const u8,
    password_mode: protocol.PasswordMode = .hashed,
    tls: tls_server.Config,
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

pub const Transport = enum { tls, ws };

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    InvalidPassword,
    AuthenticationFailed,
    UnsupportedCommand,
    TruncatedRequest,
    LineTooLong,
    InvalidRequest,
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
        if (config.password.len == 0) return error.InvalidPassword;
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
            var connection = tls_server.Connection.accept(
                server.allocator,
                server.io,
                self.stream,
                server.config.tls,
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
            }
        }
    };
};

/// Process one authenticated Trojan TLS connection.
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

    if (config.password.len == 0) return error.InvalidPassword;

    var password_line_storage: [protocol.max_password_line_len]u8 = undefined;
    const password_line = try readLine(connection, &password_line_storage);
    if (!protocol.verifyPasswordLine(
        config.password,
        config.password_mode,
        password_line,
    )) {
        if (config.stats) |value| value.authFailure();
        return error.AuthenticationFailed;
    }

    var command_byte: [1]u8 = undefined;
    try readExact(connection, &command_byte);
    const command = try protocol.commandFromByte(command_byte[0]);

    var address_storage: [1 + 1 + 255 + 2]u8 = undefined;
    const decoded = try readAddress(connection, &address_storage);

    var first_payload: [1]u8 = undefined;
    var initial_payload: []const u8 = "";
    const first_count = try connection.read(&first_payload);
    if (first_count == 0) {
        return error.TruncatedRequest;
    }
    if (first_payload[0] == '\r') {
        var second: [1]u8 = undefined;
        try readExact(connection, &second);
        if (second[0] != '\n') return error.InvalidRequest;
    } else {
        initial_payload = first_payload[0..1];
    }

    switch (command) {
        .connect => {
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

            if (initial_payload.len > 0) {
                try io_helpers.writeAll(
                    io,
                    upstream,
                    initial_payload,
                    currentDeadline(io, config.idle_timeout),
                );
            }
            return relay(
                allocator,
                io,
                connection,
                upstream,
                config,
            );
        },
        .udp_associate => {
            if (!config.allow_udp) return error.UnsupportedCommand;
            try connection.writeAll("\r\n");
            const socket = try (net.IpAddress{ .ip4 = .unspecified(0) }).bind(
                io,
                .{ .mode = .dgram, .protocol = .udp },
            );
            defer socket.close(io);
            return relayUdpAssociate(
                allocator,
                io,
                connection,
                socket,
                config,
                initial_payload,
            );
        },
    }
}

fn relayUdpAssociate(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    socket: net.Socket,
    config: Config,
    initial_payload: []const u8,
) !void {
    const address_storage = try allocator.alloc(u8, 1 + 1 + 255 + 2);
    defer allocator.free(address_storage);
    const data = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(data);

    const Shared = struct {
        io: std.Io,
        connection: @TypeOf(connection),
        socket: net.Socket,
        allocator: std.mem.Allocator,
        buffer: []u8,
        config: Config,
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
                    self.buffer,
                    .{ .duration = .{
                        .raw = .fromMilliseconds(100),
                        .clock = .awake,
                    } },
                ) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };
                if (message.flags.trunc) continue;
                const encoded = protocol.buildUdpPacket(
                    self.allocator,
                    .{ .ip = message.from },
                    message.data,
                ) catch continue;
                defer self.allocator.free(encoded);
                try self.connection.writeAll(encoded);
                if (self.config.stats) |value| {
                    value.addBytesOut(@intCast(message.data.len));
                }
            }
        }
    };

    var shared = Shared{
        .io = io,
        .connection = connection,
        .socket = socket,
        .allocator = allocator,
        .buffer = data,
        .config = config,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.closed.store(true, .release);
        thread.join();
    };

    var first_atyp: ?u8 = if (initial_payload.len > 0)
        initial_payload[0]
    else
        null;
    while (true) {
        const packet = readUdpPacket(
            connection,
            first_atyp,
            address_storage,
            data,
        ) catch |err| switch (err) {
            error.EndOfStream, error.TruncatedRequest => break,
            else => return err,
        };
        first_atyp = null;
        const target: destination.Target = switch (packet.address) {
            .ip => |ip| .{ .ip = ip },
            .domain => |domain| .{ .domain = .{
                .host = domain.host,
                .port = domain.port,
            } },
        };
        const resolved = destination.resolveTarget(
            allocator,
            io,
            reload.policyFor(config.acl, config.policy_store),
            target,
            .udp_associate,
            config.connect_timeout,
        ) catch continue;
        socket.send(io, &resolved, packet.payload) catch continue;
        if (config.stats) |value| {
            value.addBytesIn(@intCast(packet.payload.len));
        }
    }

    shared.closed.store(true, .release);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const UdpPacket = struct {
    address: codec.Address,
    payload: []const u8,
};

fn readUdpPacket(
    connection: anytype,
    first_atyp: ?u8,
    address_storage: []u8,
    data: []u8,
) !UdpPacket {
    var atyp: u8 = undefined;
    if (first_atyp) |value| {
        atyp = value;
    } else {
        var byte: [1]u8 = undefined;
        try readExact(connection, &byte);
        atyp = byte[0];
    }
    address_storage[0] = atyp;

    var decoded: codec.DecodedAddress = undefined;
    switch (atyp) {
        0x01 => {
            try readExact(connection, address_storage[1..7]);
            decoded = try codec.decodeSocks5Address(address_storage[0..7], 0);
        },
        0x04 => {
            try readExact(connection, address_storage[1..19]);
            decoded = try codec.decodeSocks5Address(address_storage[0..19], 0);
        },
        0x03 => {
            var length: [1]u8 = undefined;
            try readExact(connection, &length);
            if (length[0] == 0) return error.InvalidRequest;
            address_storage[1] = length[0];
            const total = 2 + @as(usize, length[0]) + 2;
            try readExact(connection, address_storage[2..total]);
            decoded = try codec.decodeSocks5Address(
                address_storage[0..total],
                0,
            );
        },
        else => return error.InvalidRequest,
    }

    var length_bytes: [2]u8 = undefined;
    try readExact(connection, &length_bytes);
    const length = std.mem.readInt(u16, &length_bytes, .big);
    if (length > data.len) return error.BufferTooSmall;
    try readExact(connection, data[0..length]);
    return .{ .address = decoded.address, .payload = data[0..length] };
}

fn relay(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: anytype,
    upstream: net.Stream,
    config: Config,
) !void {
    const buffer = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(buffer);

    const Shared = struct {
        io: std.Io,
        connection: @TypeOf(connection),
        upstream: net.Stream,
        idle_timeout: std.Io.Duration,
        buffer: []u8,
        stats: ?*stats_mod.Stats,
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
                    currentDeadline(self.io, self.idle_timeout),
                ) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (count == 0) break;
                try self.connection.writeAll(self.buffer[0..count]);
                if (self.stats) |value| {
                    value.addBytesOut(@intCast(count));
                }
            }
        }
    };

    var shared = Shared{
        .io = io,
        .connection = connection,
        .upstream = upstream,
        .idle_timeout = config.idle_timeout,
        .buffer = buffer,
        .stats = config.stats,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        upstream.shutdown(io, .both) catch {};
        thread.join();
    };

    while (true) {
        const count = try connection.read(buffer);
        if (count == 0) break;
        try io_helpers.writeAll(
            io,
            upstream,
            buffer[0..count],
            currentDeadline(io, config.idle_timeout),
        );
    }
    upstream.shutdown(io, .send) catch {};
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn readLine(
    connection: anytype,
    storage: []u8,
) ![]const u8 {
    var used: usize = 0;
    while (used < storage.len) {
        var byte: [1]u8 = undefined;
        const count = try connection.read(&byte);
        if (count == 0) return error.TruncatedRequest;
        if (byte[0] == '\r') {
            var second: [1]u8 = undefined;
            try readExact(connection, &second);
            if (second[0] != '\n') return error.InvalidRequest;
            return storage[0..used];
        }
        if (byte[0] == '\n') return error.InvalidRequest;
        storage[used] = byte[0];
        used += 1;
    }
    return error.LineTooLong;
}

fn readAddress(
    connection: anytype,
    storage: []u8,
) !codec.DecodedAddress {
    var address_type: [1]u8 = undefined;
    try readExact(connection, &address_type);
    storage[0] = address_type[0];
    switch (address_type[0]) {
        0x01 => {
            try readExact(connection, storage[1 .. 1 + 4 + 2]);
            return codec.decodeSocks5Address(storage[0 .. 1 + 4 + 2], 0);
        },
        0x04 => {
            try readExact(connection, storage[1 .. 1 + 16 + 2]);
            return codec.decodeSocks5Address(storage[0 .. 1 + 16 + 2], 0);
        },
        0x03 => {
            var length: [1]u8 = undefined;
            try readExact(connection, &length);
            if (length[0] == 0) return error.InvalidRequest;
            storage[1] = length[0];
            const total = 2 + @as(usize, length[0]) + 2;
            if (total > storage.len) return error.InvalidRequest;
            try readExact(connection, storage[2..total]);
            return codec.decodeSocks5Address(storage[0..total], 0);
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

fn currentDeadline(
    io: std.Io,
    idle_timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, idle_timeout) catch null;
}
