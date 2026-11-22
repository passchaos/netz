//! SOCKS5 server state machine.

const std = @import("std");

const codec = @import("codec.zig");
const auth = @import("auth.zig");
const relay = @import("relay.zig");
const udp_relay = @import("udp_relay.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const io_helpers = @import("../internal/io.zig");
const destination = @import("../runtime/destination.zig");

const net = std.Io.net;

pub const Config = struct {
    auth: auth.Policy = .{},
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    handshake_timeout: std.Io.Duration = .fromSeconds(10),
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    reader_buffer_size: usize = 4096,
    relay_buffer_size: usize = 16 * 1024,
    /// BIND opens a listening socket and is therefore opt-in.
    allow_bind: bool = false,
    bind_timeout: std.Io.Duration = .fromSeconds(30),
    /// UDP ASSOCIATE is opt-in for deployments that only want TCP.
    allow_udp: bool = true,
    udp_idle_timeout: std.Io.Duration = .fromSeconds(60),
    udp_poll_interval: std.Io.Duration = .fromMilliseconds(250),
    max_udp_datagram_size: usize = 65535,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    UnsupportedVersion,
    AuthenticationFailed,
    NoAcceptableAuthentication,
    MalformedRequest,
    DestinationDenied,
    InvalidBindRequest,
    BindNotAllowed,
    UdpNotAllowed,
    UdpRequestInvalid,
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
        // Callers must stop accepting before deinit; active jobs keep their
        // own bounded connection state and are joined by the process.
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
            job.* = .{
                .server = self,
                .stream = stream,
                .peer = peer,
            };
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
            defer self.stream.close(server.io);
            processConnection(
                server.allocator,
                server.io,
                self.stream,
                self.peer,
                server.config,
                &server.limiter,
            ) catch {};
        }
    };
};

/// Process one accepted connection. The caller retains ownership of `stream`.
pub fn processConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
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

    const handshake_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    const storage = try allocator.alloc(u8, config.reader_buffer_size);
    defer allocator.free(storage);
    var reader = io_helpers.BufferedReader.init(
        io,
        stream,
        storage,
        handshake_deadline,
    );

    const version = reader.readByte() catch |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    };
    return switch (version) {
        @intFromEnum(codec.Version.v5) => handleSocks5(
            allocator,
            io,
            stream,
            peer,
            config,
            &reader,
        ),
        else => error.UnsupportedVersion,
    };
}

fn handleSocks5(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    peer: net.IpAddress,
    config: Config,
    reader: *io_helpers.BufferedReader,
) !void {
    const deadline = reader.deadline;

    var method_count: [1]u8 = undefined;
    try reader.readExact(&method_count);
    if (method_count[0] == 0) return error.MalformedRequest;
    var methods: [255]u8 = undefined;
    try reader.readExact(methods[0..method_count[0]]);

    const selection = auth.selectMethod(
        methods[0..method_count[0]],
        config.auth,
    );
    const method: codec.Method = switch (selection) {
        .none => .none,
        .username_password => .username_password,
        .reject => {
            var reply: [2]u8 = undefined;
            try codec.encodeSocks5Method(&reply, .no_acceptable);
            try io_helpers.writeAll(io, stream, &reply, deadline);
            return error.NoAcceptableAuthentication;
        },
    };
    var method_reply: [2]u8 = undefined;
    try codec.encodeSocks5Method(&method_reply, method);
    try io_helpers.writeAll(io, stream, &method_reply, deadline);

    if (selection == .username_password) {
        authenticate(io, stream, reader, config.auth.authenticator.?) catch |err| {
            if (config.stats) |value| value.authFailure();
            return err;
        };
    }

    var head: [4]u8 = undefined;
    try reader.readExact(&head);
    if (head[0] != @intFromEnum(codec.Version.v5)) {
        return error.MalformedRequest;
    }
    if (head[2] != 0) return error.MalformedRequest;
    const command = codec.Command.fromByte(head[1]) catch |err| {
        var reply: [64]u8 = undefined;
        const len = try codec.encodeSocks5Reply(
            &reply,
            .command_not_supported,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        );
        try io_helpers.writeAll(io, stream, reply[0..len], deadline);
        return err;
    };

    var address_storage: [1 + 255 + 2]u8 = undefined;
    address_storage[0] = head[3];
    const rest_len = try addressRemainderLength(head[3], reader);
    try reader.readExact(address_storage[1..][0..rest_len]);
    const decoded = try codec.decodeSocks5Address(
        address_storage[0 .. 1 + rest_len],
        0,
    );

    switch (command) {
        .connect => {
            try handleConnect(
                allocator,
                io,
                stream,
                config,
                reader,
                decoded.address,
            );
        },
        .bind => {
            try handleBind(
                allocator,
                io,
                stream,
                config,
                reader,
                decoded.address,
            );
        },
        .udp_associate => {
            try handleUdpAssociate(
                allocator,
                io,
                stream,
                peer,
                config,
                reader,
                decoded.address,
            );
        },
        else => return error.MalformedRequest,
    }
}

fn addressRemainderLength(
    address_type: u8,
    reader: *io_helpers.BufferedReader,
) !usize {
    return switch (address_type) {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => blk: {
            var length: [1]u8 = undefined;
            try reader.readExact(&length);
            if (length[0] == 0) return error.MalformedRequest;
            break :blk @as(usize, length[0]) + 2;
        },
        else => error.MalformedRequest,
    };
}

fn authenticate(
    io: std.Io,
    stream: net.Stream,
    reader: *io_helpers.BufferedReader,
    authenticator: auth.Authenticator,
) !void {
    const deadline = reader.deadline;
    var prefix: [2]u8 = undefined;
    try reader.readExact(&prefix);
    if (prefix[0] != 1 or prefix[1] == 0) {
        return error.MalformedRequest;
    }
    var username_storage: [255]u8 = undefined;
    try reader.readExact(username_storage[0..prefix[1]]);
    var password_length: [1]u8 = undefined;
    try reader.readExact(&password_length);
    if (password_length[0] == 0) return error.MalformedRequest;
    var password_storage: [255]u8 = undefined;
    try reader.readExact(password_storage[0..password_length[0]]);

    const ok = authenticator.verifyCredentials(
        username_storage[0..prefix[1]],
        password_storage[0..password_length[0]],
    );
    var reply: [2]u8 = .{ 1, if (ok) 0 else 1 };
    try io_helpers.writeAll(io, stream, &reply, deadline);
    if (!ok) return error.AuthenticationFailed;
}

fn handleConnect(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    config: Config,
    reader: *io_helpers.BufferedReader,
    address: codec.Address,
) !void {
    const target = connectTarget(allocator, io, config, address) catch |err| {
        if (config.stats) |value| {
            if (err == error.DestinationDenied) value.deniedRequest();
        }
        try sendConnectFailure(io, stream, config, err);
        return err;
    };
    defer target.close(io);

    const reply_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    var reply: [64]u8 = undefined;
    const len = try codec.encodeSocks5Reply(
        &reply,
        .succeeded,
        .{ .ip = .{ .ip4 = .unspecified(0) } },
    );
    try io_helpers.writeAll(io, stream, reply[0..len], reply_deadline);

    return relay.relay(
        allocator,
        io,
        stream,
        target,
        reader.buffered(),
        "",
        .{
            .buffer_size = config.relay_buffer_size,
            .idle_timeout = config.idle_timeout,
            .stats = config.stats,
        },
    );
}

fn handleBind(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    config: Config,
    reader: *io_helpers.BufferedReader,
    address: codec.Address,
) !void {
    if (!config.allow_bind) {
        try sendConnectFailure(
            io,
            stream,
            config,
            error.BindNotAllowed,
        );
        return error.BindNotAllowed;
    }

    const bind_address = bindAddress(address) catch |err| {
        try sendConnectFailure(
            io,
            stream,
            config,
            error.InvalidBindRequest,
        );
        return err;
    };
    var listener = bind_address.listen(io, .{ .reuse_address = true }) catch |err| {
        try sendConnectFailure(io, stream, config, err);
        return err;
    };
    defer listener.deinit(io);

    const reply_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    var reply: [64]u8 = undefined;
    const len = try codec.encodeSocks5Reply(
        &reply,
        .succeeded,
        .{ .ip = listener.socket.address },
    );
    try io_helpers.writeAll(io, stream, reply[0..len], reply_deadline);

    const bind_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.bind_timeout,
    );
    const accepted = acceptWithDeadline(io, &listener, bind_deadline) catch |err| {
        try sendConnectFailure(io, stream, config, err);
        return err;
    };
    defer accepted.close(io);

    const accepted_reply_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    const accepted_len = try codec.encodeSocks5Reply(
        &reply,
        .succeeded,
        .{ .ip = accepted.socket.address },
    );
    try io_helpers.writeAll(
        io,
        stream,
        reply[0..accepted_len],
        accepted_reply_deadline,
    );

    return relay.relay(
        allocator,
        io,
        stream,
        accepted,
        reader.buffered(),
        "",
        .{
            .buffer_size = config.relay_buffer_size,
            .idle_timeout = config.idle_timeout,
            .stats = config.stats,
        },
    );
}

fn bindAddress(address: codec.Address) !net.IpAddress {
    return switch (address) {
        .ip => |ip| ip,
        .domain => error.InvalidBindRequest,
    };
}

fn acceptWithDeadline(
    io: std.Io,
    listener: *net.Server,
    deadline: ?std.Io.Clock.Timestamp,
) !net.Stream {
    const absolute = deadline orelse return listener.accept(io);
    if (absolute.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.Timeout;
    }

    const Wake = union(enum) {
        accepted: net.Server.AcceptError!net.Stream,
        timeout: std.Io.Cancelable!void,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_storage);
    defer while (select.cancel()) |wake| switch (wake) {
        .accepted => |result| if (result) |stream| {
            stream.close(io);
        } else |_| {},
        .timeout => {},
    };
    select.async(.accepted, net.Server.accept, .{ listener, io });
    select.async(.timeout, waitUntil, .{ io, absolute });
    return switch (select.await() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
    }) {
        .accepted => |result| try result,
        .timeout => |result| {
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    };
}

fn waitUntil(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Cancelable!void {
    try deadline.wait(io);
}

fn handleUdpAssociate(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    peer: net.IpAddress,
    config: Config,
    reader: *io_helpers.BufferedReader,
    address: codec.Address,
) !void {
    const deadline = reader.deadline;
    if (!config.allow_udp) {
        var reply: [64]u8 = undefined;
        const len = try codec.encodeSocks5Reply(
            &reply,
            .connection_not_allowed,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        );
        try io_helpers.writeAll(io, stream, reply[0..len], deadline);
        return error.UdpNotAllowed;
    }

    var session = udp_relay.Session.init(
        allocator,
        io,
        .{
            .acl = config.acl,
            .connect_timeout = config.connect_timeout,
            .idle_timeout = config.udp_idle_timeout,
            .poll_interval = config.udp_poll_interval,
            .max_datagram_size = config.max_udp_datagram_size,
            .stats = config.stats,
        },
        stream,
        peer,
        address,
    ) catch |err| {
        var reply: [64]u8 = undefined;
        const len = try codec.encodeSocks5Reply(
            &reply,
            .general_failure,
            .{ .ip = .{ .ip4 = .unspecified(0) } },
        );
        try io_helpers.writeAll(io, stream, reply[0..len], deadline);
        return err;
    };
    defer session.deinit();

    var reply: [64]u8 = undefined;
    const len = try codec.encodeSocks5Reply(
        &reply,
        .succeeded,
        .{ .ip = session.address() },
    );
    try io_helpers.writeAll(io, stream, reply[0..len], deadline);

    return session.run();
}

fn connectTarget(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    address: codec.Address,
) !net.Stream {
    const target: destination.Target = switch (address) {
        .ip => |ip| .{ .ip = ip },
        .domain => |domain| .{ .domain = .{
            .host = domain.host,
            .port = domain.port,
        } },
    };
    if (config.policy_store) |store| {
        return destination.connectTargetReloadable(
            allocator,
            io,
            store,
            target,
            .connect,
            config.connect_timeout,
        );
    }
    return destination.connectTarget(
        allocator,
        io,
        config.acl,
        target,
        .connect,
        config.connect_timeout,
    );
}

fn sendConnectFailure(
    io: std.Io,
    stream: net.Stream,
    config: Config,
    err: anyerror,
) !void {
    const deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    var reply: [64]u8 = undefined;
    const len = try codec.encodeSocks5Reply(
        &reply,
        replyForError(err),
        .{ .ip = .{ .ip4 = .unspecified(0) } },
    );
    try io_helpers.writeAll(io, stream, reply[0..len], deadline);
}

fn replyForError(err: anyerror) codec.Reply {
    return switch (err) {
        error.DestinationDenied,
        error.BindNotAllowed,
        error.UdpNotAllowed,
        => .connection_not_allowed,
        error.ConnectionRefused => .connection_refused,
        error.NetworkUnreachable, error.NetworkDown => .network_unreachable,
        error.HostUnreachable,
        error.UnknownHostName,
        error.NoAddressReturned,
        error.Timeout,
        => .host_unreachable,
        else => .general_failure,
    };
}

test "SOCKS5 proxy server init and deinit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var server = try Server.init(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    try std.testing.expect(server.listener.socket.address.ip4.port != 0);
    // Force the accept loop to analyze without blocking: a stopped server
    // returns before its first accept.
    server.requestStop();
    try server.serve();
}
