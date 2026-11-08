//! HTTP/1 CONNECT server with Basic authentication and destination ACLs.

const std = @import("std");

const protocol = @import("protocol.zig");
const socks_auth = @import("../socks/auth.zig");
const socks_relay = @import("../socks/relay.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const Config = struct {
    auth: socks_auth.Policy = .{},
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    handshake_timeout: std.Io.Duration = .fromSeconds(10),
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    max_head_bytes: usize = protocol.max_head_bytes,
    reader_buffer_size: usize = 4096,
    relay_buffer_size: usize = 16 * 1024,
    realm: []const u8 = "proxyz",
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    RequestTooLarge,
    AuthenticationFailed,
    DestinationDenied,
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
            job.* = .{
                .server = self,
                .stream = stream,
                .peer = peer,
            };
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

/// Process one accepted HTTP proxy connection. The caller retains ownership
/// of `stream`.
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
    const reader_storage = try allocator.alloc(u8, config.reader_buffer_size);
    defer allocator.free(reader_storage);
    var reader = io_helpers.BufferedReader.init(
        io,
        stream,
        reader_storage,
        handshake_deadline,
    );

    const head_storage = try allocator.alloc(u8, config.max_head_bytes);
    defer allocator.free(head_storage);
    const head = readHead(&reader, head_storage) catch |err| {
        if (err == error.Timeout) {
            sendError(io, stream, config, .request_timeout) catch {};
        } else if (err == error.HeadTooLarge) {
            sendError(io, stream, config, .request_header_fields_too_large) catch {};
        }
        return err;
    };

    const request = protocol.parseRequest(head) catch |err| {
        const status: Status = switch (err) {
            error.UnsupportedMethod => .method_not_allowed,
            error.UnsupportedVersion => .version_not_supported,
            else => .bad_request,
        };
        sendError(io, stream, config, status) catch {};
        return err;
    };

    authenticate(io, stream, config, request.authorization) catch |err| {
        if (config.stats) |value| value.authFailure();
        return err;
    };

    const target: destination.Target = switch (request.authority) {
        .ip => |ip| .{ .ip = ip },
        .domain => |domain| .{ .domain = .{
            .host = domain.host,
            .port = domain.port,
        } },
    };
    const upstream = (if (config.policy_store) |store|
        destination.connectTargetReloadable(
            allocator,
            io,
            store,
            target,
            .connect,
            config.connect_timeout,
        )
    else
        destination.connectTarget(
            allocator,
            io,
            config.acl,
            target,
            .connect,
            config.connect_timeout,
        )) catch |err| {
        if (config.stats) |value| {
            if (err == error.DestinationDenied) value.deniedRequest();
        }
        const status: Status = switch (err) {
            error.DestinationDenied => .forbidden,
            error.Timeout => .gateway_timeout,
            else => .bad_gateway,
        };
        sendError(io, stream, config, status) catch {};
        return err;
    };
    defer upstream.close(io);

    try sendResponse(io, stream, config, .connection_established, null);
    return socks_relay.relay(
        allocator,
        io,
        stream,
        upstream,
        reader.buffered(),
        "",
        .{
            .buffer_size = config.relay_buffer_size,
            .idle_timeout = config.idle_timeout,
            .stats = config.stats,
        },
    );
}

fn readHead(
    reader: *io_helpers.BufferedReader,
    storage: []u8,
) ![]const u8 {
    var used: usize = 0;
    while (true) {
        if (used == storage.len) return error.HeadTooLarge;
        const byte = try reader.readByte();
        storage[used] = byte;
        used += 1;
        if (used >= 4 and std.mem.endsWith(u8, storage[0..used], "\r\n\r\n")) {
            return storage[0..used];
        }
    }
}

fn authenticate(
    io: std.Io,
    stream: net.Stream,
    config: Config,
    authorization: ?[]const u8,
) !void {
    if (authorization) |token| {
        if (config.auth.authenticator) |authenticator| {
            var storage: [1024]u8 = undefined;
            const credentials = protocol.decodeBasic(token, &storage) catch {
                try sendProxyAuthenticationRequired(io, stream, config);
                return error.AuthenticationFailed;
            };
            if (!authenticator.verifyCredentials(
                credentials.username,
                credentials.password,
            )) {
                try sendProxyAuthenticationRequired(io, stream, config);
                return error.AuthenticationFailed;
            }
            return;
        }
        if (config.auth.allow_anonymous) return;
        try sendProxyAuthenticationRequired(io, stream, config);
        return error.AuthenticationFailed;
    }

    if (config.auth.allow_anonymous) return;
    try sendProxyAuthenticationRequired(io, stream, config);
    return error.AuthenticationFailed;
}

pub const Status = enum {
    bad_request,
    forbidden,
    method_not_allowed,
    request_timeout,
    request_header_fields_too_large,
    proxy_authentication_required,
    bad_gateway,
    gateway_timeout,
    version_not_supported,
    connection_established,

    pub fn code(self: Status) u16 {
        return switch (self) {
            .bad_request => 400,
            .forbidden => 403,
            .method_not_allowed => 405,
            .request_timeout => 408,
            .request_header_fields_too_large => 431,
            .proxy_authentication_required => 407,
            .bad_gateway => 502,
            .gateway_timeout => 504,
            .version_not_supported => 505,
            .connection_established => 200,
        };
    }

    pub fn reason(self: Status) []const u8 {
        return switch (self) {
            .bad_request => "Bad Request",
            .forbidden => "Forbidden",
            .method_not_allowed => "Method Not Allowed",
            .request_timeout => "Request Timeout",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .proxy_authentication_required => "Proxy Authentication Required",
            .bad_gateway => "Bad Gateway",
            .gateway_timeout => "Gateway Timeout",
            .version_not_supported => "HTTP Version Not Supported",
            .connection_established => "Connection Established",
        };
    }
};

fn sendError(
    io: std.Io,
    stream: net.Stream,
    config: Config,
    status: Status,
) !void {
    const extra: ?[]const u8 = switch (status) {
        .method_not_allowed => "Allow: CONNECT\r\n",
        .proxy_authentication_required => null,
        else => null,
    };
    return sendResponse(io, stream, config, status, extra);
}

fn sendProxyAuthenticationRequired(
    io: std.Io,
    stream: net.Stream,
    config: Config,
) !void {
    var header_storage: [256]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &header_storage,
        "Proxy-Authenticate: Basic realm=\"{s}\"\r\n",
        .{config.realm},
    );
    return sendResponse(
        io,
        stream,
        config,
        .proxy_authentication_required,
        header,
    );
}

fn sendResponse(
    io: std.Io,
    stream: net.Stream,
    config: Config,
    status: Status,
    extra_headers: ?[]const u8,
) !void {
    const deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    var head_storage: [512]u8 = undefined;
    const head = if (status == .connection_established)
        try std.fmt.bufPrint(
            &head_storage,
            "HTTP/1.1 200 Connection Established\r\n\r\n",
            .{},
        )
    else
        try std.fmt.bufPrint(
            &head_storage,
            "HTTP/1.1 {d} {s}\r\n{s}Content-Length: 0\r\nConnection: close\r\n\r\n",
            .{
                status.code(),
                status.reason(),
                extra_headers orelse "",
            },
        );
    try io_helpers.writeAll(io, stream, head, deadline);
}

test "HTTP status responses carry the expected codes" {
    try std.testing.expectEqual(@as(u16, 200), Status.connection_established.code());
    try std.testing.expectEqual(@as(u16, 403), Status.forbidden.code());
    try std.testing.expectEqual(@as(u16, 407), Status.proxy_authentication_required.code());
    try std.testing.expectEqual(@as(u16, 502), Status.bad_gateway.code());
}
