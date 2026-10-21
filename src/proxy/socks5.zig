//! RFC 1928 SOCKS5 CONNECT with optional RFC 1929 username/password auth.
//!
//! Destination hostnames are sent to the proxy without local resolution, as
//! in the commonly named `socks5h` mode. Proxy DNS/TCP setup and every SOCKS
//! exchange share one optional absolute awake-clock deadline.

const std = @import("std");
const address_resolver = @import("../internal/address_resolver.zig");
const deadline_policy = @import("../internal/deadline.zig");
const stream_io = @import("../internal/stream_io.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");

const net = std.Io.net;

pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const Options = struct {
    credentials: ?Credentials = null,
    /// Permit a proxy to select no-auth even when credentials were offered.
    /// Disable this to prevent authentication downgrade.
    allow_no_authentication: bool = true,
    /// One budget spanning proxy resolution, TCP, authentication, and CONNECT.
    connect_timeout: ?std.Io.Duration = null,
    address_resolver: ?AddressResolver = null,
    /// Null inherits ordered address fallback.
    address_connect_policy: ?AddressConnectPolicy = null,
};

pub const Error = address_resolver.Error ||
    tcp_connect.ResolvedPolicyConnectError || net.IpAddress.ConnectError ||
    net.Stream.Reader.Error || net.Stream.Writer.Error ||
    stream_io.TimedReadError || stream_io.TimedWriteError || error{
    InvalidProxyPort,
    InvalidTargetPort,
    InvalidCredentials,
    InvalidAddressConnectPolicy,
    ProxyConnectionClosed,
    ProxyProtocolViolation,
    ProxyNoAcceptableAuthentication,
    ProxyUnsupportedAuthentication,
    ProxyAuthenticationRequired,
    ProxyAuthenticationFailed,
    ProxyConnectionNotAllowed,
    ProxyNetworkUnreachable,
    ProxyHostUnreachable,
    ProxyConnectionRefused,
    ProxyTtlExpired,
    ProxyCommandUnsupported,
    ProxyAddressTypeUnsupported,
    ProxyGeneralFailure,
};

const AuthenticationMethod = enum(u8) {
    none = 0x00,
    username_password = 0x02,
    no_acceptable = 0xff,
    _,
};

const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
    _,
};

/// Resolve and connect to a SOCKS5 proxy, then open one CONNECT tunnel.
pub fn connectHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    target_host: []const u8,
    target_port: u16,
    options: Options,
) Error!net.Stream {
    const deadline = try deadline_policy.fromTimeout(io, options.connect_timeout);
    return connectHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        options,
        deadline,
    );
}

/// Preserve one caller-owned deadline across proxy TCP and SOCKS negotiation.
pub fn connectHostWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    target_host: []const u8,
    target_port: u16,
    options: Options,
    deadline: std.Io.Clock.Timestamp,
) Error!net.Stream {
    return connectHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        options,
        try deadline_policy.capTimeout(io, deadline, options.connect_timeout),
    );
}

fn connectHostMaybeDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    target_host: []const u8,
    target_port: u16,
    options: Options,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    if (proxy_port == 0) return error.InvalidProxyPort;
    try validateTarget(target_host, target_port);
    try validateCredentials(options.credentials);
    const policy = options.address_connect_policy orelse .ordered;
    try tcp_connect.validateAddressConnectPolicy(policy);

    const stream = try connectProxy(
        allocator,
        io,
        proxy_host,
        proxy_port,
        options.address_resolver,
        policy,
        deadline,
    );
    errdefer stream.close(io);
    try establishMaybeDeadline(
        io,
        stream,
        target_host,
        target_port,
        options.credentials,
        options.allow_no_authentication,
        deadline,
    );
    return stream;
}

/// Negotiate SOCKS5 over a caller-connected proxy stream. Ownership remains
/// with the caller on both success and failure.
pub fn establish(
    io: std.Io,
    stream: net.Stream,
    target_host: []const u8,
    target_port: u16,
    credentials: ?Credentials,
    allow_no_authentication: bool,
) Error!void {
    try validateTarget(target_host, target_port);
    try validateCredentials(credentials);
    return establishMaybeDeadline(
        io,
        stream,
        target_host,
        target_port,
        credentials,
        allow_no_authentication,
        null,
    );
}

pub fn establishWithDeadline(
    io: std.Io,
    stream: net.Stream,
    target_host: []const u8,
    target_port: u16,
    credentials: ?Credentials,
    allow_no_authentication: bool,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    try validateTarget(target_host, target_port);
    try validateCredentials(credentials);
    return establishMaybeDeadline(
        io,
        stream,
        target_host,
        target_port,
        credentials,
        allow_no_authentication,
        try deadline_policy.usableAwake(io, deadline),
    );
}

fn connectProxy(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    resolver: ?AddressResolver,
    policy: AddressConnectPolicy,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    if (net.IpAddress.parse(host, port)) |address| {
        return if (deadline) |absolute|
            tcp_connect.ipWithDeadline(io, address, absolute)
        else
            tcp_connect.ip(io, address, null);
    } else |_| {}

    const addresses = if (resolver) |configured|
        try configured.resolve(
            configured.context,
            allocator,
            io,
            host,
            port,
            deadline,
        )
    else
        try address_resolver.resolveSystem(
            allocator,
            io,
            host,
            port,
            deadline,
        );
    defer allocator.free(addresses);
    return if (deadline) |absolute|
        tcp_connect.resolvedWithPolicyAndDeadline(
            allocator,
            io,
            addresses,
            absolute,
            policy,
        )
    else
        tcp_connect.resolvedWithPolicy(
            allocator,
            io,
            addresses,
            null,
            policy,
        );
}

fn establishMaybeDeadline(
    io: std.Io,
    stream: net.Stream,
    target_host: []const u8,
    target_port: u16,
    credentials: ?Credentials,
    allow_no_authentication: bool,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var greeting: [4]u8 = .{ 0x05, 0x01, 0x00, 0x00 };
    const greeting_len: usize = if (credentials != null) blk: {
        if (allow_no_authentication) {
            greeting[1] = 2;
            greeting[2] = 0x00;
            greeting[3] = 0x02;
            break :blk 4;
        }
        greeting[1] = 1;
        greeting[2] = 0x02;
        break :blk 3;
    } else 3;
    try writeAll(io, stream, greeting[0..greeting_len], deadline);

    var method_reply: [2]u8 = undefined;
    try readExact(io, stream, &method_reply, deadline);
    if (method_reply[0] != 0x05) return error.ProxyProtocolViolation;
    switch (@as(AuthenticationMethod, @enumFromInt(method_reply[1]))) {
        .none => {
            if (credentials != null and !allow_no_authentication) {
                return error.ProxyAuthenticationRequired;
            }
        },
        .username_password => {
            const auth = credentials orelse
                return error.ProxyAuthenticationRequired;
            try authenticate(io, stream, auth, deadline);
        },
        .no_acceptable => return error.ProxyNoAcceptableAuthentication,
        _ => return error.ProxyUnsupportedAuthentication,
    }

    var request: [4 + 1 + 255 + 2]u8 = undefined;
    const request_len = try encodeConnectRequest(
        &request,
        target_host,
        target_port,
    );
    try writeAll(io, stream, request[0..request_len], deadline);
    try readConnectReply(io, stream, deadline);
}

fn authenticate(
    io: std.Io,
    stream: net.Stream,
    credentials: Credentials,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var request: [3 + 255 + 255]u8 = undefined;
    request[0] = 0x01;
    request[1] = @intCast(credentials.username.len);
    @memcpy(request[2..][0..credentials.username.len], credentials.username);
    const password_len_index = 2 + credentials.username.len;
    request[password_len_index] = @intCast(credentials.password.len);
    @memcpy(
        request[password_len_index + 1 ..][0..credentials.password.len],
        credentials.password,
    );
    try writeAll(
        io,
        stream,
        request[0 .. password_len_index + 1 + credentials.password.len],
        deadline,
    );
    var reply: [2]u8 = undefined;
    try readExact(io, stream, &reply, deadline);
    if (reply[0] != 0x01) return error.ProxyProtocolViolation;
    if (reply[1] != 0x00) return error.ProxyAuthenticationFailed;
}

fn encodeConnectRequest(
    output: *[4 + 1 + 255 + 2]u8,
    host: []const u8,
    port: u16,
) Error!usize {
    output[0..3].* = .{ 0x05, 0x01, 0x00 };
    var offset: usize = 4;
    if (net.IpAddress.parse(host, port)) |address| switch (address) {
        .ip4 => |value| {
            output[3] = @intFromEnum(AddressType.ipv4);
            @memcpy(output[offset..][0..4], &value.bytes);
            offset += 4;
        },
        .ip6 => |value| {
            output[3] = @intFromEnum(AddressType.ipv6);
            @memcpy(output[offset..][0..16], &value.bytes);
            offset += 16;
        },
    } else |_| {
        _ = try net.HostName.init(host);
        if (host.len > 255) return error.ProxyAddressTypeUnsupported;
        output[3] = @intFromEnum(AddressType.domain);
        output[offset] = @intCast(host.len);
        offset += 1;
        @memcpy(output[offset..][0..host.len], host);
        offset += host.len;
    }
    std.mem.writeInt(u16, output[offset..][0..2], port, .big);
    return offset + 2;
}

fn readConnectReply(
    io: std.Io,
    stream: net.Stream,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var prefix: [4]u8 = undefined;
    try readExact(io, stream, &prefix, deadline);
    if (prefix[0] != 0x05 or prefix[2] != 0x00) {
        return error.ProxyProtocolViolation;
    }
    if (replyError(prefix[1])) |err| return err;

    const address_len: usize = switch (@as(AddressType, @enumFromInt(prefix[3]))) {
        .ipv4 => 4,
        .ipv6 => 16,
        .domain => blk: {
            var length: [1]u8 = undefined;
            try readExact(io, stream, &length, deadline);
            if (length[0] == 0) return error.ProxyProtocolViolation;
            break :blk length[0];
        },
        _ => return error.ProxyProtocolViolation,
    };
    var ignored: [255 + 2]u8 = undefined;
    try readExact(io, stream, ignored[0 .. address_len + 2], deadline);
}

fn replyError(reply: u8) ?Error {
    return switch (reply) {
        0x00 => null,
        0x01 => error.ProxyGeneralFailure,
        0x02 => error.ProxyConnectionNotAllowed,
        0x03 => error.ProxyNetworkUnreachable,
        0x04 => error.ProxyHostUnreachable,
        0x05 => error.ProxyConnectionRefused,
        0x06 => error.ProxyTtlExpired,
        0x07 => error.ProxyCommandUnsupported,
        0x08 => error.ProxyAddressTypeUnsupported,
        else => error.ProxyProtocolViolation,
    };
}

fn validateTarget(host: []const u8, port: u16) Error!void {
    if (port == 0) return error.InvalidTargetPort;
    if (net.IpAddress.parse(host, port)) |_| return else |_| {}
    _ = try net.HostName.init(host);
    if (host.len > 255) return error.ProxyAddressTypeUnsupported;
}

fn validateCredentials(credentials: ?Credentials) Error!void {
    const value = credentials orelse return;
    if (value.username.len == 0 or value.username.len > 255 or
        value.password.len == 0 or value.password.len > 255)
    {
        return error.InvalidCredentials;
    }
}

fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    if (deadline) |absolute| {
        var committed: usize = 0;
        return stream_io.writeAllTrackedWithDeadline(
            io,
            stream,
            bytes,
            &committed,
            absolute,
        );
    }
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.ProxyConnectionClosed;
        written += count;
    }
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    output: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = if (deadline) |absolute|
            try stream_io.readSomeWithDeadline(
                io,
                stream,
                output[offset..],
                absolute,
            )
        else blk: {
            var parts = [_][]u8{output[offset..]};
            break :blk try io.vtable.netRead(
                io.userdata,
                stream.socket.handle,
                &parts,
            );
        };
        if (count == 0) return error.ProxyConnectionClosed;
        offset += count;
    }
}

test "SOCKS5 encodes domain IPv4 and IPv6 CONNECT requests" {
    var storage: [4 + 1 + 255 + 2]u8 = undefined;
    const domain_len = try encodeConnectRequest(&storage, "broker.example", 1883);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 1, 0, 3, 14 },
        storage[0..5],
    );
    try std.testing.expectEqualStrings("broker.example", storage[5..19]);
    try std.testing.expectEqual(@as(u16, 1883), std.mem.readInt(
        u16,
        storage[domain_len - 2 ..][0..2],
        .big,
    ));

    const ip4_len = try encodeConnectRequest(&storage, "192.0.2.1", 8883);
    try std.testing.expectEqual(@as(usize, 10), ip4_len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 1, 0, 1, 192, 0, 2, 1, 0x22, 0xb3 },
        storage[0..ip4_len],
    );

    const ip6_len = try encodeConnectRequest(&storage, "2001:db8::1", 443);
    try std.testing.expectEqual(@as(usize, 22), ip6_len);
    try std.testing.expectEqual(@as(u8, 4), storage[3]);
    try std.testing.expectEqual(@as(u16, 443), std.mem.readInt(
        u16,
        storage[ip6_len - 2 ..][0..2],
        .big,
    ));
}

test "SOCKS5 validates credentials and maps every CONNECT reply" {
    try std.testing.expectError(
        error.InvalidCredentials,
        validateCredentials(.{ .username = "", .password = "secret" }),
    );
    try std.testing.expectError(
        error.InvalidCredentials,
        validateCredentials(.{ .username = "user", .password = "" }),
    );
    try validateCredentials(.{ .username = "user", .password = "secret" });
    try std.testing.expect(replyError(0) == null);
    const expected = [_]Error{
        error.ProxyGeneralFailure,
        error.ProxyConnectionNotAllowed,
        error.ProxyNetworkUnreachable,
        error.ProxyHostUnreachable,
        error.ProxyConnectionRefused,
        error.ProxyTtlExpired,
        error.ProxyCommandUnsupported,
        error.ProxyAddressTypeUnsupported,
        error.ProxyProtocolViolation,
    };
    for (expected, 1..) |wanted, reply| {
        try std.testing.expectEqual(wanted, replyError(@intCast(reply)).?);
    }
}

test "SOCKS5 rejects expired deadline before proxy I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.Timeout,
        connectHostWithDeadline(
            std.testing.allocator,
            io,
            "127.0.0.1",
            1080,
            "broker.example",
            1883,
            .{},
            .{ .raw = .zero, .clock = .awake },
        ),
    );
}

test "SOCKS5 negotiates username password and remote hostname" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var greeting: [3]u8 = undefined;
            try readExact(self.io, stream, &greeting, null);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 5, 1, 2 },
                &greeting,
            );
            try writeAll(self.io, stream, &.{ 5, 2 }, null);

            var auth_prefix: [2]u8 = undefined;
            try readExact(self.io, stream, &auth_prefix, null);
            try std.testing.expectEqualSlices(u8, &.{ 1, 4 }, &auth_prefix);
            var username: [4]u8 = undefined;
            try readExact(self.io, stream, &username, null);
            try std.testing.expectEqualStrings("user", &username);
            var password_length: [1]u8 = undefined;
            try readExact(self.io, stream, &password_length, null);
            try std.testing.expectEqual(@as(u8, 6), password_length[0]);
            var password: [6]u8 = undefined;
            try readExact(self.io, stream, &password, null);
            try std.testing.expectEqualStrings("secret", &password);
            try writeAll(self.io, stream, &.{ 1, 0 }, null);

            var request_prefix: [5]u8 = undefined;
            try readExact(self.io, stream, &request_prefix, null);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 5, 1, 0, 3, 14 },
                &request_prefix,
            );
            var authority: [16]u8 = undefined;
            try readExact(self.io, stream, &authority, null);
            try std.testing.expectEqualStrings(
                "broker.example",
                authority[0..14],
            );
            try std.testing.expectEqual(
                @as(u16, 1883),
                std.mem.readInt(u16, authority[14..16], .big),
            );
            try writeAll(
                self.io,
                stream,
                &.{
                    5,    0,    0, 4,
                    0,    0,    0, 0,
                    0,    0,    0, 0,
                    0,    0,    0, 0,
                    0,    0,    0, 1,
                    0x1f, 0x90,
                },
                null,
            );

            var marker: [1]u8 = undefined;
            try readExact(self.io, stream, &marker, null);
            try writeAll(self.io, stream, &marker, null);
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try connectHost(
        allocator,
        io,
        "127.0.0.1",
        listener.socket.address.ip4.port,
        "broker.example",
        1883,
        .{
            .credentials = .{
                .username = "user",
                .password = "secret",
            },
            .allow_no_authentication = false,
            .connect_timeout = .fromSeconds(1),
        },
    );
    defer stream.close(io);
    try writeAll(io, stream, &.{0xa5}, null);
    var echoed: [1]u8 = undefined;
    try readExact(io, stream, &echoed, null);
    try std.testing.expectEqual(@as(u8, 0xa5), echoed[0]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "SOCKS5 can require authentication without downgrade" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            var greeting: [3]u8 = undefined;
            readExact(self.io, stream, &greeting, null) catch |err| {
                self.err = err;
                return;
            };
            writeAll(self.io, stream, &.{ 5, 0 }, null) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.ProxyAuthenticationRequired,
        connectHost(
            allocator,
            io,
            "127.0.0.1",
            listener.socket.address.ip4.port,
            "broker.example",
            1883,
            .{
                .credentials = .{
                    .username = "user",
                    .password = "secret",
                },
                .allow_no_authentication = false,
            },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}
