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
const socket_binding = @import("../internal/socket_binding.zig");
const udp_impl = @import("socks5/udp.zig");

const net = std.Io.net;

pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;
pub const udp = udp_impl;
pub const Target = udp.Address;
pub const ReplyAddress = udp.OwnedAddress;

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

pub const Options = struct {
    /// Source IP/port for newly opened TCP sockets.
    /// Null leaves source selection to the OS. Requires Netz's zio backend.
    local_address: ?std.Io.net.IpAddress = null,
    /// Constrain the socket's network interface independently of source IP.
    /// Names are borrowed; unsupported platforms/backends fail explicitly.
    network_interface: ?tcp_connect.NetworkInterface = null,

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
    tcp_connect.BindingResolvedConnectError || net.IpAddress.ConnectError ||
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

pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

/// One authenticated SOCKS5 TCP control connection. The stored deadline spans
/// proxy resolution, TCP, authentication, and the first command. A successful
/// CONNECT may transfer the stream with `takeStream`; UDP ASSOCIATE callers keep
/// this value alive for the complete association lifetime.
pub const Control = struct {
    io: std.Io,
    stream: net.Stream,
    deadline: ?std.Io.Clock.Timestamp,

    pub fn openHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_host: []const u8,
        proxy_port: u16,
        options: Options,
    ) Error!Control {
        return openHostMaybeDeadline(
            allocator,
            io,
            proxy_host,
            proxy_port,
            options,
            try deadline_policy.fromTimeout(io, options.connect_timeout),
        );
    }

    pub fn openHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_host: []const u8,
        proxy_port: u16,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Control {
        return openHostMaybeDeadline(
            allocator,
            io,
            proxy_host,
            proxy_port,
            options,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
    }

    fn openHostMaybeDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy_host: []const u8,
        proxy_port: u16,
        options: Options,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Control {
        if (proxy_port == 0) return error.InvalidProxyPort;
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
            .fromOptions(options),
        );
        errdefer stream.close(io);
        try negotiateAuthentication(
            io,
            stream,
            options.credentials,
            options.allow_no_authentication,
            deadline,
        );
        return .{ .io = io, .stream = stream, .deadline = deadline };
    }

    pub fn command(
        self: *Control,
        command_value: Command,
        target: Target,
    ) Error!ReplyAddress {
        var request: [4 + 1 + 255 + 2]u8 = undefined;
        const request_len = try encodeCommandRequest(
            &request,
            command_value,
            target,
        );
        try writeAll(
            self.io,
            self.stream,
            request[0..request_len],
            self.deadline,
        );
        return readCommandReply(self.io, self.stream, self.deadline);
    }

    pub fn takeStream(self: *Control) net.Stream {
        const stream = self.stream;
        self.* = undefined;
        return stream;
    }

    pub fn deinit(self: *Control) void {
        self.stream.close(self.io);
        self.* = undefined;
    }
};

pub const UdpAssociateOptions = struct {
    socks5: Options = .{},
    /// Bind the UDP side to this exact local address before requesting the
    /// association. Null asks the proxy to infer the client endpoint and binds
    /// an ephemeral wildcard socket matching the returned relay family.
    bind_address: ?net.IpAddress = null,
    /// Datagram send/receive interface; null inherits the control policy.
    network_interface: ?tcp_connect.NetworkInterface = null,
};

pub const UdpAssociation = udp.Association(Control);

pub const UdpAssociateError = Error || net.IpAddress.BindError || error{
    ProxyInvalidRelayAddress,
};

/// Open an RFC 1928 UDP association while retaining its authenticated TCP
/// control connection for the complete association lifetime.
pub fn associateUdpHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    options: UdpAssociateOptions,
) UdpAssociateError!UdpAssociation {
    return associateUdpHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        options,
        try deadline_policy.fromTimeout(io, options.socks5.connect_timeout),
    );
}

pub fn associateUdpHostWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    options: UdpAssociateOptions,
    deadline: std.Io.Clock.Timestamp,
) UdpAssociateError!UdpAssociation {
    return associateUdpHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        options,
        try deadline_policy.capTimeout(
            io,
            deadline,
            options.socks5.connect_timeout,
        ),
    );
}

fn associateUdpHostMaybeDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    options: UdpAssociateOptions,
    deadline: ?std.Io.Clock.Timestamp,
) UdpAssociateError!UdpAssociation {
    var control = try Control.openHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        options.socks5,
        deadline,
    );
    errdefer control.deinit();

    var bound_socket: ?net.Socket = if (options.bind_address) |bind_address|
        try socket_binding.bindDatagram(io, bind_address, options.network_interface orelse options.socks5.network_interface)
    else
        null;
    errdefer if (bound_socket) |socket| socket.close(io);

    const requested_client = if (bound_socket) |socket|
        socket.address
    else
        net.IpAddress{ .ip4 = .unspecified(0) };
    const reply = try control.command(
        .udp_associate,
        .{ .ip = requested_client },
    );
    const preferred_family: ?net.IpAddress.Family = if (bound_socket) |socket|
        std.meta.activeTag(socket.address)
    else
        null;
    var relay = try resolveRelayAddress(
        allocator,
        io,
        reply,
        options.socks5.address_resolver,
        preferred_family,
        deadline,
    );
    if (isUnspecified(relay)) {
        relay = try resolveHostAddress(
            allocator,
            io,
            proxy_host,
            relay.getPort(),
            options.socks5.address_resolver,
            std.meta.activeTag(relay),
            deadline,
        );
    }
    if (relay.getPort() == 0) return error.ProxyInvalidRelayAddress;

    if (bound_socket == null) {
        const bind_address = switch (relay) {
            .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
            .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
        };
        bound_socket = try socket_binding.bindDatagram(
            io,
            bind_address,
            options.network_interface orelse options.socks5.network_interface,
        );
    }
    const socket = bound_socket.?;
    if (std.meta.activeTag(socket.address) != std.meta.activeTag(relay)) {
        return error.ProxyInvalidRelayAddress;
    }
    bound_socket = null;
    return UdpAssociation.init(io, control, socket, relay);
}

fn resolveRelayAddress(
    allocator: std.mem.Allocator,
    io: std.Io,
    reply: ReplyAddress,
    resolver: ?AddressResolver,
    preferred_family: ?net.IpAddress.Family,
    deadline: ?std.Io.Clock.Timestamp,
) UdpAssociateError!net.IpAddress {
    return switch (reply) {
        .ip => |ip| if (preferred_family == null or
            preferred_family.? == std.meta.activeTag(ip))
            ip
        else
            error.ProxyInvalidRelayAddress,
        .domain => |domain| resolveHostAddress(
            allocator,
            io,
            domain.bytes[0..domain.len],
            domain.port,
            resolver,
            preferred_family,
            deadline,
        ),
    };
}

fn resolveHostAddress(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    resolver: ?AddressResolver,
    preferred_family: ?net.IpAddress.Family,
    deadline: ?std.Io.Clock.Timestamp,
) UdpAssociateError!net.IpAddress {
    if (port == 0) return error.ProxyInvalidRelayAddress;
    if (net.IpAddress.parse(host, port)) |ip| {
        if (preferred_family == null or
            preferred_family.? == std.meta.activeTag(ip)) return ip;
        return error.ProxyInvalidRelayAddress;
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
    for (addresses) |ip| {
        if (preferred_family == null or
            preferred_family.? == std.meta.activeTag(ip)) return ip;
    }
    return error.ProxyInvalidRelayAddress;
}

fn isUnspecified(ip: net.IpAddress) bool {
    return switch (ip) {
        .ip4 => |value| std.mem.allEqual(u8, &value.bytes, 0),
        .ip6 => |value| std.mem.allEqual(u8, &value.bytes, 0),
    };
}

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
    var control = try Control.openHostMaybeDeadline(
        allocator,
        io,
        proxy_host,
        proxy_port,
        options,
        deadline,
    );
    errdefer control.deinit();
    _ = try control.command(
        .connect,
        try Target.fromHost(target_host, target_port),
    );
    return control.takeStream();
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
    binding: tcp_connect.Binding,
) Error!net.Stream {
    return tcp_connect.endpointWithOptions(
        allocator,
        io,
        net.IpAddress.parse(host, port) catch null,
        host,
        port,
        resolver,
        policy,
        deadline,
        binding,
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
    try negotiateAuthentication(
        io,
        stream,
        credentials,
        allow_no_authentication,
        deadline,
    );

    var request: [4 + 1 + 255 + 2]u8 = undefined;
    const request_len = try encodeCommandRequest(
        &request,
        .connect,
        try Target.fromHost(target_host, target_port),
    );
    try writeAll(io, stream, request[0..request_len], deadline);
    _ = try readCommandReply(io, stream, deadline);
}

fn negotiateAuthentication(
    io: std.Io,
    stream: net.Stream,
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

fn encodeCommandRequest(
    output: *[4 + 1 + 255 + 2]u8,
    command_value: Command,
    target: Target,
) Error!usize {
    output[0..3].* = .{ 0x05, @intFromEnum(command_value), 0x00 };
    var offset: usize = 4;
    switch (target) {
        .ip => |address| switch (address) {
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
        },
        .domain => |domain| {
            _ = try net.HostName.init(domain.host);
            if (domain.host.len > 255) {
                return error.ProxyAddressTypeUnsupported;
            }
            output[3] = @intFromEnum(AddressType.domain);
            output[offset] = @intCast(domain.host.len);
            offset += 1;
            @memcpy(output[offset..][0..domain.host.len], domain.host);
            offset += domain.host.len;
        },
    }
    std.mem.writeInt(u16, output[offset..][0..2], target.getPort(), .big);
    return offset + 2;
}

fn readCommandReply(
    io: std.Io,
    stream: net.Stream,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ReplyAddress {
    var prefix: [4]u8 = undefined;
    try readExact(io, stream, &prefix, deadline);
    if (prefix[0] != 0x05 or prefix[2] != 0x00) {
        return error.ProxyProtocolViolation;
    }
    if (replyError(prefix[1])) |err| return err;

    return switch (@as(AddressType, @enumFromInt(prefix[3]))) {
        .ipv4 => blk: {
            var encoded: [4 + 2]u8 = undefined;
            try readExact(io, stream, &encoded, deadline);
            break :blk .{ .ip = .{ .ip4 = .{
                .bytes = encoded[0..4].*,
                .port = std.mem.readInt(u16, encoded[4..6], .big),
            } } };
        },
        .ipv6 => blk: {
            var encoded: [16 + 2]u8 = undefined;
            try readExact(io, stream, &encoded, deadline);
            break :blk .{ .ip = .{ .ip6 = .{
                .bytes = encoded[0..16].*,
                .port = std.mem.readInt(u16, encoded[16..18], .big),
            } } };
        },
        .domain => blk: {
            var length: [1]u8 = undefined;
            try readExact(io, stream, &length, deadline);
            if (length[0] == 0) return error.ProxyProtocolViolation;
            var result: ReplyAddress = .{ .domain = .{
                .bytes = undefined,
                .len = length[0],
                .port = undefined,
            } };
            try readExact(
                io,
                stream,
                result.domain.bytes[0..result.domain.len],
                deadline,
            );
            var port: [2]u8 = undefined;
            try readExact(io, stream, &port, deadline);
            result.domain.port = std.mem.readInt(u16, &port, .big);
            break :blk result;
        },
        _ => return error.ProxyProtocolViolation,
    };
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
    const domain_len = try encodeCommandRequest(
        &storage,
        .connect,
        try Target.fromHost("broker.example", 1883),
    );
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

    const ip4_len = try encodeCommandRequest(
        &storage,
        .connect,
        try Target.fromHost("192.0.2.1", 8883),
    );
    try std.testing.expectEqual(@as(usize, 10), ip4_len);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 1, 0, 1, 192, 0, 2, 1, 0x22, 0xb3 },
        storage[0..ip4_len],
    );

    const ip6_len = try encodeCommandRequest(
        &storage,
        .connect,
        try Target.fromHost("2001:db8::1", 443),
    );
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
