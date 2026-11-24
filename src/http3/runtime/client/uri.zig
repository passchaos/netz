const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const address_resolver = @import("../../../internal/address_resolver.zig");
const system_lookup = @import("../../../internal/address_resolver/lookup.zig");
const address_collector = @import("../../../internal/address_resolver/collector.zig");

const net = std.Io.net;
pub const Error = runtime_error.Error;

pub const Endpoint = struct {
    allocator: std.mem.Allocator,
    host_storage: []u8,
    authority: []u8,
    port: u16,
    target: Target,
    /// Host text suitable for TLS SNI/certificate policy. Bracketed IPv6 URI
    /// literals drop their brackets here while authority keeps them.
    tls_host: []const u8,

    pub const Target = union(enum) {
        host: net.HostName,
        ip: net.IpAddress,
    };

    pub fn deinit(self: *Endpoint) void {
        self.allocator.free(self.authority);
        self.allocator.free(self.host_storage);
        self.* = undefined;
    }

    pub fn resolve(self: Endpoint, io: std.Io) Error!net.IpAddress {
        return switch (self.target) {
            .ip => |address| address,
            .host => |host| try resolveHostName(io, host, self.port),
        };
    }

    pub fn resolveAll(
        self: Endpoint,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) Error![]net.IpAddress {
        return switch (self.target) {
            .ip => |address| try ownedSingleAddress(allocator, address),
            .host => |host| try resolveHostAddresses(
                allocator,
                io,
                host,
                self.port,
            ),
        };
    }
};

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    headers: []const http3.Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http3.Qpack.HeaderField = &.{},
};

pub fn parseEndpoint(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error!Endpoint {
    if (uri.user != null or uri.password != null) return error.InvalidUri;
    if (uri.scheme.len == 0 or !std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InvalidUri;
    }
    const host_component = uri.host orelse return error.InvalidUri;
    const host_storage = try hostToOwned(allocator, host_component);
    errdefer allocator.free(host_storage);

    const port = uri.port orelse 443;
    const authority = if (uri.port == null)
        try allocator.dupe(u8, host_storage)
    else
        try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_storage, port });
    errdefer allocator.free(authority);

    const target, const tls_host = try targetForHost(host_storage, port);
    return .{
        .allocator = allocator,
        .host_storage = host_storage,
        .authority = authority,
        .port = port,
        .target = target,
        .tls_host = tls_host,
    };
}

fn hostToOwned(
    allocator: std.mem.Allocator,
    host: std.Uri.Component,
) Error![]u8 {
    var buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw = host.toRaw(&buffer) catch return error.InvalidUri;
    if (raw.len == 0) return error.InvalidUri;
    return allocator.dupe(u8, raw);
}

fn targetForHost(
    host: []const u8,
    port: u16,
) Error!struct { Endpoint.Target, []const u8 } {
    if (host[0] == '[') {
        if (host[host.len - 1] != ']') return error.InvalidUri;
        const inner = host[1 .. host.len - 1];
        if (inner.len == 0) return error.InvalidUri;
        const ip6 = net.IpAddress.parseIp6(inner, port) catch
            return error.InvalidUri;
        return .{ .{ .ip = ip6 }, inner };
    }
    if (std.mem.indexOfScalar(u8, host, '[') != null or
        std.mem.indexOfScalar(u8, host, ']') != null)
    {
        return error.InvalidUri;
    }
    if (net.IpAddress.parse(host, port)) |address| {
        return .{ .{ .ip = address }, host };
    } else |_| {}
    return .{ .{ .host = try net.HostName.init(host) }, host };
}

const resolveHostName = system_lookup.first;
const resolveHostAddresses = system_lookup.all;
const collectLookupAddresses = system_lookup.collect;
const drainLookupQueue = system_lookup.drain;
const address_stack_capacity = address_collector.stack_capacity;
const AddressCollector = address_collector.Collector;

pub fn resolveEndpointBefore(
    endpoint: Endpoint,
    allocator: std.mem.Allocator,
    io: std.Io,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    return switch (endpoint.target) {
        .ip => |address| try ownedSingleAddress(allocator, address),
        .host => |host| try resolveAddressesBefore(
            allocator,
            io,
            host,
            endpoint.port,
            deadline,
        ),
    };
}

pub fn resolveHostPortAddressesBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    if (net.IpAddress.parse(host, port)) |address| {
        return ownedSingleAddress(allocator, address);
    } else |_| {}
    return resolveAddressesBefore(
        allocator,
        io,
        try net.HostName.init(host),
        port,
        deadline,
    );
}

fn resolveAddressesBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: net.HostName,
    port: u16,
    deadline: ?std.Io.Clock.Timestamp,
) Error![]net.IpAddress {
    return address_resolver.resolveHostBefore(allocator, io, host, port, deadline) catch |err| switch (err) {
        error.Timeout => error.HandshakeTimeout,
        else => |other| other,
    };
}

pub fn connectDeadline(
    io: std.Io,
    timeout: ?std.Io.Duration,
) Error!?std.Io.Clock.Timestamp {
    const duration = timeout orelse return null;
    if (duration.nanoseconds <= 0) return error.HandshakeTimeout;
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}

fn usableConnectDeadline(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) Error!std.Io.Clock.Timestamp {
    if (deadline.clock != .awake) return error.InvalidHandshakeRecovery;
    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.HandshakeTimeout;
    }
    return deadline;
}

pub fn cappedConnectDeadline(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    const outer = try usableConnectDeadline(io, deadline);
    const phase = (try connectDeadline(io, timeout)) orelse return outer;
    return if (std.Io.Clock.Timestamp.compare(outer, .lt, phase))
        outer
    else
        phase;
}

pub fn handshakeRecoveryBefore(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    configured: @FieldType(quic.handshake.ClientOptions, "handshake_recovery"),
) Error!@FieldType(quic.handshake.ClientOptions, "handshake_recovery") {
    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining <= 0) return error.HandshakeTimeout;
    var result = configured;
    result.deadline = deadline;
    return result;
}

fn ownedSingleAddress(
    allocator: std.mem.Allocator,
    address: net.IpAddress,
) std.mem.Allocator.Error![]net.IpAddress {
    const addresses = try allocator.alloc(net.IpAddress, 1);
    addresses[0] = address;
    return addresses;
}

/// Build the HTTP/3 origin-form request target from a parsed HTTPS URI.
pub fn requestTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
    const path_value = componentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return std.fmt.allocPrint(
            allocator,
            "{s}?{s}",
            .{ path, componentBytes(query) },
        );
    }
    return allocator.dupe(u8, path);
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

test "HTTP/3 URI address collection exceeds former 32 result limit" {
    const allocator = std.testing.allocator;
    var collector = AddressCollector.init(allocator);
    defer collector.deinit();

    for (0..40) |index| {
        try collector.appendUnique(.{ .ip4 = .{
            .bytes = .{ 192, 0, 2, @intCast(index + 1) },
            .port = 443,
        } });
    }
    try collector.appendUnique(.{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 443,
    } });
    try std.testing.expectEqual(@as(usize, 40), collector.count());
    const addresses = try collector.toOwnedSlice();
    defer allocator.free(addresses);
    try std.testing.expectEqual(@as(usize, 40), addresses.len);
    try std.testing.expect(addresses[0].eql(&.{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 443,
    } }));
    try std.testing.expect(addresses[39].eql(&.{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 40 },
        .port = 443,
    } }));
}

test "HTTP/3 URI address collection remains intact on spill OOM" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var collector = AddressCollector.init(failing.allocator());
    defer collector.deinit();
    for (0..address_stack_capacity) |index| {
        try collector.appendUnique(.{ .ip4 = .{
            .bytes = .{ 198, 51, 100, @intCast(index + 1) },
            .port = 8443,
        } });
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectError(
        error.OutOfMemory,
        collector.appendUnique(.{ .ip4 = .{
            .bytes = .{ 198, 51, 100, 17 },
            .port = 8443,
        } }),
    );
    try std.testing.expectEqual(address_stack_capacity, collector.count());
    try std.testing.expect(collector.items()[15].eql(&.{ .ip4 = .{
        .bytes = .{ 198, 51, 100, 16 },
        .port = 8443,
    } }));
}

test "HTTP/3 URI hostname resolution drains async lookup" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const host = try net.HostName.init("localhost");

    const first = try resolveHostName(io, host, 443);
    try std.testing.expect(switch (first) {
        .ip4 => |address| address.port == 443,
        .ip6 => |address| address.port == 443,
    });
    const addresses = try resolveHostAddresses(allocator, io, host, 443);
    defer allocator.free(addresses);
    try std.testing.expect(addresses.len != 0);
    for (addresses) |address| {
        try std.testing.expect(switch (address) {
            .ip4 => |value| value.port == 443,
            .ip6 => |value| value.port == 443,
        });
    }
}

test "HTTP/3 URI lookup collector drains more results than queue capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue_storage: [16]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&queue_storage);

    const Producer = struct {
        fn run(
            producer_io: std.Io,
            output: *std.Io.Queue(net.HostName.LookupResult),
        ) !void {
            defer output.close(producer_io);
            for (0..40) |index| {
                try output.putOne(producer_io, .{ .address = .{ .ip4 = .{
                    .bytes = .{ 203, 0, 113, @intCast(index + 1) },
                    .port = 9443,
                } } });
            }
            try output.putOne(producer_io, .{ .address = .{ .ip4 = .{
                .bytes = .{ 203, 0, 113, 1 },
                .port = 9443,
            } } });
        }
    };
    var producer = io.async(Producer.run, .{ io, &queue });
    defer {
        producer.cancel(io) catch {};
        drainLookupQueue(io, &queue);
    }
    const addresses = try collectLookupAddresses(allocator, io, &queue);
    defer allocator.free(addresses);
    try producer.await(io);
    try std.testing.expectEqual(@as(usize, 40), addresses.len);
    try std.testing.expect(addresses[39].eql(&.{ .ip4 = .{
        .bytes = .{ 203, 0, 113, 40 },
        .port = 9443,
    } }));
}

test "HTTP/3 URI lookup collector preserves an empty closed queue" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue_storage: [16]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&queue_storage);
    queue.close(io);
    const addresses = try collectLookupAddresses(allocator, io, &queue);
    defer allocator.free(addresses);
    try std.testing.expectEqual(@as(usize, 0), addresses.len);
}

test "HTTP/3 URI endpoint parses authorities for handshake clients" {
    const allocator = std.testing.allocator;

    const host_uri = try std.Uri.parse("https://Example.COM:8443/robots.txt");
    var host_endpoint = try parseEndpoint(allocator, host_uri);
    defer host_endpoint.deinit();
    try std.testing.expectEqualStrings(
        "Example.COM:8443",
        host_endpoint.authority,
    );
    try std.testing.expectEqualStrings("Example.COM", host_endpoint.tls_host);
    try std.testing.expectEqual(@as(u16, 8443), host_endpoint.port);
    try std.testing.expect(host_endpoint.target == .host);

    const ip4_uri = try std.Uri.parse("https://127.0.0.1/");
    var ip4_endpoint = try parseEndpoint(allocator, ip4_uri);
    defer ip4_endpoint.deinit();
    try std.testing.expectEqualStrings("127.0.0.1", ip4_endpoint.authority);
    try std.testing.expectEqual(@as(u16, 443), ip4_endpoint.port);
    try std.testing.expect(ip4_endpoint.target == .ip);

    const ip6_uri = try std.Uri.parse("https://[::1]:9443/");
    var ip6_endpoint = try parseEndpoint(allocator, ip6_uri);
    defer ip6_endpoint.deinit();
    try std.testing.expectEqualStrings("[::1]:9443", ip6_endpoint.authority);
    try std.testing.expectEqualStrings("::1", ip6_endpoint.tls_host);
    try std.testing.expectEqual(@as(u16, 9443), ip6_endpoint.port);
    try std.testing.expect(ip6_endpoint.target == .ip);

    try std.testing.expectError(
        error.InvalidUri,
        parseEndpoint(allocator, try std.Uri.parse("http://example.com/")),
    );
    try std.testing.expectError(
        error.InvalidUri,
        parseEndpoint(
            allocator,
            try std.Uri.parse("https://user@example.com/"),
        ),
    );
}
