//! TLS HTTP/2 over RFC 1928 SOCKS5 CONNECT with proxy-side origin DNS.
const std = @import("std");
const runtime = @import("runtime.zig");
const socks5 = @import("../proxy/socks5.zig");
const endpoint_host = @import("../internal/endpoint_host.zig");
const deadline_policy = @import("../internal/deadline.zig");

pub const Error = runtime.Error || socks5.Error || std.Io.Timeout.Error;

/// Borrowed for one connection attempt. Destination hostname resolution stays
/// inside the proxy; these options configure only the proxy transport.
pub const Proxy = struct {
    host: []const u8,
    port: u16 = 1080,
    options: socks5.Options = .{},
};

pub const Client = struct {
    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Proxy,
        host: []const u8,
        port: u16,
        limits: runtime.Limits,
        tls_options: runtime.TlsConnectOptions,
    ) Error!runtime.Connection {
        const origin = try Origin.init(allocator, host, port);
        defer origin.deinit(allocator);
        var proxy_options = proxy.options;
        if (limits.local_address) |address| proxy_options.local_address = address;
        if (limits.network_interface) |interface| proxy_options.network_interface = interface;
        const stream = try socks5.connectHost(
            allocator,
            io,
            proxy.host,
            proxy.port,
            origin.identity,
            port,
            proxy_options,
        );
        return runtime.Client.adoptTlsStream(
            allocator,
            io,
            stream,
            origin.identity,
            origin.authority,
            limits,
            tls_options,
        );
    }

    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Proxy,
        host: []const u8,
        port: u16,
        limits: runtime.Limits,
        tls_options: runtime.TlsConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!runtime.Connection {
        _ = try deadline_policy.usableAwake(io, deadline);
        const origin = try Origin.init(allocator, host, port);
        defer origin.deinit(allocator);
        var proxy_options = proxy.options;
        if (limits.local_address) |address| proxy_options.local_address = address;
        if (limits.network_interface) |interface| proxy_options.network_interface = interface;
        const stream = try socks5.connectHostWithDeadline(
            allocator,
            io,
            proxy.host,
            proxy.port,
            origin.identity,
            port,
            proxy_options,
            deadline,
        );
        return runtime.Client.adoptTlsStreamWithDeadline(
            allocator,
            io,
            stream,
            origin.identity,
            origin.authority,
            limits,
            tls_options,
            deadline,
        );
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: Proxy,
        host: []const u8,
        port: u16,
        limits: runtime.Limits,
        tls_options: runtime.TlsConnectOptions,
        timeout: std.Io.Duration,
    ) Error!runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            proxy,
            host,
            port,
            limits,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
};

const Origin = struct {
    identity: []const u8,
    authority: []u8,

    fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
    ) (std.mem.Allocator.Error || std.Io.net.HostName.ValidateError || error{
        InvalidTargetPort,
    })!Origin {
        if (port == 0) return error.InvalidTargetPort;
        const parsed = try endpoint_host.parse(host, port);
        return .{
            .identity = parsed.host,
            .authority = try parsed.authorityAlloc(allocator, port),
        };
    }

    fn deinit(self: Origin, allocator: std.mem.Allocator) void {
        allocator.free(self.authority);
    }
};

test "HTTP/2 SOCKS5 TLS validates timeout and origin allocation before proxy I/O" {
    try std.testing.expectError(
        error.Timeout,
        Client.connectTlsHostWithTimeout(
            std.testing.allocator,
            undefined,
            .{ .host = "proxy.invalid" },
            "origin.invalid",
            443,
            .{},
            .{},
            .zero,
        ),
    );
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        Client.connectTlsHost(
            failing.allocator(),
            undefined,
            .{ .host = "proxy.invalid" },
            "origin.invalid",
            443,
            .{},
            .{},
        ),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(
        failing.allocated_bytes,
        failing.freed_bytes,
    );
}
