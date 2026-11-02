//! Borrowed reconnect targets and transport retry classification.
const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const endpoint = @import("../../endpoint_client.zig");
const Error = endpoint.Error || error{InvalidReconnectOptions};

pub const CustomConnector = struct {
    context: ?*anyopaque,
    connect_fn: *const fn (
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection,
    retryable_fn: ?*const fn (context: ?*anyopaque, err: anyerror) bool = null,
};

/// Borrowed for the ReconnectingEndpointClient lifetime. Established
/// connections and Sessions own their transport state independently.
pub const Target = union(enum) {
    cleartext_address: struct {
        address: std.Io.net.IpAddress,
        limits: http2.runtime.Limits = .{},
    },
    cleartext_host: struct {
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
    },
    tls_address: struct {
        address: std.Io.net.IpAddress,
        tls_host: []const u8,
        authority: []const u8,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    tls_host: struct {
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    tls_http_proxy: struct {
        host: []const u8,
        port: u16,
        proxy: http2.runtime.HttpConnectProxy,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    tls_socks5_proxy: struct {
        proxy: http2.socks5_runtime.Proxy,
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits = .{},
        tls: http2.runtime.TlsConnectOptions = .{},
    },
    custom: CustomConnector,

    pub fn validate(self: Target) Error!void {
        switch (self) {
            .cleartext_host => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            .tls_host => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            .tls_http_proxy => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            .tls_socks5_proxy => |value| if (value.port == 0) return error.InvalidReconnectOptions,
            else => {},
        }
    }

    pub fn connect(
        self: Target,
        allocator: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.runtime.Connection {
        return switch (self) {
            .cleartext_address => |value| http2.runtime.Client.connectWithDeadline(
                allocator,
                io,
                value.address,
                value.limits,
                deadline,
            ),
            .cleartext_host => |value| http2.runtime.Client.connectHostWithDeadline(
                allocator,
                io,
                value.host,
                value.port,
                value.limits,
                deadline,
            ),
            .tls_address => |value| http2.runtime.Client.connectTlsAddressWithDeadline(
                allocator,
                io,
                value.address,
                value.tls_host,
                value.authority,
                value.limits,
                value.tls,
                deadline,
            ),
            .tls_host => |value| http2.runtime.Client.connectTlsHostWithDeadline(
                allocator,
                io,
                value.host,
                value.port,
                value.limits,
                value.tls,
                deadline,
            ),
            .tls_http_proxy => |value| http2.runtime.Client
                .connectTlsHostViaProxyWithDeadline(
                allocator,
                io,
                value.host,
                value.port,
                value.proxy,
                value.limits,
                value.tls,
                deadline,
            ),
            .tls_socks5_proxy => |value| http2.socks5_runtime.Client
                .connectTlsHostWithDeadline(
                allocator,
                io,
                value.proxy,
                value.host,
                value.port,
                value.limits,
                value.tls,
                deadline,
            ),
            .custom => |value| value.connect_fn(
                value.context,
                allocator,
                io,
                deadline,
            ),
        };
    }

    pub fn retryable(self: Target, err: anyerror) bool {
        return switch (self) {
            .custom => |value| if (value.retryable_fn) |classify|
                classify(value.context, err)
            else
                retryableConnectError(err),
            else => retryableConnectError(err),
        };
    }
};

fn retryableConnectError(err: anyerror) bool {
    return switch (err) {
        error.AddressUnavailable,
        error.ConnectionPending,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.DetectingNetworkConfigurationFailed,
        error.HostUnreachable,
        error.NameServerFailure,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.NoAddressReturned,
        error.ProcessFdQuotaExceeded,
        error.ProxyConnectionClosed,
        error.ProxyConnectionRefused,
        error.ProxyGeneralFailure,
        error.ProxyHostUnreachable,
        error.ProxyNetworkUnreachable,
        error.ProxyTtlExpired,
        error.SocketUnconnected,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.Timeout,
        error.UnknownHostName,
        => true,
        else => false,
    };
}
