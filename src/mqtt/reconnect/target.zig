//! Owned raw MQTT endpoint used by the reconnecting client.
//!
//! Unlike the generic connector escape hatch, raw hostname and URI targets do
//! not need to borrow application state. Owning their canonical text makes a
//! reconnect safe after the initialization arguments disappear and allows DNS
//! to be resolved again on each connection attempt.

const std = @import("std");
const redirect = @import("../redirect.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

pub const Target = union(enum) {
    tcp: net.IpAddress,
    host: struct {
        name: []u8,
        port: u16,
    },
    uri: []u8,
    connector: runtime.ClientConnector,

    pub fn initHost(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
    ) (std.mem.Allocator.Error || net.HostName.ValidateError)!Target {
        _ = try net.HostName.init(host);
        return .{ .host = .{
            .name = try allocator.dupe(u8, host),
            .port = port,
        } };
    }

    pub fn initUri(
        allocator: std.mem.Allocator,
        uri_text: []const u8,
    ) redirect.Error!Target {
        var parsed = try redirect.parse(allocator, uri_text, .tcp);
        defer parsed.deinit();
        if (parsed.transport != .tcp) {
            return error.UnsupportedRedirectScheme;
        }
        return .{ .uri = try allocator.dupe(u8, parsed.uri) };
    }

    pub fn deinit(self: *Target, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .host => |host| allocator.free(host.name),
            .uri => |uri| allocator.free(uri),
            .tcp, .connector => {},
        }
        self.* = undefined;
    }

    pub fn connectAttempt(
        self: Target,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: runtime.ConnectOptions,
        tls_tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        return switch (self) {
            .tcp => |address| runtime.Client.connectAttempt(
                allocator,
                io,
                address,
                options,
            ),
            .host => |host| runtime.Client.connectHostAttempt(
                allocator,
                io,
                host.name,
                host.port,
                options,
            ),
            .uri => |uri| runtime.Client.connectUriAttempt(
                allocator,
                io,
                uri,
                options,
            ),
            .connector => |connector| connector.connectAttemptWithTlsTickets(
                allocator,
                io,
                options,
                tls_tickets,
            ),
        };
    }

    pub fn connectAttemptWithDeadline(
        self: Target,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: runtime.ConnectOptions,
        tls_tickets: runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) runtime.Error!runtime.ConnectAttempt {
        return switch (self) {
            .tcp => |address| runtime.Client.connectAttemptWithDeadline(
                allocator,
                io,
                address,
                options,
                deadline,
            ),
            .host => |host| runtime.Client.connectHostAttemptWithDeadline(
                allocator,
                io,
                host.name,
                host.port,
                options,
                deadline,
            ),
            .uri => |uri| runtime.Client.connectUriAttemptWithDeadline(
                allocator,
                io,
                uri,
                options,
                deadline,
            ),
            .connector => |connector| connector
                .connectAttemptWithTlsTicketsAndDeadline(
                allocator,
                io,
                options,
                tls_tickets,
                deadline,
            ),
        };
    }
};
