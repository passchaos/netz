//! TLS ticket lifecycle for the negotiated HTTP/1.1 and HTTP/2 pool.

const std = @import("std");
const client = @import("../client.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_ticket_cache = @import("../../tls/stream/client_ticket_cache.zig");
const setup_tickets = @import("../../internal/pool_tickets/setup.zig");

pub const Manager = struct {
    io: std.Io,
    options: client.Options,
    tls12: tls_ticket_cache.Cache,
    tls13: tls_ticket_cache.Tls13Cache,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: client.Options,
        max_tls12: usize,
        max_tls13: usize,
    ) Manager {
        return .{
            .io = io,
            .options = options,
            .tls12 = .init(allocator, io, max_tls12),
            .tls13 = .init(allocator, io, max_tls13),
        };
    }

    pub fn deinit(self: *Manager) void {
        self.tls12.deinit();
        self.tls13.deinit();
        self.* = undefined;
    }

    pub fn clear(self: *Manager) void {
        self.clearBefore(null) catch unreachable;
    }

    pub fn clearBefore(self: *Manager, deadline: ?std.Io.Clock.Timestamp) !void {
        try self.tls12.clearBefore(deadline);
        try self.tls13.clearBefore(deadline);
    }

    pub fn cloneTls12(
        self: *Manager,
        host: []const u8,
        port: u16,
    ) !?tls_stream.Tls12SessionTicket {
        return self.cloneTls12Before(host, port, null);
    }

    pub fn cloneTls12Before(
        self: *Manager,
        host: []const u8,
        port: u16,
        deadline: ?std.Io.Clock.Timestamp,
    ) !?tls_stream.Tls12SessionTicket {
        const now = realNowSeconds(self.io);
        return switch (self.options.protocol_policy) {
            .http2_only => self.tls12.cloneForAlpnBefore(host, port, "h2", now, deadline),
            .http1_only => (try self.tls12.cloneForAlpnBefore(
                host,
                port,
                "http/1.1",
                now,
                deadline,
            )) orelse if (self.options.allow_http1_without_alpn)
                try self.tls12.cloneForAlpnBefore(host, port, "", now, deadline)
            else
                null,
            .prefer_http2 => (try self.tls12.cloneForAlpnBefore(
                host,
                port,
                "h2",
                now,
                deadline,
            )) orelse (try self.tls12.cloneForAlpnBefore(
                host,
                port,
                "http/1.1",
                now,
                deadline,
            )) orelse if (self.options.allow_http1_without_alpn)
                try self.tls12.cloneForAlpnBefore(host, port, "", now, deadline)
            else
                null,
        };
    }

    pub fn cloneTls13(
        self: *Manager,
        host: []const u8,
        port: u16,
    ) !?tls_stream.Tls13SessionTicket {
        return self.cloneTls13Before(host, port, null);
    }

    pub fn cloneTls13Before(
        self: *Manager,
        host: []const u8,
        port: u16,
        deadline: ?std.Io.Clock.Timestamp,
    ) !?tls_stream.Tls13SessionTicket {
        const now = realNowMilliseconds(self.io);
        return switch (self.options.protocol_policy) {
            .http2_only => self.tls13.cloneForAlpnBefore(host, port, "h2", now, deadline),
            .http1_only => (try self.tls13.cloneForAlpnBefore(
                host,
                port,
                "http/1.1",
                now,
                deadline,
            )) orelse if (self.options.allow_http1_without_alpn)
                try self.tls13.cloneForAlpnBefore(host, port, "", now, deadline)
            else
                null,
            .prefer_http2 => (try self.tls13.cloneForAlpnBefore(
                host,
                port,
                "h2",
                now,
                deadline,
            )) orelse (try self.tls13.cloneForAlpnBefore(
                host,
                port,
                "http/1.1",
                now,
                deadline,
            )) orelse if (self.options.allow_http1_without_alpn)
                try self.tls13.cloneForAlpnBefore(host, port, "", now, deadline)
            else
                null,
        };
    }

    pub fn rememberSetupBefore(self: *Manager, host: []const u8, port: u16, connection: *client.Connection, attempted_tls13: bool, deadline: ?std.Io.Clock.Timestamp) !void {
        try setup_tickets.remember12(&self.tls12, connection, host, port, true, self.io, deadline);
        _ = try setup_tickets.remember13(&self.tls13, connection, host, port, true, attempted_tls13, self.io, deadline);
    }

    pub fn rememberTls12(
        self: *Manager,
        host: []const u8,
        port: u16,
        connection: *client.Connection,
    ) void {
        if (connection.takeTls12SessionTicket()) |ticket| {
            self.tls12.store(
                host,
                port,
                ticket,
                realNowSeconds(self.io),
            );
            return;
        }
        if (connection.negotiatedTlsProtocol() == .tls12 and
            !(connection.wasTlsSessionResumed() orelse false))
        {
            if (connection.negotiatedAlpn()) |alpn| {
                _ = self.tls12.removeForAlpn(host, port, alpn);
            }
        }
    }

    pub fn rememberTls13(
        self: *Manager,
        host: []const u8,
        port: u16,
        connection: *client.Connection,
    ) tls_stream.Error!bool {
        if (try connection.takeTls13SessionTicket()) |ticket| {
            self.tls13.store(
                host,
                port,
                ticket,
                realNowMilliseconds(self.io),
            );
            return true;
        }
        return false;
    }

    pub fn removeTls13ForConnection(
        self: *Manager,
        host: []const u8,
        port: u16,
        connection: *const client.Connection,
    ) void {
        if (connection.negotiatedAlpn()) |alpn| {
            _ = self.tls13.removeForAlpn(host, port, alpn);
        }
    }

    /// Remove both protocol-version tickets for the connection's exact ALPN.
    /// This is used when a release races pool shutdown after post-handshake
    /// tickets were collected.
    pub fn removeForConnection(
        self: *Manager,
        host: []const u8,
        port: u16,
        connection: *const client.Connection,
    ) void {
        const alpn = connection.negotiatedAlpn() orelse "";
        _ = self.tls12.removeForAlpn(host, port, alpn);
        _ = self.tls13.removeForAlpn(host, port, alpn);
    }
};

fn realNowSeconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toSeconds()));
}

fn realNowMilliseconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Timestamp.now(io, .real).toMilliseconds()));
}
