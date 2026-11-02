//! Listener transport and reference-counted per-connection owner.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const endpoint = @import("../endpoint_server.zig");
const Error = endpoint.Error;

pub const OwnedListener = union(enum) {
    cleartext: http2.runtime.Server,
    tls: http2.runtime.TlsServer,

    pub fn io(self: *const OwnedListener) std.Io {
        return switch (self.*) {
            .cleartext => |*value| value.io,
            .tls => |*value| value.io,
        };
    }

    pub fn address(self: *const OwnedListener) std.Io.net.IpAddress {
        return switch (self.*) {
            .cleartext => |value| value.address(),
            .tls => |value| value.address(),
        };
    }

    pub const Admission = struct {
        connection: http2.runtime.Connection,
        deadline: std.Io.Clock.Timestamp,
    };

    pub fn accept(self: *OwnedListener, timeout: std.Io.Duration) http2.runtime.Error!Admission {
        return switch (self.*) {
            inline else => |*server| blk: {
                const stream = try server.listener.accept(server.io);
                const deadline = std.Io.Clock.Timestamp.fromNow(server.io, .{ .clock = .awake, .raw = timeout });
                break :blk .{
                    .connection = try http2.runtime.acceptOwnedStreamWithDeadline(server, stream, deadline),
                    .deadline = deadline,
                };
            },
        };
    }

    pub fn deinit(self: *OwnedListener) void {
        switch (self.*) {
            .cleartext => |*value| value.deinit(),
            .tls => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};

pub const ManagedConnection = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    server: endpoint.EndpointServer,

    pub fn create(
        allocator: std.mem.Allocator,
        connection: http2.runtime.Connection,
        options: endpoint.Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*ManagedConnection {
        var owned_connection = connection;
        var connection_owned = true;
        errdefer if (connection_owned) owned_connection.closeWithoutCloseNotify();
        _ = try @import("../../../internal/deadline.zig").usableAwake(owned_connection.io, deadline);
        try owned_connection.io.checkCancel();
        const self = try allocator.create(ManagedConnection);
        errdefer allocator.destroy(self);
        connection_owned = false;
        const server = try endpoint.EndpointServer.initWithDeadline(
            allocator,
            owned_connection,
            options,
            deadline,
        );
        self.* = .{
            .allocator = allocator,
            .server = server,
        };
        return self;
    }

    pub fn retain(self: *ManagedConnection) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *ManagedConnection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.server.deinit();
        self.allocator.destroy(self);
    }
};
