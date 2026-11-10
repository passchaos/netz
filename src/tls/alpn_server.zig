//! TLS listener that exposes the negotiated ALPN protocol to the caller.
//!
//! Application protocols use this when one TCP port must serve more than one
//! ALPN protocol (for example `h2` and `http/1.1`). The caller owns the
//! accepted TLS connection and dispatches it to the matching protocol runtime.

const std = @import("std");
const accept_deadline = @import("../internal/accept.zig");
const socket_options = @import("../internal/socket_options.zig");
const stream = @import("stream/mod.zig");

pub const Options = struct {
    address: std.Io.net.IpAddress,
    tls: stream.ServerOptions,
    tcp_nodelay: bool = true,
};

pub const Accepted = struct {
    stream: std.Io.net.Stream,
    tls: *stream.ServerConnection,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: std.Io.net.Server,
    tls: stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
    ) !Server {
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try options.address.listen(
                io,
                .{ .reuse_address = true },
            ),
            .tls = options.tls,
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) std.Io.net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn acceptWithTimeout(
        self: *Server,
        timeout: std.Io.Duration,
    ) !Accepted {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) !Accepted {
        const net_stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        var stream_owned = true;
        errdefer if (stream_owned) net_stream.close(self.io);
        if (self.tcp_nodelay) {
            try socket_options.setTcpNoDelay(net_stream);
        }
        const tls_connection = try stream.ServerConnection.initWithDeadline(
            self.allocator,
            self.io,
            net_stream,
            self.tls,
            deadline,
        );
        stream_owned = false;
        return .{
            .stream = net_stream,
            .tls = tls_connection,
        };
    }
};
