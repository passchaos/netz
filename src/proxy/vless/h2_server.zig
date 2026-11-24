//! VLESS over HTTP/2 CONNECT tunnels.
//!
//! The HTTP/2 transport terminates TLS and exposes a bidirectional tunnel per
//! CONNECT stream. VLESS then runs its normal request parser on that tunnel.

const std = @import("std");
const netz = @import("../netz.zig");

const vless = @import("server.zig");
const protocol = @import("protocol.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const h2_stream = @import("../transport/h2_stream.zig");

const net = std.Io.net;
const http2 = netz.http2;

pub const Config = struct {
    uuid: protocol.Uuid,
    identity: netz.quic.tls.auth.ServerIdentity,
    acl: acl.Policy = .{},
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    auth_timeout: std.Io.Duration = .fromSeconds(10),
    relay_buffer_size: usize = 16 * 1024,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    listener: http2.runtime.TlsServer,
    limiter: limits.ConnectionLimiter,
    running: std.atomic.Value(bool) = .init(true),
    active_jobs: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        config: Config,
    ) !Server {
        var listener = try http2.runtime.TlsServer.listen(
            allocator,
            io,
            bind_address,
            .{
                .identity = config.identity,
                .tls_handshake_timeout = config.auth_timeout,
            },
        );
        errdefer listener.deinit();
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
        self.listener.deinit();
        self.* = undefined;
    }

    pub fn requestStop(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn address(self: *const Server) net.IpAddress {
        return self.listener.address();
    }

    pub fn serve(self: *Server) !void {
        while (self.running.load(.acquire)) {
            var connection = self.listener.acceptWithTimeout(
                .fromSeconds(1),
            ) catch continue;
            const job = self.allocator.create(Job) catch {
                connection.close();
                continue;
            };
            job.* = .{ .server = self, .connection = connection };
            _ = self.active_jobs.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
                _ = self.active_jobs.fetchSub(1, .release);
                self.allocator.destroy(job);
                job.connection.close();
                continue;
            };
            thread.detach();
        }
    }

    const Job = struct {
        server: *Server,
        connection: http2.runtime.Connection,

        fn run(self: *Job) void {
            const server = self.server;
            defer _ = server.active_jobs.fetchSub(1, .release);
            defer server.allocator.destroy(self);
            defer self.connection.close();
            processConnection(
                server.allocator,
                server.io,
                &self.connection,
                server.config,
                &server.limiter,
            ) catch {};
        }
    };
};

fn processConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *http2.runtime.Connection,
    config: Config,
    limiter: ?*limits.ConnectionLimiter,
) !void {
    const peer = connection.peerAddress() orelse return error.SocketUnconnected;
    while (true) {
        var request = connection.readRequestWithTimeout(config.auth_timeout) catch break;
        defer request.deinit(allocator);
        if (!std.mem.eql(u8, request.method, "CONNECT")) break;

        var tunnel = connection.acceptConnectTunnel(request, &.{}) catch break;
        var stream = h2_stream.Stream.init(
            allocator,
            io,
            &tunnel,
            config.idle_timeout,
        );
        defer stream.deinit();
        vless.processTlsConnection(
            allocator,
            io,
            &stream,
            peer,
            .{
                .uuid = config.uuid,
                .tls = null,
                .acl = config.acl,
                .policy_store = config.policy_store,
                .limits = config.limits,
                .connect_timeout = config.connect_timeout,
                .idle_timeout = config.idle_timeout,
                .relay_buffer_size = config.relay_buffer_size,
                .stats = config.stats,
                .rate_limiter = config.rate_limiter,
                .transport = .h2,
            },
            limiter,
        ) catch {};
        tunnel.abort(null);
    }
}
