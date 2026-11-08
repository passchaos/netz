//! VLESS over QUIC using one client-initiated bidirectional stream.
//!
//! QUIC already terminates TLS, so the VLESS request and relay payload run
//! directly on the stream without a second TLS handshake.

const std = @import("std");
const netz = @import("../netz.zig");

const vless = @import("server.zig");
const protocol = @import("protocol.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const quic_stream = @import("../transport/quic_stream.zig");

const quic = netz.quic;
const net = std.Io.net;

pub const Config = struct {
    uuid: protocol.Uuid,
    identity: quic.tls.auth.ServerIdentity,
    alpn_protocol: []const u8 = "vless",
    acl: acl.Policy = .{},
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    auth_timeout: std.Io.Duration = .fromSeconds(10),
    max_datagram_size: usize = 4096,
    relay_buffer_size: usize = 16 * 1024,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    endpoint: quic.runtime.Endpoint,
    limiter: limits.ConnectionLimiter,
    running: std.atomic.Value(bool) = .init(true),
    active_jobs: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        config: Config,
    ) !Server {
        const endpoint = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            bind_address,
            .{ .max_datagram_size = config.max_datagram_size },
        );
        errdefer endpoint.deinit();
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
            .endpoint = endpoint,
            .limiter = limiter,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);
        while (self.active_jobs.load(.acquire) != 0) {
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch {};
        }
        self.limiter.deinit();
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn requestStop(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn address(self: *const Server) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn serve(self: *Server) !void {
        while (self.running.load(.acquire)) {
            var local_cid: [4]u8 = undefined;
            self.io.random(&local_cid);
            var random: [32]u8 = undefined;
            self.io.random(&random);
            var x25519: [32]u8 = undefined;
            self.io.random(&x25519);
            var established = quic.handshake.accept(
                &self.endpoint,
                .{
                    .local_connection_id = &local_cid,
                    .alpn_protocol = self.config.alpn_protocol,
                    .identity = self.config.identity,
                    .random = random,
                    .x25519_secret_key = x25519,
                    .max_crypto_buffer = 64 * 1024,
                },
            ) catch continue;
            const job = self.allocator.create(Job) catch {
                established.deinit();
                continue;
            };
            job.* = .{ .server = self, .established = established };
            self.active_jobs.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
                self.active_jobs.fetchSub(1, .release);
                self.allocator.destroy(job);
                job.established.deinit();
                continue;
            };
            thread.detach();
        }
    }

    const Job = struct {
        server: *Server,
        established: quic.handshake.EstablishedConnection,

        fn run(self: *Job) void {
            const server = self.server;
            defer server.active_jobs.fetchSub(1, .release);
            defer server.allocator.destroy(self);
            defer self.established.deinit();
            processEstablished(
                server.allocator,
                server.io,
                &self.established,
                server.config,
                &server.limiter,
            ) catch {};
        }
    };
};

pub fn processEstablished(
    allocator: std.mem.Allocator,
    io: std.Io,
    established: *quic.handshake.EstablishedConnection,
    config: Config,
    limiter: ?*limits.ConnectionLimiter,
) !void {
    const peer = established.connection.config.peer;
    if (config.rate_limiter) |value| {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        if (!value.allow(peer, 1, now)) return error.RateLimited;
    }

    var buffer: [4096]u8 = undefined;
    const event = try established.connection.receiveStreamWithTimeout(
        &buffer,
        config.auth_timeout,
    );
    var stream_id: u64 = undefined;
    var initial_len: usize = 0;
    switch (event) {
        .data => |data| {
            stream_id = data.stream_id;
            initial_len = data.bytes;
        },
        .reset => return error.ConnectionClosed,
    }

    var stream = quic_stream.Stream.init(
        io,
        established,
        stream_id,
        config.idle_timeout,
    );
    stream.setInitial(buffer[0..initial_len]);
    defer stream.deinit();

    try vless.processTlsConnection(
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
            .transport = .quic,
        },
        limiter,
    );
}
