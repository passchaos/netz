//! Bootstrap-driven xDS control-plane channel, delta client and failover.
const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const delta = @import("ads/delta.zig");
const lrs_client = @import("lrs/client.zig");
const shared = @import("../channel/shared.zig");
const streaming = @import("../stream/runtime.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const server_identity_file = @import("../../tls/server_identity_file.zig");
const http2 = @import("../../http2/mod.zig");
pub const Error = bootstrap.Error || shared.Error || delta.Error || lrs_client.Error || error{ InvalidControlPlaneOptions, NoUsableXdsServer, InvalidBootstrapNode, InvalidBootstrapTls };

pub const Options = struct {
    /// Overrides the bootstrap node. The bootstrap node is used otherwise.
    node: ?delta.codec.Node = null,
    /// Select an authority's xds_servers. Empty authority server lists fall
    /// back to the top-level servers.
    authority: ?[]const u8 = null,
    channel: shared.Options = .{},
    request: streaming.RequestOptions = .{ .path = delta.path, .wait_for_ready = true },
    subscriptions: delta.subscriptions.Options = .{},
    limits: delta.codec.Limits = .{},
    /// Per-server stream-opening budget. A failed server is skipped before the
    /// overall discovery deadline expires.
    server_open_timeout: std.Io.Duration = .fromMilliseconds(250),
};

fn usable(server: bootstrap.Server) bool {
    return (server.target.scheme == .http and server.hasInsecureCreds()) or
        (server.target.scheme == .https and server.hasTlsCreds());
}

fn earlier(a: std.Io.Clock.Timestamp, b: std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
    return if (a.raw.nanoseconds <= b.raw.nanoseconds) a else b;
}

const TlsMaterial = struct {
    allocator: std.mem.Allocator,
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_loaded: bool = false,
    lock: std.Io.RwLock = .init,
    identity: ?server_identity_file.Identity = null,

    fn load(gpa: std.mem.Allocator, io: std.Io, config: ?bootstrap.TlsConfig) Error!*TlsMaterial {
        const self = try gpa.create(TlsMaterial);
        self.* = .{ .allocator = gpa };
        errdefer self.deinit();
        const tls = config orelse return self;
        if (tls.ca_certificate_file.len != 0) {
            self.bundle.addCertsFromFilePath(gpa, io, std.Io.Timestamp.now(io, .real), std.Io.Dir.cwd(), tls.ca_certificate_file) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidBootstrapTls,
            };
            if (self.bundle.map.count() == 0) return error.InvalidBootstrapTls;
            self.bundle_loaded = true;
        }
        if (tls.certificate_file.len != 0) {
            self.identity = server_identity_file.load(gpa, io, std.Io.Dir.cwd(), tls.certificate_file, tls.private_key_file) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidBootstrapTls,
            };
        }
        return self;
    }
    fn deinit(self: *TlsMaterial) void {
        if (self.identity) |*identity| identity.deinit();
        self.bundle.deinit(self.allocator);
        self.allocator.destroy(self);
    }
    fn options(self: *TlsMaterial) http2.runtime.TlsConnectOptions {
        var result: http2.runtime.TlsConnectOptions = .{};
        if (self.bundle_loaded) result.ca_bundle = .{ .bundle = &self.bundle, .lock = &self.lock };
        if (self.identity) |*identity| {
            const value = identity.serverIdentity();
            result.client_identity = .{
                .certificate_chain = value.certificate_chain,
                .signer = value.signer,
                .certificate_type = value.certificate_type,
            };
        }
        return result;
    }
};

fn createChannel(gpa: std.mem.Allocator, io: std.Io, server: bootstrap.Server, options: shared.Options, material: *TlsMaterial) Error!shared.SharedChannel {
    if (server.target.scheme == .http) {
        if (!server.hasInsecureCreds()) return error.UnsupportedBootstrapCreds;
        return shared.SharedChannel.init(gpa, io, .{ .cleartext_host = .{ .host = server.target.host, .port = server.target.port } }, options);
    }
    if (server.target.scheme == .https) {
        if (!server.hasTlsCreds()) return error.UnsupportedBootstrapCreds;
        return shared.SharedChannel.init(gpa, io, .{ .tls_host = .{ .host = server.target.host, .port = server.target.port, .tls = material.options() } }, options);
    }
    return error.UnsupportedBootstrapCreds;
}

pub const ControlPlane = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    bootstrap: *bootstrap.Bootstrap,
    options: Options,
    servers: []bootstrap.Server,
    server_index: usize,
    material: *TlsMaterial,
    channel: shared.SharedChannel,
    client: delta.Client,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, options: Options) Error!*ControlPlane {
        const node = options.node orelse configuration.adsNode() orelse return error.InvalidBootstrapNode;
        if (node.id.len == 0) return error.InvalidBootstrapNode;
        const servers = if (options.authority) |name| blk: {
            const authority = configuration.authority(name) orelse return error.InvalidControlPlaneOptions;
            break :blk if (authority.servers.len != 0) authority.servers else configuration.servers;
        } else configuration.servers;
        var index: usize = 0;
        while (index < servers.len) : (index += 1) if (usable(servers[index])) break;
        if (index == servers.len) return error.NoUsableXdsServer;
        var material = try TlsMaterial.load(gpa, io, servers[index].tlsConfig());
        errdefer material.deinit();
        var channel = try createChannel(gpa, io, servers[index], options.channel, material);
        errdefer channel.deinit();
        var new_sender = channel.sender();
        defer new_sender.deinit();
        var client = try delta.Client.init(gpa, new_sender, .{ .node = node, .subscriptions = options.subscriptions, .limits = options.limits, .request = options.request });
        errdefer client.deinit();
        const self = try gpa.create(ControlPlane);
        self.* = .{ .allocator = gpa, .io = io, .bootstrap = configuration, .options = options, .servers = servers, .server_index = index, .material = material, .channel = channel, .client = client };
        return self;
    }
    pub fn deinit(self: *ControlPlane) void {
        self.client.deinit();
        self.channel.deinit();
        self.material.deinit();
        self.allocator.destroy(self);
    }
    pub fn discovery(self: *ControlPlane) *delta.Client {
        return &self.client;
    }
    pub fn server(self: *const ControlPlane) *const bootstrap.Server {
        return &self.servers[self.server_index];
    }
    pub fn serverUri(self: *const ControlPlane) []const u8 {
        return self.server().uri;
    }
    /// A new sender on the current control-plane channel. The caller owns it.
    pub fn sender(self: *ControlPlane) shared.Sender {
        return self.channel.sender();
    }
    /// Switch the current channel to the next usable server without connecting
    /// the owned delta client. Use this when other clients share the channel.
    pub fn moveToNextServer(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.advanceAndRebind();
    }
    pub fn moveToNextServerWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.moveToNextServer(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Rebind an external delta client to the current channel.
    pub fn rebindDelta(self: *ControlPlane, client: *delta.Client, request: streaming.RequestOptions) Error!void {
        var new_sender = self.channel.sender();
        errdefer new_sender.deinit();
        try client.rebind(new_sender, request);
    }
    /// Rebind an external LRS client to the current channel.
    pub fn rebindLrs(self: *ControlPlane, client: *lrs_client.Client, request: streaming.RequestOptions) Error!void {
        var new_sender = self.channel.sender();
        errdefer new_sender.deinit();
        try client.rebind(new_sender, request);
    }
    fn rebindServer(self: *ControlPlane, selected: usize) Error!void {
        const target_server = self.servers[selected];
        var material = try TlsMaterial.load(self.allocator, self.io, target_server.tlsConfig());
        errdefer material.deinit();
        var channel = try createChannel(self.allocator, self.io, target_server, self.options.channel, material);
        errdefer channel.deinit();
        var new_sender = channel.sender();
        var sender_owned = true;
        defer if (sender_owned) new_sender.deinit();
        try self.client.rebind(new_sender, self.options.request);
        sender_owned = false;
        self.channel.deinit();
        self.material.deinit();
        self.channel = channel;
        self.material = material;
        self.server_index = selected;
    }
    fn advanceAndRebind(self: *ControlPlane) Error!void {
        const servers = self.servers;
        var next: ?usize = null;
        var index = self.server_index + 1;
        while (index < servers.len) : (index += 1) if (usable(servers[index])) {
            next = index;
            break;
        };
        if (next == null) {
            index = 0;
            while (index <= self.server_index) : (index += 1) if (usable(servers[index])) {
                next = index;
                break;
            };
        }
        const selected = next orelse return error.NoUsableXdsServer;
        try self.rebindServer(selected);
    }
    /// Connect, trying the remaining usable bootstrap servers on failure.
    pub fn connectWithDeadline(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var attempts: usize = 0;
        var last_error: ?Error = null;
        while (attempts < self.bootstrap.servers.len) : (attempts += 1) {
            if (!usable(self.bootstrap.servers[self.server_index])) {
                try self.advanceAndRebind();
                continue;
            }
            const now = std.Io.Clock.Timestamp.now(self.io, .awake);
            const open_deadline = if (self.options.server_open_timeout.nanoseconds > 0)
                earlier(deadline, now.addDuration(.{ .clock = .awake, .raw = self.options.server_open_timeout }))
            else
                deadline;
            self.client.connectWithDeadline(open_deadline) catch |err| {
                switch (err) {
                    error.OutOfMemory, error.InvalidAdsOptions, error.DiscoveryLimitExceeded, error.InvalidDiscoveryMessage => return err,
                    else => last_error = err,
                }
                if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
                try self.advanceAndRebind();
                continue;
            };
            return;
        }
        return last_error orelse error.NoUsableXdsServer;
    }
    pub fn connectWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Reconnect the same logical session on the next usable server. The
    /// client retains desired names and accepted versions, so the new stream
    /// sends `initial_resource_versions` and the complete desired set.
    pub fn failoverWithDeadline(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.advanceAndRebind();
        try self.connectWithDeadline(deadline);
    }
    pub fn failoverWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.failoverWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Reconnect the same server after a stream terminal.
    pub fn reconnectWithDeadline(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.client.connectWithDeadline(deadline);
    }
    pub fn reconnectWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reconnectWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Re-read the current server's TLS files, recreate its channel, rebind the
    /// client and reconnect. Desired names and accepted versions are retained.
    /// A failed load leaves the current channel and material untouched.
    pub fn reloadServerWithDeadline(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.rebindServer(self.server_index);
        try self.connectWithDeadline(deadline);
    }
    pub fn reloadServerWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reloadServerWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
};
