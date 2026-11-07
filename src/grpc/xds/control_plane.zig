//! Bootstrap-driven xDS control-plane channel, delta client and failover.
const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const delta = @import("ads/delta.zig");
const ads = @import("ads.zig");
const Source = @import("discovery_source.zig").Source;
const lrs_client = @import("lrs/client.zig");
const shared = @import("../channel/shared.zig");
const streaming = @import("../stream/runtime.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const server_identity_file = @import("../../tls/server_identity_file.zig");
const http2 = @import("../../http2/mod.zig");
pub const Error = @import("discovery_source.zig").Error || bootstrap.Error || shared.Error || delta.Error || lrs_client.Error || error{ InvalidControlPlaneOptions, NoUsableXdsServer, InvalidBootstrapNode, InvalidBootstrapTls };

pub const Options = struct {
    /// Overrides the bootstrap node. The bootstrap node is used otherwise.
    node: ?delta.codec.Node = null,
    /// Select an authority's xds_servers. Empty authority server lists fall
    /// back to the top-level servers.
    authority: ?[]const u8 = null,
    /// Private control plane restricted to one immutable LRS destination.
    /// Construction creates the channel without opening an RPC.
    pinned_server: ?bootstrap.Server = null,
    channel: shared.Options = .{},
    request: streaming.RequestOptions = .{ .path = delta.path, .wait_for_ready = true },
    subscriptions: delta.subscriptions.Options = .{},
    limits: delta.codec.Limits = .{},
    /// Per-server stream-opening budget. A failed server is skipped before the
    /// overall discovery deadline expires.
    server_open_timeout: std.Io.Duration = .fromMilliseconds(250),
};

fn usable(server: bootstrap.Server) bool {
    return server.selectedCredential() != null;
}

fn earlier(a: std.Io.Clock.Timestamp, b: std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
    return if (a.raw.nanoseconds <= b.raw.nanoseconds) a else b;
}

fn resolveTls(config: ?bootstrap.TlsConfig, configuration: *bootstrap.Bootstrap) Error!?bootstrap.TlsConfig {
    var tls = config orelse return null;
    var root_interval: ?std.Io.Duration = null;
    var identity_interval: ?std.Io.Duration = null;
    if (tls.root_certificate_provider.len != 0) {
        const provider = configuration.certificateProvider(tls.root_certificate_provider) orelse return error.InvalidBootstrapTls;
        tls.ca_certificate_file = provider.ca_certificate_file;
        root_interval = provider.refresh_interval;
    }
    if (tls.identity_certificate_provider.len != 0) {
        const provider = configuration.certificateProvider(tls.identity_certificate_provider) orelse return error.InvalidBootstrapTls;
        tls.certificate_file = provider.certificate_file;
        tls.private_key_file = provider.private_key_file;
        identity_interval = provider.refresh_interval;
    }
    if (root_interval) |root| {
        tls.refresh_interval = if (identity_interval) |identity| if (identity.nanoseconds > 0 and identity.nanoseconds < root.nanoseconds) identity else root else root;
    } else if (identity_interval) |identity| tls.refresh_interval = identity;
    return tls;
}

const TlsMaterial = struct {
    allocator: std.mem.Allocator,
    bootstrap: *bootstrap.Bootstrap,
    host: []u8 = &.{},
    refs: std.atomic.Value(usize) = .init(1),
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_loaded: bool = false,
    lock: std.Io.RwLock = .init,
    identity: ?server_identity_file.Identity = null,

    fn load(gpa: std.mem.Allocator, io: std.Io, server: bootstrap.Server, configuration: *bootstrap.Bootstrap) Error!*TlsMaterial {
        const self = try gpa.create(TlsMaterial);
        self.* = .{ .allocator = gpa, .bootstrap = configuration.retain() };
        errdefer self.deinit();
        self.host = try gpa.dupe(u8, server.target.host);
        const tls = try resolveTls(server.tlsConfig(), configuration) orelse return self;
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
    fn retainOpaque(context: *anyopaque) void {
        const self: *TlsMaterial = @ptrCast(@alignCast(context));
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    fn releaseOpaque(context: *anyopaque) void {
        const self: *TlsMaterial = @ptrCast(@alignCast(context));
        self.deinit();
    }
    fn lifetime(self: *TlsMaterial) @import("../channel/shared/target_lifetime.zig").Lifetime {
        return .{ .context = self, .retain_fn = retainOpaque, .release_fn = releaseOpaque };
    }
    fn deinit(self: *TlsMaterial) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.identity) |*identity| identity.deinit();
        self.bundle.deinit(self.allocator);
        self.allocator.free(self.host);
        self.bootstrap.deinit();
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
    if (server.selectedCredential() == null) return error.UnsupportedBootstrapCreds;
    // Credential preference is fixed by bootstrap order. Connection failures
    // retry that transport or another server without changing credentials.
    const channel = if (server.usesTls())
        try shared.SharedChannel.init(gpa, io, .{ .tls_host = .{ .host = material.host, .port = server.target.port, .tls = material.options() } }, options)
    else
        try shared.SharedChannel.init(gpa, io, .{ .cleartext_host = .{ .host = material.host, .port = server.target.port } }, options);
    channel.state.target_lifetime = material.lifetime().retain();
    for (channel.state.sources) |source| source.target_lifetime = material.lifetime().retain();
    return channel;
}

pub const ControlPlane = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    bootstrap: *bootstrap.Bootstrap,
    source: *Source,
    options: Options,
    servers: []bootstrap.Server,
    servers_owned: bool = false,
    server_index: usize,
    material: *TlsMaterial,
    channel: shared.SharedChannel,
    client: delta.Client,
    last_reload_ns: ?i96 = null,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, options: Options) Error!*ControlPlane {
        const node = options.node orelse configuration.adsNode() orelse return error.InvalidBootstrapNode;
        if (node.id.len == 0) return error.InvalidBootstrapNode;
        const servers_owned = options.pinned_server != null;
        const servers = if (options.pinned_server) |selected_server| blk: {
            const inventory = try gpa.alloc(bootstrap.Server, 1);
            inventory[0] = selected_server;
            break :blk inventory;
        } else if (options.authority) |name| blk: {
            const authority = configuration.authority(name) orelse return error.InvalidControlPlaneOptions;
            break :blk if (authority.servers.len != 0) authority.servers else configuration.servers;
        } else configuration.servers;
        errdefer if (servers_owned) gpa.free(servers);
        var index: usize = 0;
        while (index < servers.len) : (index += 1) if (usable(servers[index])) break;
        if (index == servers.len) return error.NoUsableXdsServer;
        var request = options.request;
        request.path = delta.path;
        request.max_message_size = @min(request.max_message_size, options.limits.max_message_bytes);
        const source = try Source.create(gpa, configuration, servers[index], node, request);
        errdefer source.release();
        if (servers_owned) servers[0] = source.server;
        var material = try TlsMaterial.load(gpa, io, source.server, configuration);
        errdefer material.deinit();
        var channel = try createChannel(gpa, io, servers[index], options.channel, material);
        errdefer channel.deinit();
        var new_sender = channel.sender();
        defer new_sender.deinit();
        var client = try delta.Client.init(gpa, new_sender, .{ .node = source.node, .source = source, .subscriptions = options.subscriptions, .limits = options.limits, .request = source.request });
        errdefer client.deinit();
        const self = try gpa.create(ControlPlane);
        self.* = .{ .allocator = gpa, .io = io, .bootstrap = configuration.retain(), .source = source, .options = options, .servers = servers, .servers_owned = servers_owned, .server_index = index, .material = material, .channel = channel, .client = client, .last_reload_ns = std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds };
        return self;
    }
    pub fn deinit(self: *ControlPlane) void {
        self.client.deinit();
        self.channel.deinit();
        self.material.deinit();
        self.source.release();
        self.bootstrap.deinit();
        if (self.servers_owned) self.allocator.free(self.servers);
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
    /// Construct a managed SotW client on the selected server. The client's
    /// actual typed node and request become its immutable reporting source.
    pub fn newSotwClient(self: *ControlPlane, options: ads.Options) Error!ads.Client {
        var request = options.request;
        request.path = ads.path;
        request.max_message_size = @min(request.max_message_size, options.limits.max_message_bytes);
        const source = try Source.create(self.allocator, self.bootstrap, self.server().*, options.node, request);
        defer source.release();
        var sender_handle = self.channel.sender();
        defer sender_handle.deinit();
        var managed = options;
        managed.node = source.node;
        managed.request = source.request;
        managed.source = source;
        return ads.Client.init(self.allocator, sender_handle, managed);
    }
    pub fn newDeltaClient(self: *ControlPlane, options: delta.Options) Error!delta.Client {
        var request = options.request;
        request.path = delta.path;
        request.max_message_size = @min(request.max_message_size, options.limits.max_message_bytes);
        const source = try Source.create(self.allocator, self.bootstrap, self.server().*, options.node, request);
        defer source.release();
        var sender_handle = self.channel.sender();
        defer sender_handle.deinit();
        var managed = options;
        managed.node = source.node;
        managed.request = source.request;
        managed.source = source;
        return delta.Client.init(self.allocator, sender_handle, managed);
    }
    /// Rebind an external client. Managed clients preserve their original
    /// typed node while capturing the new server and request.
    pub fn rebindDelta(self: *ControlPlane, client: *delta.Client, request: streaming.RequestOptions) Error!void {
        var normalized = request;
        normalized.path = delta.path;
        normalized.max_message_size = @min(normalized.max_message_size, client.limits.max_message_bytes);
        const source = if (client.source) |origin| try Source.create(self.allocator, self.bootstrap, self.server().*, origin.node, normalized) else null;
        defer if (source) |value| value.release();
        var new_sender = self.channel.sender();
        errdefer new_sender.deinit();
        try client.rebindWithSource(new_sender, if (source) |value| value.request else normalized, source);
    }
    pub fn rebindSotw(self: *ControlPlane, client: *ads.Client, request: streaming.RequestOptions) Error!void {
        var normalized = request;
        normalized.path = ads.path;
        normalized.max_message_size = @min(normalized.max_message_size, client.limits.max_message_bytes);
        const source = if (client.source) |origin| try Source.create(self.allocator, self.bootstrap, self.server().*, origin.node, normalized) else null;
        defer if (source) |value| value.release();
        var new_sender = self.channel.sender();
        errdefer new_sender.deinit();
        try client.rebindWithSource(new_sender, if (source) |value| value.request else normalized, source);
    }
    /// Rebind an external LRS client to the current channel.
    pub fn rebindLrs(self: *ControlPlane, client: *lrs_client.Client, request: streaming.RequestOptions) Error!void {
        var new_sender = self.channel.sender();
        errdefer new_sender.deinit();
        try client.rebind(new_sender, request);
    }
    fn advanceAndRebindLrs(self: *ControlPlane, client: *lrs_client.Client, request: streaming.RequestOptions) Error!void {
        try self.advanceAndRebind();
        try self.rebindLrs(client, request);
    }
    /// Fail over an external LRS client to the next usable server and reconnect
    /// it, trying every remaining server when the first choice refuses. The
    /// client retains its node, counters and stream state.
    pub fn failoverLrsWithDeadline(self: *ControlPlane, client: *lrs_client.Client, request: streaming.RequestOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.advanceAndRebindLrs(client, request);
        var attempts: usize = 0;
        var last_error: ?Error = null;
        while (attempts < self.servers.len) : (attempts += 1) {
            if (!usable(self.servers[self.server_index])) {
                try self.advanceAndRebindLrs(client, request);
                continue;
            }
            const now = std.Io.Clock.Timestamp.now(self.io, .awake);
            const open_deadline = if (self.options.server_open_timeout.nanoseconds > 0)
                earlier(deadline, now.addDuration(.{ .clock = .awake, .raw = self.options.server_open_timeout }))
            else
                deadline;
            client.connectWithDeadline(open_deadline) catch |err| {
                switch (err) {
                    error.OutOfMemory, error.InvalidLrsOptions, error.InvalidLoadReport, error.LoadReportLimitExceeded => return err,
                    else => last_error = err,
                }
                if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) return error.Timeout;
                try self.advanceAndRebindLrs(client, request);
                continue;
            };
            return;
        }
        return last_error orelse error.NoUsableXdsServer;
    }
    pub fn failoverLrsWithTimeout(self: *ControlPlane, client: *lrs_client.Client, request: streaming.RequestOptions, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.failoverLrsWithDeadline(client, request, .fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Reconnect an external LRS client on the current server without moving
    /// the shared control channel. The per-server stream-opening budget applies.
    pub fn reconnectLrsWithDeadline(self: *ControlPlane, client: *lrs_client.Client, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const now = std.Io.Clock.Timestamp.now(self.io, .awake);
        const open_deadline = if (self.options.server_open_timeout.nanoseconds > 0)
            earlier(deadline, now.addDuration(.{ .clock = .awake, .raw = self.options.server_open_timeout }))
        else
            deadline;
        try client.connectWithDeadline(open_deadline);
    }
    pub fn reconnectLrsWithTimeout(self: *ControlPlane, client: *lrs_client.Client, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reconnectLrsWithDeadline(client, .fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
    fn rebindServer(self: *ControlPlane, selected: usize) Error!void {
        const source = try Source.create(self.allocator, self.bootstrap, self.servers[selected], self.source.node, self.source.request);
        errdefer source.release();
        const target_server = source.server;
        var material = try TlsMaterial.load(self.allocator, self.io, target_server, self.bootstrap);
        errdefer material.deinit();
        var channel = try createChannel(self.allocator, self.io, target_server, self.options.channel, material);
        errdefer channel.deinit();
        var new_sender = channel.sender();
        var sender_owned = true;
        defer if (sender_owned) new_sender.deinit();
        try self.client.rebindWithSource(new_sender, source.request, source);
        sender_owned = false;
        self.channel.deinit();
        self.material.deinit();
        self.source.release();
        self.source = source;
        if (self.servers_owned) self.servers[0] = source.server;
        self.channel = channel;
        self.material = material;
        self.server_index = selected;
        self.last_reload_ns = std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds;
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
        while (attempts < self.servers.len) : (attempts += 1) {
            if (!usable(self.servers[self.server_index])) {
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
    /// The current server's TLS file refresh period. Returns null when the
    /// server has no file-based TLS material or the parsed interval is zero.
    pub fn refreshInterval(self: *const ControlPlane) ?std.Io.Duration {
        const tls = (resolveTls(self.server().tlsConfig(), self.bootstrap) catch return null) orelse return null;
        if (tls.ca_certificate_file.len == 0 and tls.certificate_file.len == 0) return null;
        if (tls.refresh_interval.nanoseconds <= 0) return null;
        return tls.refresh_interval;
    }
    /// Deadline for the next scheduled TLS file reload, or null when refresh
    /// is disabled.
    pub fn nextRefreshDeadline(self: *const ControlPlane) ?std.Io.Clock.Timestamp {
        const interval = self.refreshInterval() orelse return null;
        const last = self.last_reload_ns orelse return null;
        return .{ .clock = .awake, .raw = .{ .nanoseconds = last + interval.nanoseconds } };
    }
    /// Reload the current server's TLS files when the bootstrap
    /// `refresh_interval` has elapsed. The reload recreates the channel and
    /// reconnects the delta client, so callers should invoke this from the
    /// task that owns discovery. Returns false when refresh is disabled or not
    /// yet due.
    pub fn reloadIfDueWithDeadline(self: *ControlPlane, deadline: std.Io.Clock.Timestamp) Error!bool {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const interval = self.refreshInterval() orelse return false;
        const last = self.last_reload_ns orelse return false;
        const now = std.Io.Clock.Timestamp.now(self.io, .awake);
        if (now.raw.nanoseconds < last + interval.nanoseconds) return false;
        try self.reloadServerWithDeadline(deadline);
        return true;
    }
    pub fn reloadIfDueWithTimeout(self: *ControlPlane, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reloadIfDueWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }
};
