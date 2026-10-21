//! Optional HTTP/3 backend owned by the unified HTTP pool.

const std = @import("std");
const alt_svc_cache = @import("../alt_svc_cache.zig");
const connection_budget = @import("../../internal/connection_budget.zig");
const http_method = @import("../../internal/http_method.zig");
const http3 = @import("../../http3/mod.zig");
const http3_socks5 = @import("../../http3/socks5_runtime.zig");
const proxy_socks5 = @import("../../proxy/socks5.zig");
const quic = @import("../../quic/mod.zig");
const runtime = @import("../../http3/runtime.zig");
const client_types = @import("../client/types.zig");
const remembered_settings = @import("http3_settings.zig");

pub const FallbackPolicy = enum {
    /// Surface an HTTP/3 failure without replaying over TCP.
    never,
    /// Replay only methods classified idempotent by shared HTTP semantics.
    idempotent_methods,
};

pub const RememberedSettingsStats = remembered_settings.Stats;

pub const EarlyDataOptions = struct {
    preparation: runtime.PreparedEarlyRequestOptions = .{},
};

pub const RequestResult = struct {
    response: runtime.OwnedHandshakeResponse,
    early_data: ?struct {
        disposition: runtime.EarlyRequestDisposition,
        retry_reason: runtime.EarlyDataRetryReason,
    } = null,
};

pub const Options = struct {
    local_address: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) },
    /// Optional opposite-family UDP bind shared by QUIC Happy Eyeballs and
    /// preferred-address migration when `shared_endpoint` is enabled.
    migration_local_address: ?std.Io.net.IpAddress = null,
    limits: runtime.Limits = .{},
    handshake: runtime.HandshakeClientOptions,
    idle: http3.origin_pool.Config = .{},
    max_connections: usize = 32,
    /// Maximum origins retaining peer H3 SETTINGS for a future 0-RTT offer.
    /// Zero disables SETTINGS memory and therefore disables safe early use.
    max_remembered_settings: usize = 32,
    /// Enable safe-method 0-RTT on new H3 connections when both a ticket and
    /// remembered peer SETTINGS exist. Idle connection reuse remains 1-RTT.
    early_data: ?EarlyDataOptions = null,
    /// Bounded multi-producer queue with one owner per active H3 route.
    shared_requests: runtime.HandshakeClientPoolSharedOptions = .{
        .max_connection_drivers = 4,
    },
    /// Use one UDP endpoint for ordinary and 0-RTT requests. The endpoint's
    /// sole dispatcher owner handles handshake promotion and request replay.
    shared_endpoint: bool = true,
    /// Optional resolver for shared-endpoint acquisitions. Resolution runs as
    /// a cancelable pending phase and inherits the request/connect deadline.
    address_resolver: ?runtime.SharedHandshakeClientPoolAddressResolver = null,
    /// Route HTTP/3 UDP through one SOCKS5 proxy. Domain targets remain
    /// proxy-resolved. Shared mode lazily owns one association and dispatcher;
    /// exclusive mode retains one association per QUIC connection.
    socks5_proxy: ?client_types.Socks5Proxy = null,
    /// Maximum proxy-resolved domain mappings retained by one shared SOCKS5
    /// endpoint. Zero is invalid when both options are enabled.
    max_socks5_shared_routes: usize = 1024,
    alt_svc: alt_svc_cache.Config = .{},
    fallback: FallbackPolicy = .idempotent_methods,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    connector: runtime.HandshakeClientPoolDefaultConnector,
    socks5_transport: ?Socks5Transport,
    shared_connection_budget: *connection_budget.Budget,
    pool: runtime.HandshakeClientPool,
    dispatcher: runtime.HandshakeClientPoolSharedDispatcher,
    driver: DriverState,
    shared_pool: ?runtime.SharedHandshakeClientPool,
    shared_dispatcher: ?runtime.SharedHandshakeClientPoolRequestDispatcher,
    shared_driver: ?DriverState,
    shared_init_mutex: std.Io.Mutex = .init,
    cache: alt_svc_cache.Cache,
    settings_mutex: std.Io.Mutex = .init,
    settings: remembered_settings.Cache,
    closed: bool = false,

    const DriverState = struct {
        future: std.Io.Future(void) = undefined,
    };

    const Driver = struct {
        fn run(self: *State) void {
            self.dispatcher.run() catch {
                self.dispatcher.close();
            };
        }
    };

    const SharedDriver = struct {
        fn run(self: *State) void {
            const dispatcher = if (self.shared_dispatcher) |*value|
                value
            else
                return;
            dispatcher.run() catch {
                dispatcher.close();
            };
        }
    };

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        shared_connection_budget: *connection_budget.Budget,
    ) !*State {
        if (options.shared_endpoint and options.socks5_proxy != null and
            (options.max_socks5_shared_routes == 0 or
                options.max_socks5_shared_routes > 65_535))
        {
            return error.InvalidProxyRouteCapacity;
        }
        const self = try allocator.create(State);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.io = io;
        self.options = options;
        self.settings_mutex = .init;
        self.shared_init_mutex = .init;
        self.closed = false;
        self.shared_connection_budget = shared_connection_budget;
        self.shared_pool = null;
        self.shared_dispatcher = null;
        self.shared_driver = null;
        self.socks5_transport = if (options.socks5_proxy) |proxy|
            .{ .proxy = proxy }
        else
            null;
        self.connector = .{
            .options = options.handshake,
            .transport = if (self.socks5_transport) |*transport|
                transport.connector()
            else
                null,
        };
        self.cache = try .init(allocator, io, options.alt_svc);
        errdefer self.cache.deinit();
        self.settings = try .init(
            allocator,
            options.max_remembered_settings,
        );
        errdefer self.settings.deinit();
        self.pool = try .init(allocator, io, .{
            .local_address = options.local_address,
            .limits = options.limits,
            .idle = options.idle,
            .max_connections = options.max_connections,
            .shared_connection_budget = shared_connection_budget,
            .connector = self.connector.connector(),
            .peer_settings_observer = .{
                .context = self,
                .observe = observePeerSettings,
            },
        });
        errdefer self.pool.deinit();
        self.dispatcher = try .init(
            allocator,
            io,
            &self.pool,
            options.shared_requests,
        );
        errdefer self.dispatcher.deinit();
        self.driver = .{};
        if (options.shared_endpoint and options.socks5_proxy == null) {
            self.shared_pool = try .init(allocator, io, .{
                .local_address = options.local_address,
                .migration_local_address = options.migration_local_address,
                .limits = options.limits,
                .client = options.handshake,
                .resolver = options.address_resolver,
                .idle = options.idle,
                .max_connections = options.max_connections,
                .shared_connection_budget = shared_connection_budget,
                .peer_settings_observer = .{
                    .context = self,
                    .observe = observePeerSettings,
                },
            });
            errdefer {
                self.shared_pool.?.deinit();
                self.shared_pool = null;
            }
            self.shared_dispatcher = try .init(
                allocator,
                io,
                &self.shared_pool.?,
                .{
                    .max_queued_requests = options.shared_requests.max_queued_requests,
                    .max_active_connections = options.shared_requests.max_connection_drivers,
                    .max_requests_per_connection = options.shared_requests.max_batch_requests,
                },
            );
            errdefer {
                self.shared_dispatcher.?.deinit();
                self.shared_dispatcher = null;
            }
            self.shared_driver = .{};
        }
        self.driver.future = io.async(Driver.run, .{self});
        if (self.shared_driver) |*driver| {
            driver.future = io.async(SharedDriver.run, .{self});
        }
        return self;
    }

    fn ensureSocks5SharedEndpoint(
        self: *State,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        if (!self.options.shared_endpoint or
            self.options.socks5_proxy == null or
            self.shared_pool != null)
        {
            return;
        }
        if (self.options.max_socks5_shared_routes == 0) {
            return error.InvalidPoolOptions;
        }
        self.shared_init_mutex.lockUncancelable(self.io);
        defer self.shared_init_mutex.unlock(self.io);
        if (self.shared_pool != null) return;
        if (self.closed) return error.PoolClosed;
        const proxy = self.options.socks5_proxy.?;
        var association = if (deadline) |absolute|
            try proxy_socks5.associateUdpHostWithDeadline(
                self.allocator,
                self.io,
                proxy.host,
                proxy.port,
                .{
                    .socks5 = proxy.options,
                    .bind_address = self.options.local_address,
                },
                absolute,
            )
        else
            try proxy_socks5.associateUdpHost(
                self.allocator,
                self.io,
                proxy.host,
                proxy.port,
                .{
                    .socks5 = proxy.options,
                    .bind_address = self.options.local_address,
                },
            );
        var association_owned = true;
        defer if (association_owned) association.deinit();
        const endpoint = try self.allocator.create(quic.runtime.Endpoint);
        endpoint.* = quic.runtime.Endpoint.fromSocks5AssociationForDomains(
            self.allocator,
            &association,
            self.options.max_socks5_shared_routes,
            self.options.limits.quic,
        ) catch |err| {
            self.allocator.destroy(endpoint);
            return err;
        };
        association_owned = false;
        var endpoint_owned = true;
        defer if (endpoint_owned) {
            endpoint.deinit();
            self.allocator.destroy(endpoint);
        };
        var client_options = self.options.handshake;
        client_options.alternate_local_address = null;
        const pool = try runtime.SharedHandshakeClientPool.initWithOwnedEndpoint(
            self.allocator,
            self.io,
            .{
                .local_address = self.options.local_address,
                .limits = self.options.limits,
                .client = client_options,
                .resolver = null,
                .proxy_domain_routing = true,
                .idle = self.options.idle,
                .max_connections = self.options.max_connections,
                .shared_connection_budget = self.shared_connection_budget,
                .peer_settings_observer = .{
                    .context = self,
                    .observe = observePeerSettings,
                },
            },
            endpoint,
        );
        endpoint_owned = false;
        self.shared_pool = pool;
        errdefer {
            self.shared_pool.?.deinit();
            self.shared_pool = null;
        }
        self.shared_dispatcher = try .init(
            self.allocator,
            self.io,
            &self.shared_pool.?,
            .{
                .max_queued_requests = self.options.shared_requests.max_queued_requests,
                .max_active_connections = self.options.shared_requests.max_connection_drivers,
                .max_requests_per_connection = self.options.shared_requests.max_batch_requests,
            },
        );
        errdefer {
            self.shared_dispatcher.?.deinit();
            self.shared_dispatcher = null;
        }
        self.shared_driver = .{};
        self.shared_driver.?.future = self.io.async(SharedDriver.run, .{self});
    }

    pub fn deinit(self: *State) void {
        const allocator = self.allocator;
        self.close();
        if (self.shared_dispatcher) |*dispatcher| dispatcher.deinit();
        if (self.shared_pool) |*pool| pool.deinit();
        self.dispatcher.deinit();
        self.pool.deinit();
        self.cache.deinit();
        self.settings.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn close(self: *State) void {
        self.shared_init_mutex.lockUncancelable(self.io);
        defer self.shared_init_mutex.unlock(self.io);
        if (self.shared_dispatcher) |*dispatcher| dispatcher.close();
        self.dispatcher.close();
        if (self.shared_pool) |*pool| pool.close();
        self.pool.close();
        if (self.shared_driver) |*driver| driver.future.await(self.io);
        self.driver.future.await(self.io);
        self.cache.clear();
        self.settings_mutex.lockUncancelable(self.io);
        self.closed = true;
        self.settings.clear();
        self.settings_mutex.unlock(self.io);
    }

    pub fn evictOldestIdle(self: *State) bool {
        if (self.pool.evictOldestIdle()) return true;
        if (self.shared_pool) |*pool| return pool.evictOldestIdle();
        return false;
    }

    pub fn connectionCount(self: *State) usize {
        return self.pool.connectionCount() +
            if (self.shared_pool) |*pool| pool.connectionCount() else 0;
    }

    pub fn idleCount(self: *State) usize {
        return self.pool.idleCount() +
            if (self.shared_pool) |*pool| pool.idleCount() else 0;
    }

    pub fn rememberedPeerSettings(
        self: *State,
        origin: http3.Origin,
    ) ?http3.Settings {
        self.settings_mutex.lockUncancelable(self.io);
        defer self.settings_mutex.unlock(self.io);
        if (self.closed) return null;
        return self.settings.lookup(origin);
    }

    pub fn rememberedSettingsStats(
        self: *State,
    ) remembered_settings.Stats {
        self.settings_mutex.lockUncancelable(self.io);
        defer self.settings_mutex.unlock(self.io);
        return self.settings.stats();
    }

    fn observePeerSettings(
        context: *anyopaque,
        origin: http3.Origin,
        settings: http3.Settings,
    ) void {
        const self: *State = @ptrCast(@alignCast(context));
        self.settings_mutex.lockUncancelable(self.io);
        defer self.settings_mutex.unlock(self.io);
        if (self.closed) return;
        self.settings.remember(origin, settings) catch {};
    }

    pub fn request(
        self: *State,
        origin: http3.Origin,
        uri_text: []const u8,
        alternative: *const alt_svc_cache.Alternative,
        options: runtime.UriRequestOptions,
        allow_early_data: bool,
        deadline: ?std.Io.Clock.Timestamp,
        crossed_origin: bool,
        forward_client_identity: bool,
        reclaimer: connection_budget.Reclaimer,
    ) !RequestResult {
        try self.ensureSocks5SharedEndpoint(deadline);
        const redirect: ?runtime.HandshakeClientPoolRedirectConnectContext =
            if (crossed_origin) .{
                .cross_origin = true,
                .forward_client_identity = forward_client_identity,
            } else null;
        const early_options = self.options.early_data;
        const remembered = if (!allow_early_data or crossed_origin or
            early_options == null or
            (early_options.?.preparation.replay_policy == .safe_methods_only and
                !http_method.isSafe(options.method)))
            null
        else
            self.rememberedPeerSettings(origin);
        if (remembered) |settings| {
            if (self.shared_dispatcher) |*dispatcher| {
                const sender = dispatcher.sender();
                var result = try sender.requestAltSvcEarlyReclaiming(
                    uri_text,
                    alternative.target(),
                    options,
                    early_options.?.preparation,
                    self.options.handshake.session.local_settings,
                    settings,
                    deadline,
                    reclaimer,
                );
                const owned: runtime.OwnedHandshakeResponse = .{
                    .stream_bytes = result.response.stream_bytes,
                    .response = result.response.response,
                };
                result.response = undefined;
                return .{
                    .response = owned,
                    .early_data = if (result.early_data) |metadata| .{
                        .disposition = metadata.disposition,
                        .retry_reason = metadata.retry_reason,
                    } else null,
                };
            }
            const result = try self.pool.requestUriAltSvcEarlyReclaiming(
                uri_text,
                alternative.target(),
                options,
                early_options.?.preparation,
                self.options.handshake.session.local_settings,
                settings,
                deadline,
                reclaimer,
            );
            return .{
                .response = result.response,
                .early_data = if (result.early_data) |metadata| .{
                    .disposition = metadata.disposition,
                    .retry_reason = metadata.retry_reason,
                } else null,
            };
        }
        if (!crossed_origin) {
            if (self.shared_dispatcher) |*dispatcher| {
                const sender = dispatcher.sender();
                var may_retry = http_method.isIdempotent(options.method);
                while (true) {
                    var response = sender.requestAltSvcReclaiming(
                        uri_text,
                        alternative.target(),
                        options,
                        deadline,
                        reclaimer,
                    ) catch |err| {
                        if (may_retry and retryableSharedRequestError(err)) {
                            may_retry = false;
                            continue;
                        }
                        return err;
                    };
                    const owned: runtime.OwnedHandshakeResponse = .{
                        .stream_bytes = response.stream_bytes,
                        .response = response.response,
                    };
                    response = undefined;
                    return .{ .response = owned };
                }
            }
        }
        if (!crossed_origin) {
            const sender = self.dispatcher.sender();
            var may_retry = http_method.isIdempotent(options.method);
            while (true) {
                const response = sender.requestAltSvcReclaiming(
                    uri_text,
                    alternative.target(),
                    options,
                    deadline,
                    reclaimer,
                ) catch |err| {
                    if (may_retry and retryableSharedRequestError(err)) {
                        may_retry = false;
                        continue;
                    }
                    return err;
                };
                return .{ .response = response };
            }
        }
        return .{ .response = try self.pool.requestUriAltSvcReclaiming(
            uri_text,
            alternative.target(),
            options,
            redirect,
            deadline,
            reclaimer,
        ) };
    }
};

const Socks5Transport = struct {
    proxy: client_types.Socks5Proxy,

    fn connector(self: *Socks5Transport) runtime.HandshakeClientPoolTransportConnector {
        return .{ .context = self, .connect = connect };
    }

    fn connect(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        target_host: []const u8,
        target_port: u16,
        limits: runtime.Limits,
        options: runtime.HandshakeClientOptions,
    ) runtime.Error!runtime.HandshakeClient {
        const self: *Socks5Transport = @ptrCast(@alignCast(context));
        return http3_socks5.connectHost(
            allocator,
            io,
            local_address,
            .{
                .host = self.proxy.host,
                .port = self.proxy.port,
                .options = self.proxy.options,
            },
            target_host,
            target_port,
            limits,
            options,
        );
    }
};

fn retryableSharedRequestError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.SocketUnconnected,
        error.GoAwayReceived,
        error.RequestRejected,
        => true,
        else => false,
    };
}
