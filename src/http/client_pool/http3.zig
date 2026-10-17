//! Optional HTTP/3 backend owned by the unified HTTP pool.

const std = @import("std");
const alt_svc_cache = @import("../alt_svc_cache.zig");
const connection_budget = @import("../../internal/connection_budget.zig");
const http_method = @import("../../internal/http_method.zig");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../../http3/runtime.zig");
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
    alt_svc: alt_svc_cache.Config = .{},
    fallback: FallbackPolicy = .idempotent_methods,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    connector: runtime.HandshakeClientPoolDefaultConnector,
    pool: runtime.HandshakeClientPool,
    dispatcher: runtime.HandshakeClientPoolSharedDispatcher,
    driver: DriverState,
    shared_pool: ?runtime.SharedHandshakeClientPool,
    shared_dispatcher: ?runtime.SharedHandshakeClientPoolRequestDispatcher,
    shared_driver: ?DriverState,
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
        const self = try allocator.create(State);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.io = io;
        self.options = options;
        self.settings_mutex = .init;
        self.closed = false;
        self.shared_pool = null;
        self.shared_dispatcher = null;
        self.shared_driver = null;
        self.connector = .{ .options = options.handshake };
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
        if (options.shared_endpoint) {
            self.shared_pool = try .init(allocator, io, .{
                .local_address = options.local_address,
                .limits = options.limits,
                .client = options.handshake,
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
