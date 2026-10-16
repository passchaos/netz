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
    alt_svc: alt_svc_cache.Config = .{},
    fallback: FallbackPolicy = .idempotent_methods,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    options: Options,
    connector: runtime.HandshakeClientPoolDefaultConnector,
    pool: runtime.HandshakeClientPool,
    cache: alt_svc_cache.Cache,
    settings: remembered_settings.Cache,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        shared_connection_budget: *connection_budget.Budget,
    ) !*State {
        const self = try allocator.create(State);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.options = options;
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
        return self;
    }

    pub fn deinit(self: *State) void {
        const allocator = self.allocator;
        self.pool.deinit();
        self.cache.deinit();
        self.settings.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn close(self: *State) void {
        self.pool.close();
        self.cache.clear();
        self.settings.clear();
    }

    pub fn evictOldestIdle(self: *State) bool {
        return self.pool.evictOldestIdle();
    }

    pub fn rememberedPeerSettings(
        self: *State,
        origin: http3.Origin,
    ) ?http3.Settings {
        return self.settings.lookup(origin);
    }

    pub fn rememberedSettingsStats(
        self: *const State,
    ) remembered_settings.Stats {
        return self.settings.stats();
    }

    fn observePeerSettings(
        context: *anyopaque,
        origin: http3.Origin,
        settings: http3.Settings,
    ) void {
        const self: *State = @ptrCast(@alignCast(context));
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
