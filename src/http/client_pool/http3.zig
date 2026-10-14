//! Optional HTTP/3 backend owned by the unified HTTP pool.

const std = @import("std");
const alt_svc_cache = @import("../alt_svc_cache.zig");
const connection_budget = @import("../../internal/connection_budget.zig");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../../http3/runtime.zig");

pub const FallbackPolicy = enum {
    /// Surface an HTTP/3 failure without replaying over TCP.
    never,
    /// Replay only methods classified idempotent by shared HTTP semantics.
    idempotent_methods,
};

pub const Options = struct {
    local_address: std.Io.net.IpAddress = .{ .ip4 = .unspecified(0) },
    limits: runtime.Limits = .{},
    handshake: runtime.HandshakeClientOptions,
    idle: http3.origin_pool.Config = .{},
    max_connections: usize = 32,
    alt_svc: alt_svc_cache.Config = .{},
    fallback: FallbackPolicy = .idempotent_methods,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    options: Options,
    connector: runtime.HandshakeClientPoolDefaultConnector,
    pool: runtime.HandshakeClientPool,
    cache: alt_svc_cache.Cache,

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
        self.pool = try .init(allocator, io, .{
            .local_address = options.local_address,
            .limits = options.limits,
            .idle = options.idle,
            .max_connections = options.max_connections,
            .shared_connection_budget = shared_connection_budget,
            .connector = self.connector.connector(),
        });
        return self;
    }

    pub fn deinit(self: *State) void {
        const allocator = self.allocator;
        self.pool.deinit();
        self.cache.deinit();
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn close(self: *State) void {
        self.pool.close();
        self.cache.clear();
    }

    pub fn request(
        self: *State,
        uri_text: []const u8,
        alternative: *const alt_svc_cache.Alternative,
        options: runtime.UriRequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
        crossed_origin: bool,
        forward_client_identity: bool,
    ) !runtime.OwnedHandshakeResponse {
        if (crossed_origin) {
            const redirect: runtime.HandshakeClientPoolRedirectConnectContext = .{
                .cross_origin = true,
                .forward_client_identity = forward_client_identity,
            };
            return if (deadline) |absolute|
                self.pool.requestUriAltSvcForRedirectWithDeadline(
                    uri_text,
                    alternative.target(),
                    options,
                    redirect,
                    absolute,
                )
            else
                self.pool.requestUriAltSvcForRedirect(
                    uri_text,
                    alternative.target(),
                    options,
                    redirect,
                );
        }
        return if (deadline) |absolute|
            self.pool.requestUriAltSvcWithDeadline(
                uri_text,
                alternative.target(),
                options,
                absolute,
            )
        else
            self.pool.requestUriAltSvc(
                uri_text,
                alternative.target(),
                options,
            );
    }
};
