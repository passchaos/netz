//! Managed federated ADS sessions feeding one transactional data-plane publisher.
const std = @import("std");
const bootstrap = @import("../bootstrap.zig");
const target = @import("../client_target.zig");
const shared = @import("../../channel/shared.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const lds = @import("../lds.zig");
const rds = @import("../rds.zig");
const controller_mod = @import("controller.zig");
const registry_mod = @import("managed/registry.zig");
const names = @import("managed/names.zig");
const features = @import("managed/features.zig");
pub const Mode = registry_mod.Mode;
pub const Error = controller_mod.Error || target.Error || std.Io.ConcurrentError || error{ WrongDiscoverySession, MissingDiscoverySource };
pub const Options = struct { controller: controller_mod.Options, discovery: registry_mod.Options = .{} };
pub const TargetOptions = struct {
    discovery: registry_mod.Options = .{},
    resolver: target.Options = .{},
    configure: ?*const fn (*controller_mod.Options) void = null,
};

pub fn controllerOptions(resolved: *const target.Resolved) controller_mod.Options {
    return .{ .listener_name = resolved.listener_name, .authority = resolved.discovery_authority, .target = .{ .authority = resolved.data_authority } };
}

pub fn Managed(comptime mode: Mode) type {
    return struct {
        const Self = @This();
        pub const Registry = registry_mod.Registry(mode);
        pub const Session = Registry.Session;
        pub const Update = if (mode == .sotw) ads.Update else delta.Update;
        pub const Event = struct {
            session: *Session,
            result: Session.ClientError!Session.Event,
            pub fn authority(self: *const Event) ?[]const u8 {
                return if (self.session.authority.len == 0) null else self.session.authority;
            }
            pub fn deinit(self: *Event) void {
                if (self.result) |event_value| {
                    var value = event_value;
                    value.deinit();
                } else |_| {}
                self.session.release();
            }
        };
        const Outcome = struct { session: *Session, result: Session.ClientError!Session.Event };
        const Wake = union(enum) { response: Outcome };
        allocator: std.mem.Allocator,
        io: std.Io,
        data: shared.SharedChannel,
        controller: *controller_mod.Controller,
        registry: Registry,
        started: bool = false,

        pub fn create(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, data: shared.SharedChannel, options: Options) Error!*Self {
            if (options.discovery.max_sessions == 0) return error.InvalidXdsOptions;
            if (options.discovery.control_plane.pinned_server != null) return error.InvalidControlPlaneOptions;
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const authorities = try gpa.alloc([]const u8, configuration.authorities.len);
            defer gpa.free(authorities);
            for (configuration.authorities, authorities) |authority, *key| key.* = authority.name;
            var selected = options.controller;
            if (selected.authority) |authority| if (configuration.authority(authority) == null) return error.InvalidControlPlaneOptions;
            selected.additional_authorities = authorities;
            const controller = try controller_mod.Controller.create(gpa, selected);
            errdefer controller.deinit();
            data.state.retain();
            self.* = .{ .allocator = gpa, .io = io, .data = data, .controller = controller, .registry = .init(gpa, io, configuration, options.discovery) };
            controller.setDiscoveryRouter(self.registry.router());
            controller.retain_valid_routes = true;
            return self;
        }

        pub fn createForTarget(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, data: shared.SharedChannel, uri: []const u8, options: TargetOptions) Error!*Self {
            const resolved = try target.resolveWithOptions(gpa, configuration, uri, options.resolver);
            defer resolved.deinit();
            var configured = controllerOptions(resolved);
            if (options.configure) |configure| configure(&configured);
            return create(gpa, io, configuration, data, .{ .controller = configured, .discovery = options.discovery });
        }

        pub fn deinit(self: *Self) void {
            self.controller.deinit();
            self.registry.deinit();
            self.data.state.release();
            self.allocator.destroy(self);
        }

        pub fn startWithDeadline(self: *Self, deadline: std.Io.Clock.Timestamp) Error!u64 {
            const session = try self.registry.forName(self.controller.options.listener_name);
            const revision = if (mode == .sotw)
                try self.controller.startWithDeadline(&session.client, self.data, deadline)
            else
                try self.controller.startDeltaWithDeadline(&session.client, self.data, deadline);
            self.started = true;
            return revision;
        }

        fn read(session: *Session, deadline: std.Io.Clock.Timestamp) Outcome {
            if (session.client.stream == null) session.client.connectWithDeadline(deadline) catch |err| {
                session.client.disconnect();
                return .{ .session = session, .result = err };
            };
            return .{ .session = session, .result = session.client.nextWithDeadline(deadline) };
        }

        pub fn nextWithDeadline(self: *Self, deadline: std.Io.Clock.Timestamp) Error!Event {
            if (!self.started) return error.XdsNotStarted;
            for (self.registry.sessions.items) |session| if (session.pending) |result| {
                session.pending = null;
                if (!self.registry.active(session)) {
                    if (result) |value| {
                        var discarded = value;
                        discarded.deinit();
                    } else |_| {}
                    continue;
                }
                return .{ .session = session.retain(), .result = result };
            };
            const storage = try self.allocator.alloc(Wake, self.registry.sessions.items.len);
            defer self.allocator.free(storage);
            var select: std.Io.Select(Wake) = .init(self.io, storage);
            defer while (select.cancel()) |wake| {
                const outcome = wake.response;
                if (outcome.result) |value| outcome.session.pending = value else |err| {
                    if (err != error.Canceled) outcome.session.pending = err;
                }
            };
            var active: usize = 0;
            for (self.registry.sessions.items) |session| {
                if (!self.registry.active(session)) continue;
                try select.concurrent(.response, read, .{ session, deadline });
                active += 1;
            }
            if (active == 0) return error.XdsNotStarted;
            const outcome = (try select.await()).response;
            return .{ .session = outcome.session.retain(), .result = outcome.result };
        }
        pub fn nextWithTimeout(self: *Self, timeout: std.Io.Duration) Error!Event {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.nextWithDeadline(.fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
        }

        fn owns(self: *Self, session: *Session) bool {
            for (self.registry.sessions.items) |candidate| if (candidate == session) return true;
            return false;
        }

        fn relevant(self: *Self, session: *Session, url: []const u8) bool {
            if (std.mem.eql(u8, url, lds.type_url)) return names.belongs(self.controller.options.listener_name, session.authority);
            if (std.mem.eql(u8, url, rds.type_url)) {
                const listener = self.controller.listener.?.listener orelse return false;
                return listener.value.hcm.route_source == .rds and names.belongs(listener.value.hcm.route_source.rds, session.authority);
            }
            return true;
        }

        fn validateIgnored(self: *Self, update: Update) Error!void {
            const url = update.response.value.type_url;
            for (update.response.value.resources) |resource| {
                const bytes = if (mode == .sotw) resource.value else if (resource.resource) |value| value.value else continue;
                if (std.mem.eql(u8, url, lds.type_url)) {
                    var decoded = try lds.decode(self.allocator, bytes, self.controller.options.limits.lds);
                    decoded.deinit();
                } else {
                    var decoded = try rds.decode(self.allocator, bytes, self.controller.options.limits.lds.rds);
                    decoded.deinit();
                }
            }
        }

        pub fn applyWithDeadline(self: *Self, event: *const Event, deadline: std.Io.Clock.Timestamp) Error!u64 {
            if (!self.owns(event.session)) return error.WrongDiscoverySession;
            const received = try event.result;
            if (received != .update) return error.InvalidDiscoveryMessage;
            const update = received.update;
            const source = update.source orelse return error.MissingDiscoverySource;
            const saved = features.Saved.capture(self.controller);
            const old_scope = self.controller.response_authority;
            self.controller.response_authority = event.session.authority;
            self.controller.applyServerFeatures(source.server);
            defer {
                saved.restore(self.controller);
                self.controller.response_authority = old_scope;
            }
            const revision = if (!self.relevant(event.session, update.response.value.type_url)) blk: {
                try event.session.client.validateUpdate(update);
                try self.validateIgnored(update);
                try event.session.client.acceptAppliedUpdate(update);
                break :blk try @import("../publication.zig").unchangedRevisionWithDeadline(self.data, deadline);
            } else if (mode == .sotw)
                try self.controller.applyWithDeadline(&event.session.client, update, self.data, deadline)
            else
                try self.controller.applyDeltaWithDeadline(&event.session.client, update, self.data, deadline);
            try self.registry.flush(deadline);
            return revision;
        }

        pub fn rejectWithDeadline(self: *Self, event: *const Event, message: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
            if (!self.owns(event.session)) return error.WrongDiscoverySession;
            const value = try event.result;
            if (value != .update) return error.InvalidDiscoveryMessage;
            try event.session.client.rejectWithDeadline(value.update, .{ .code = .invalid_argument, .message = message }, deadline);
        }

        pub fn synchronizeWithDeadline(self: *Self, deadline: std.Io.Clock.Timestamp) Error!u64 {
            const session = try self.registry.forName(self.controller.options.listener_name);
            const remote = if (self.controller.listener.?.listener) |listener|
                if (listener.value.hcm.route_source == .rds) listener.value.hcm.route_source.rds else null
            else
                null;
            var routes = try @import("discovery.zig").prepare(&session.client, self.controller.discovery_router, rds.type_url, if (remote) |name| &.{name} else &.{}, deadline);
            defer routes.deinit();
            const revision = if (mode == .sotw)
                try self.controller.synchronizeWithDeadline(&session.client, self.data, deadline)
            else
                try self.controller.synchronizeDeltaWithDeadline(&session.client, self.data, deadline);
            routes.commit();
            try self.registry.flush(deadline);
            return revision;
        }

        pub fn reconnectWithDeadline(self: *Self, event: *const Event, deadline: std.Io.Clock.Timestamp, failover: bool) Error!void {
            if (!self.owns(event.session)) return error.WrongDiscoverySession;
            try event.session.reconnect(deadline, failover);
        }

        pub fn nextDeltaExpiry(self: *Self) ?std.Io.Clock.Timestamp {
            return self.controller.nextDeltaExpiry();
        }

        pub fn expireDeltaWithDeadline(self: *Self, deadline: std.Io.Clock.Timestamp) Error!u64 {
            if (mode == .delta) {
                var revision = try @import("../publication.zig").unchangedRevisionWithDeadline(self.data, deadline);
                for (self.registry.sessions.items) |session| {
                    const saved = features.Saved.capture(self.controller);
                    const old_scope = self.controller.response_authority;
                    self.controller.response_authority = session.authority;
                    if (session.client.source) |source| self.controller.applyServerFeatures(source.server);
                    defer {
                        saved.restore(self.controller);
                        self.controller.response_authority = old_scope;
                    }
                    revision = try self.controller.expireDeltaWithDeadline(&session.client, self.data, deadline);
                }
                try self.registry.flush(deadline);
                return revision;
            }
            return error.InvalidDiscoveryMessage;
        }
    };
}

pub const SotW = Managed(.sotw);
pub const Delta = Managed(.delta);
