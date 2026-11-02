//! Transactional publication of service config and canonical resolver endpoints.
const std = @import("std");
const channel = @import("../../channel.zig");
const service_config = @import("../../service_config.zig");
const State = @import("state.zig").State;
const Generation = @import("config_generation.zig").Generation;
const Prepared = @import("update/prepare.zig").Prepared;
const Options = @import("options.zig").Options;
const orca_config = @import("orca/config.zig");

pub const TargetLifetime = @import("target_lifetime.zig").Lifetime;

pub const Update = struct {
    /// Null preserves the complete canonical inventory. An empty resolved set
    /// removes every endpoint while already admitted RPCs finish.
    target: ?channel.Target = null,
    /// Retained on success by canonical inventory and source/worker owners.
    /// Requires target != null; callers may release their reference on return.
    target_lifetime: ?TargetLifetime = null,
    /// Dynamic RPC admission categories; an empty replacement disables drops.
    drop_categories: union(enum) { keep, replace: []const channel.drop_policy.Category } = .keep,
    service_config: union(enum) { keep, replace: ?[]const u8 } = .keep,
};

pub fn apply(state: *State, update: Update, deadline: ?std.Io.Clock.Timestamp) State.Failure!u64 {
    if (update.target == null and update.target_lifetime != null) return error.InvalidSharedOptions;
    state.retain();
    defer state.release();
    if (deadline != null) try @import("../../../internal/timed_mutex.zig").lock(&state.update_mutex, state.io, deadline) else try state.update_mutex.lock(state.io);
    defer state.update_mutex.unlock(state.io);
    var prepared = try snapshot(state, update, deadline);
    defer prepared.deinit();
    try state.lockBefore(deadline);
    defer state.unlock();
    if (state.closed) return error.SharedChannelClosed;
    try @import("update/publish.zig").publish(state, &prepared, deadline);
    return state.config_revision;
}

fn snapshot(state: *State, update: Update, deadline: ?std.Io.Clock.Timestamp) State.Failure!Prepared {
    try state.lockBefore(deadline);
    var locked = true;
    defer if (locked) state.unlock();
    if (state.closed) return error.SharedChannelClosed;
    var options: Options = state.options;
    const health_override = if (state.health_explicit and state.health_service != null) try state.allocator.dupe(u8, state.health_service.?) else null;
    defer if (health_override) |name| state.allocator.free(name);
    options.health_service = health_override;
    options.health_metadata.service = "";
    var orca_override = if (state.orca_explicit and state.orca_oob != null) try state.orca_oob.?.clone() else null;
    errdefer if (orca_override) |*value| value.deinit();
    var drop = switch (update.drop_categories) {
        .keep => try state.drop.clone(state.allocator),
        .replace => |categories| try channel.drop_policy.Policy.init(state.allocator, categories),
    };
    errdefer drop.deinit();
    const old_config = state.retainConfig();
    defer if (old_config) |config| config.release();
    const resolver_policy = if (update.target) |target| if (target == .resolved) target.resolved.policy else channel.SelectionPolicy.pick_first else state.resolver_policy;
    var endpoints: []channel.Endpoint = if (update.target) |target| switch (target) {
        .resolved => |resolved| try state.allocator.dupe(channel.Endpoint, resolved.endpoints),
        else => blk: {
            const values = try state.allocator.alloc(channel.Endpoint, 1);
            values[0] = switch (target) {
                .cleartext_ip => |value| .{ .cleartext_ip = value },
                .cleartext_host => |value| .{ .cleartext_host = value },
                .tls_host => |value| .{ .tls_host = value },
                .tls_address => |value| .{ .tls_address = value },
                .custom => |value| .{ .custom = value },
                .resolved => unreachable,
            };
            break :blk values;
        },
    } else try state.allocator.dupe(channel.Endpoint, state.canonical_endpoints);
    errdefer state.allocator.free(endpoints);
    var lifetime = if (update.target != null) update.target_lifetime else state.target_lifetime;
    if (lifetime) |owner| lifetime = owner.retain();
    errdefer if (lifetime) |owner| owner.release();
    state.unlock();
    locked = false;
    var config: ?*Generation = switch (update.service_config) {
        .keep => if (old_config) |value| value.retain() else null,
        .replace => |json| if (json) |text| blk: {
            if (old_config) |old| if (old.json) |previous| {
                if (std.mem.eql(u8, previous, text)) break :blk old.retain();
            };
            var parsed = try service_config.ServiceConfig.parseWithOptions(state.allocator, text, .{ .enable_per_attempt_recv_timeout = options.enable_per_attempt_recv_timeout });
            errdefer parsed.deinit();
            break :blk try Generation.createWithJson(state.allocator, parsed, text);
        } else null,
    };
    const owned_config = config;
    config = null;
    const owned_endpoints = endpoints;
    endpoints = &.{};
    const owned_orca = orca_override;
    orca_override = null;
    const owned_lifetime = lifetime;
    lifetime = null;
    const owned_drop = drop;
    drop = .{};
    return Prepared.create(state.allocator, state.io, owned_endpoints, resolver_policy, options, owned_config, owned_orca, owned_lifetime, owned_drop);
}
