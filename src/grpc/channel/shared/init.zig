//! Validate and own shared configuration before admitting background tasks.
const std = @import("std");
const channel = @import("../../channel.zig");
const health = @import("../../health.zig");
const service_config = @import("../../service_config.zig");
const connectivity = @import("../connectivity.zig");
const State = @import("state.zig").State;
const Error = @import("state.zig").Error;
const Options = @import("options.zig").Options;

pub fn create(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: Options) Error!*State {
    if (options.max_queued_calls == 0 or options.max_active_calls_per_endpoint == 0 or options.max_write_bytes_per_turn == 0 or options.max_buffered_stream_bytes == 0 or options.operation_timeout.nanoseconds <= 0) return error.InvalidSharedOptions;
    try options.channel.backoff.validate();
    if (options.channel.resolver_min_refresh_interval.nanoseconds < 0) return error.InvalidChannelOptions;
    const count = if (target == .resolved) target.resolved.endpoints.len else 1;
    if (count == 0) return error.InvalidSharedOptions;
    var config: ?service_config.ServiceConfig = if (options.service_config_json) |json| try service_config.ServiceConfig.parse(allocator, json) else null;
    var transferred = false;
    errdefer if (!transferred) if (config) |*value| value.deinit();
    const name: ?[]const u8 = if (options.disable_health_check) null else options.health_service orelse (if (options.health_metadata.service.len != 0) options.health_metadata.service else if (config) |*value| value.healthCheckServiceName() else null);
    if (name) |service| {
        const encoded = try health.encodeRequestAlloc(allocator, .{ .service = service });
        allocator.free(encoded);
    }
    const owned_name = if (name) |service| try allocator.dupe(u8, service) else null;
    errdefer if (!transferred) if (owned_name) |value| allocator.free(value);
    const tracker = try connectivity.Tracker.create(allocator, io);
    errdefer if (!transferred) tracker.release();
    const state = try allocator.create(State);
    const balancing = if (config) |*value| value.loadBalancingConfig() else service_config.LoadBalancingConfig{};
    var retained = options;
    retained.service_config_json = null;
    retained.health_service = owned_name;
    retained.health_metadata.service = owned_name orelse "";
    state.* = .{
        .allocator = allocator,
        .io = io,
        .options = retained,
        .config = config,
        .health_service = owned_name,
        .tracker = tracker,
        .policy = options.channel.selection_policy orelse (if (balancing.configured) switch (balancing.policy) {
            .pick_first => channel.SelectionPolicy.pick_first,
            .round_robin => channel.SelectionPolicy.round_robin,
        } else if (target == .resolved) target.resolved.policy else .pick_first),
        .shuffle_addresses = options.channel.shuffle_address_list orelse (balancing.configured and balancing.shuffle_address_list),
    };
    transferred = true;
    errdefer {
        state.close();
        state.group.cancel(io);
        state.stopResolution();
        state.release();
    }
    const sources = try allocator.alloc(State.Source, count);
    var initialized: usize = 0;
    var sources_transferred = false;
    errdefer if (!sources_transferred) {
        for (sources[0..initialized]) |*source| source.deinit(allocator);
        allocator.free(sources);
    };
    var has_host = false;
    for (sources, 0..) |*source, index| {
        const endpoint: channel.Endpoint = switch (target) {
            .resolved => |set| set.endpoints[index],
            .cleartext_ip => |v| .{ .cleartext_ip = v },
            .cleartext_host => |v| .{ .cleartext_host = v },
            .tls_host => |v| .{ .tls_host = v },
            .tls_address => |v| .{ .tls_address = v },
            .custom => |v| .{ .custom = v },
        };
        source.* = try State.Source.init(allocator, io, endpoint, options.channel);
        initialized += 1;
        has_host = has_host or source.resolver != null;
    }
    if (options.channel.address_resolver != null and !has_host) return error.InvalidChannelOptions;
    if (state.shuffle_addresses) {
        var remaining = sources.len;
        while (remaining > 1) {
            remaining -= 1;
            var random: usize = undefined;
            io.random(std.mem.asBytes(&random));
            std.mem.swap(State.Source, &sources[remaining], &sources[random % (remaining + 1)]);
        }
    }
    state.sources = sources;
    sources_transferred = true;
    for (sources, 0..) |*source, index| {
        if (source.resolver) |resolver| {
            resolver.notifyPublication(&source.wake);
            try state.group.concurrent(io, State.Resolution.run, .{ state, index });
        } else {
            source.current = try allocator.alloc(*State.Worker, 1);
            state.lock();
            const worker = State.Membership.createLocked(state, index, null) catch |err| {
                state.unlock();
                return err;
            };
            worker.eligible = true;
            source.current[0] = worker;
            state.unlock();
        }
    }
    return state;
}
