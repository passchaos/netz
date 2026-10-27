//! Reference-counted send handles and concurrent background endpoint owners.
const std = @import("std");
const channel = @import("../channel.zig");
const call = @import("../call.zig");
const health = @import("../health.zig");
const service_config = @import("../service_config.zig");
const connectivity = @import("connectivity.zig");
const state_module = @import("shared/state.zig");
const State = state_module.State;
pub const Error = state_module.Error;
pub const Options = state_module.Options;

pub const Sender = struct {
    state: *State,
    pub fn clone(self: Sender) Sender {
        self.state.retain();
        return self;
    }
    pub fn deinit(self: *Sender) void {
        self.state.release();
        self.* = undefined;
    }
    pub fn unary(self: Sender, options: call.UnaryCallOptions) Error!call.UnaryResponse {
        return self.unaryResolved(options, null);
    }
    pub fn unaryWithRetry(self: Sender, options: call.UnaryCallOptions, policy: call.RetryPolicy) Error!call.UnaryResponse {
        return self.unaryResolved(options, policy);
    }
    fn unaryResolved(self: Sender, options: call.UnaryCallOptions, policy: ?call.RetryPolicy) Error!call.UnaryResponse {
        const entered = std.Io.Clock.awake.now(self.state.io);
        if (options.message.len > options.requestMessageLimit()) return error.GrpcMessageTooLarge;
        _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
        try call.validateCustomMetadata(options.metadata);
        try call.validateCustomBinaryMetadata(options.binary_metadata);
        return self.state.unary(options, policy, entered);
    }
};

pub const SharedChannel = struct {
    state: *State,
    pub fn init(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: Options) Error!SharedChannel {
        if (options.max_queued_calls == 0 or options.max_active_calls_per_endpoint == 0 or options.max_write_bytes_per_turn == 0 or options.operation_timeout.nanoseconds <= 0) return error.InvalidSharedOptions;
        var config: ?service_config.ServiceConfig = if (options.service_config_json) |json| try service_config.ServiceConfig.parse(allocator, json) else null;
        errdefer if (config) |*value| value.deinit();
        const name: ?[]const u8 = if (options.disable_health_check) null else options.health_service orelse (if (options.health_metadata.service.len != 0) options.health_metadata.service else if (config) |*value| value.healthCheckServiceName() else null);
        if (name) |service| {
            const encoded = try health.encodeRequestAlloc(allocator, .{ .service = service });
            allocator.free(encoded);
        }
        const owned_name = if (name) |service| try allocator.dupe(u8, service) else null;
        errdefer if (owned_name) |service| allocator.free(service);
        const tracker = try connectivity.Tracker.create(allocator, io);
        errdefer tracker.release();
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        const count = switch (target) {
            .resolved => |set| set.endpoints.len,
            else => 1,
        };
        if (count == 0) return error.InvalidSharedOptions;
        const workers = try allocator.alloc(State.Worker, count);
        errdefer allocator.free(workers);
        var initialized: usize = 0;
        errdefer for (workers[0..initialized]) |*worker| {
            worker.owner.deinit();
            worker.tracker.release();
        };
        for (workers, 0..) |*worker, id| {
            const local_target: channel.Target = if (target == .resolved) switch (target.resolved.endpoints[id]) {
                .cleartext_ip => |v| .{ .cleartext_ip = v },
                .cleartext_host => |v| .{ .cleartext_host = v },
                .tls_host => |v| .{ .tls_host = v },
                .tls_address => |v| .{ .tls_address = v },
                .custom => |v| .{ .custom = v },
            } else target;
            var owner = if (config) |*value| try channel.Channel.initWithServiceConfig(allocator, io, local_target, options.channel, value) else try channel.Channel.init(allocator, io, local_target, options.channel);
            const endpoint_tracker = connectivity.Tracker.create(allocator, io) catch |err| {
                owner.deinit();
                return err;
            };
            worker.* = .{ .parent = state, .id = id, .owner = owner, .tracker = endpoint_tracker };
            initialized += 1;
        }
        const balancing = if (config) |*value| value.loadBalancingConfig() else service_config.LoadBalancingConfig{};
        var retained = options;
        retained.service_config_json = null;
        retained.health_service = owned_name;
        retained.health_metadata.service = owned_name orelse "";
        state.* = .{
            .allocator = allocator,
            .io = io,
            .options = retained,
            .workers = workers,
            .config = config,
            .health_service = owned_name,
            .tracker = tracker,
            .policy = options.channel.selection_policy orelse (if (balancing.configured) switch (balancing.policy) {
                .pick_first => channel.SelectionPolicy.pick_first,
                .round_robin => channel.SelectionPolicy.round_robin,
            } else if (target == .resolved) target.resolved.policy else .pick_first),
        };
        if (options.channel.shuffle_address_list orelse (balancing.configured and balancing.shuffle_address_list)) {
            var remaining = workers.len;
            while (remaining > 1) {
                remaining -= 1;
                var random: usize = undefined;
                io.random(std.mem.asBytes(&random));
                std.mem.swap(State.Worker, &workers[remaining], &workers[random % (remaining + 1)]);
            }
            for (workers, 0..) |*worker, id| worker.id = id;
        }
        errdefer {
            state.close();
            state.group.cancel(io);
        }
        for (workers) |*worker| try state.group.concurrent(io, State.Worker.run, .{worker});
        return .{ .state = state };
    }
    pub fn sender(self: SharedChannel) Sender {
        self.state.retain();
        return .{ .state = self.state };
    }
    pub fn connect(self: SharedChannel) void {
        self.state.lock();
        defer self.state.unlock();
        if (self.state.closed) return;
        self.state.demand = true;
        if (self.state.tracker.snapshot().state == .idle) self.state.tracker.setState(.connecting);
        self.state.wakeAllLocked();
    }
    pub fn watchConnectivity(self: SharedChannel) connectivity.Watch {
        return .init(self.state.tracker);
    }
    pub fn connectivityState(self: SharedChannel) connectivity.State {
        return self.state.tracker.snapshot().state;
    }
    pub fn watchEndpointConnectivity(self: SharedChannel, index: usize) ?connectivity.Watch {
        self.state.lock();
        defer self.state.unlock();
        if (index >= self.state.workers.len) return null;
        return .init(self.state.workers[index].tracker);
    }
    pub fn deinit(self: *SharedChannel) void {
        self.state.close();
        self.state.group.cancel(self.state.io);
        self.state.release();
        self.* = undefined;
    }
};

test {
    _ = @import("shared/tests.zig");
}
