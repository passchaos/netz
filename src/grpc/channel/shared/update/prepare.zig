//! Own and validate a complete replacement before touching the active topology.
const std = @import("std");
const channel = @import("../../../channel.zig");
const service_config = @import("../../../service_config.zig");
const State = @import("../state.zig").State;
const Options = @import("../options.zig").Options;
const Generation = @import("../config_generation.zig").Generation;
const orca_config = @import("../orca/config.zig");

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    config: ?*Generation,
    endpoints: []channel.Endpoint,
    sources: []*State.Source = &.{},
    policy: channel.SelectionPolicy,
    resolver_policy: channel.SelectionPolicy,
    balancing: service_config.LoadBalancingConfig,
    weighted: ?State.WeightedTarget = null,
    health_service: ?[]u8 = null,
    orca_oob: ?orca_config.Config = null,
    shuffle: bool,
    retired_children: ?*State.Retention.Entry = null,

    /// Consumes the generation, canonical inventory and explicit ORCA clone.
    pub fn create(allocator: std.mem.Allocator, io: std.Io, endpoints: []channel.Endpoint, resolver_policy: channel.SelectionPolicy, options: Options, config: ?*Generation, orca_override: ?orca_config.Config) State.Failure!Prepared {
        var self = Prepared{
            .allocator = allocator,
            .config = config,
            .endpoints = endpoints,
            .policy = undefined,
            .resolver_policy = resolver_policy,
            .balancing = @import("../balancing.zig").resolve(if (config) |generation| generation.config.loadBalancingConfig() else .{}, options.channel.selection_policy),
            .orca_oob = orca_override,
            .shuffle = false,
        };
        errdefer self.deinit();
        const target: channel.Target = .{ .resolved = .{ .endpoints = endpoints, .policy = resolver_policy } };
        if (endpoints.len != 0) try target.validate();
        const balancing = self.balancing;
        self.policy = @import("../balancing.zig").select(balancing, options.channel.selection_policy, resolver_policy);
        self.shuffle = options.channel.shuffle_address_list orelse (balancing.configured and balancing.shuffle_address_list);
        if (self.policy == .weighted_target or self.policy == .priority) {
            if (self.policy == .weighted_target and balancing.policy != .weighted_target) {
                return error.InvalidSharedOptions;
            }
            if (self.policy == .priority and balancing.policy != .priority) {
                return error.InvalidSharedOptions;
            }
            self.weighted = try State.WeightedTarget.initResolvedWithPriorityTimeouts(
                allocator,
                balancing.root orelse return error.InvalidSharedOptions,
                endpoints,
                (options.priority_failover_timeout orelse
                    std.Io.Duration.fromSeconds(10)).nanoseconds,
                options.removed_child_retention.nanoseconds,
            );
        }
        const name: ?[]const u8 = if (options.disable_health_check) null else options.health_service orelse
            if (config) |generation| generation.config.healthCheckServiceName() else null;
        if (name) |value| self.health_service = try allocator.dupe(u8, value);
        if (self.orca_oob == null and self.policy == .weighted_round_robin and balancing.weighted_round_robin.enable_oob_load_report) {
            self.orca_oob = try orca_config.Config.init(allocator, .{ .report_interval = balancing.weighted_round_robin.oob_reporting_period });
        }
        self.sources = try @import("../layout.zig").create(allocator, io, target, options, self.policy, if (self.weighted) |*runtime| runtime else null, self.shuffle, false);
        return self;
    }

    pub fn orcaFor(self: *Prepared, source: *State.Source) ?*const orca_config.Config {
        if (self.orca_oob) |*config| return config;
        return if (self.weighted) |*runtime| runtime.orcaForPath(source.endpoint.hierarchicalPath()) else null;
    }

    pub fn deinit(self: *Prepared) void {
        State.Retention.destroyList(self.retired_children);
        for (self.sources) |source| source.release();
        self.allocator.free(self.sources);
        self.allocator.free(self.endpoints);
        if (self.weighted) |*runtime| runtime.deinit();
        if (self.health_service) |name| self.allocator.free(name);
        if (self.orca_oob) |*config| config.deinit();
        if (self.config) |config| config.release();
    }
};
