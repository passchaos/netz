//! One precedence rule for initial construction and live publication.
const channel = @import("../../channel.zig");
const service_config = @import("../../service_config.zig");

pub fn resolve(parsed: service_config.LoadBalancingConfig, override: ?channel.SelectionPolicy) service_config.LoadBalancingConfig {
    const selected = override orelse return parsed;
    const matches = switch (selected) {
        .pick_first => parsed.policy == .pick_first,
        .round_robin => parsed.policy == .round_robin,
        .least_request => parsed.policy == .least_request,
        .ring_hash => parsed.policy == .ring_hash,
        .weighted_round_robin => parsed.policy == .weighted_round_robin,
        .weighted_target => parsed.policy == .weighted_target,
    };
    return if (matches) parsed else .{};
}

pub fn select(config: service_config.LoadBalancingConfig, override: ?channel.SelectionPolicy, fallback: channel.SelectionPolicy) channel.SelectionPolicy {
    return override orelse if (!config.configured) fallback else switch (config.policy) {
        .pick_first => .pick_first,
        .round_robin => .round_robin,
        .least_request => .least_request,
        .ring_hash => .ring_hash,
        .weighted_round_robin => .weighted_round_robin,
        .weighted_target => .weighted_target,
        .priority => .round_robin,
    };
}
