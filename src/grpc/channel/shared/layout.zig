//! Derive the current policy's source owners from the canonical resolver inventory.
const std = @import("std");
const channel = @import("../../channel.zig");
const State = @import("state.zig").State;
const least_request = @import("../least_request.zig");
const ring_hash = @import("../ring_hash.zig");

pub fn create(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: @import("options.zig").Options, policy: channel.SelectionPolicy, weighted_target: ?*State.WeightedTarget, shuffle: bool, validate_resolver: bool) State.Failure![]*State.Source {
    const count = switch (target) {
        .resolved => |resolved| if (policy == .ring_hash)
            ring_hash.uniqueEndpointCount(resolved.endpoints)
        else if (policy == .weighted_target)
            weightedTargetEndpointCount(
                weighted_target.?,
                resolved.endpoints,
            )
        else if (policy == .least_request)
            least_request.exactUniqueCount(resolved.endpoints)
        else
            resolved.endpoints.len,
        else => 1,
    };
    const sources = try allocator.alloc(*State.Source, count);
    var initialized: usize = 0;
    errdefer {
        for (sources[0..initialized]) |source| source.release();
        allocator.free(sources);
    }
    var has_host = false;
    var source_index: usize = 0;
    for (0..if (target == .resolved) target.resolved.endpoints.len else 1) |index| {
        if (target == .resolved and policy == .ring_hash) {
            const endpoint = target.resolved.endpoints[index];
            for (sources[0..source_index]) |source| {
                if (!ring_hash.sameEndpointIdentity(
                    source.endpoint,
                    endpoint,
                )) continue;
                source.ring_hash_weight = std.math.add(
                    u32,
                    source.ring_hash_weight,
                    ring_hash.endpointWeight(endpoint),
                ) catch return error.InvalidSharedOptions;
                break;
            } else {
                sources[source_index] = try State.Source.create(
                    allocator,
                    io,
                    endpoint,
                    options.channel,
                );
                initialized += 1;
                has_host = has_host or
                    sources[source_index].resolver != null;
                source_index += 1;
            }
            continue;
        }
        if (target == .resolved and policy == .weighted_target and
            weighted_target.?.usesRing(
                target.resolved.endpoints[index].hierarchicalPath(),
            ))
        {
            const endpoint = target.resolved.endpoints[index];
            for (sources[0..source_index]) |source| {
                if (!ring_hash.sameEndpointIdentity(
                    source.endpoint,
                    endpoint,
                )) continue;
                source.ring_hash_weight = std.math.add(
                    u32,
                    source.ring_hash_weight,
                    ring_hash.endpointWeight(endpoint),
                ) catch return error.InvalidSharedOptions;
                break;
            } else {
                sources[source_index] = try State.Source.create(
                    allocator,
                    io,
                    endpoint,
                    options.channel,
                );
                initialized += 1;
                has_host = has_host or
                    sources[source_index].resolver != null;
                source_index += 1;
            }
            continue;
        }
        if (target == .resolved and policy == .least_request and
            least_request.isExactDuplicate(target.resolved.endpoints, index))
        {
            continue;
        }
        const endpoint: channel.Endpoint = switch (target) {
            .resolved => |set| set.endpoints[index],
            .cleartext_ip => |v| .{ .cleartext_ip = v },
            .cleartext_host => |v| .{ .cleartext_host = v },
            .tls_host => |v| .{ .tls_host = v },
            .tls_address => |v| .{ .tls_address = v },
            .custom => |v| .{ .custom = v },
        };
        sources[source_index] = try State.Source.create(allocator, io, endpoint, options.channel);
        const source = sources[source_index];
        initialized += 1;
        has_host = has_host or source.resolver != null;
        source_index += 1;
    }
    std.debug.assert(source_index == sources.len);
    for (sources) |source| {
        if (source.endpoint == .custom and source.endpoint.custom.ring_hash_key == null and
            (policy == .ring_hash or ((policy == .weighted_target or
                policy == .priority) and weighted_target.?.usesRing(source.endpoint.hierarchicalPath())))) return error.InvalidSharedOptions;
    }
    var proxy_resolves_origin = false;
    for (sources) |source| {
        proxy_resolves_origin = proxy_resolves_origin or
            (source.endpoint == .tls_host and
                (source.endpoint.tls_host.proxy != null or
                    source.endpoint.tls_host.socks5_proxy != null));
    }
    if (validate_resolver and sources.len != 0 and options.channel.address_resolver != null and !has_host and
        !proxy_resolves_origin)
    {
        return error.InvalidChannelOptions;
    }
    if (shuffle) {
        var remaining = sources.len;
        while (remaining > 1) {
            remaining -= 1;
            var random: usize = undefined;
            io.random(std.mem.asBytes(&random));
            std.mem.swap(*State.Source, &sources[remaining], &sources[random % (remaining + 1)]);
        }
    }
    return sources;
}

fn weightedTargetEndpointCount(
    runtime: *State.WeightedTarget,
    endpoints: []const channel.Endpoint,
) usize {
    var count: usize = 0;
    for (endpoints, 0..) |endpoint, index| {
        if (!runtime.usesRing(endpoint.hierarchicalPath())) {
            count += 1;
            continue;
        }
        for (endpoints[0..index]) |prior| {
            if (runtime.usesRing(prior.hierarchicalPath()) and
                ring_hash.sameEndpointIdentity(prior, endpoint)) break;
        } else {
            count += 1;
        }
    }
    return count;
}
