//! One configured endpoint and its latest resolved address membership.
const std = @import("std");
const channel = @import("../../channel.zig");
const resolver = @import("../resolver.zig");
const endpoint_host = @import("../../../internal/endpoint_host.zig");
const ring_hash = @import("../ring_hash.zig");

pub fn Source(comptime Worker: type) type {
    return struct {
        allocator: std.mem.Allocator,
        refs: std.atomic.Value(usize) = .init(1),
        retired: bool = false,
        suspended: bool = false,
        activation: std.Io.Event = .unset,
        endpoint: channel.Endpoint,
        target_lifetime: ?@import("target_lifetime.zig").Lifetime = null,
        ring_hash_weight: u32 = 1,
        resolver: ?*resolver.State = null,
        authority: ?[]u8 = null,
        current: []*Worker = &.{},
        pending: ?[]*Worker = null,
        wake: std.Io.Event = .unset,
        refresh_requested: bool = false,
        backoff_reset_requested: bool = false,
        generation: u64 = 0,
        last_error: ?anyerror = null,

        const Self = @This();
        pub fn create(allocator: std.mem.Allocator, io: std.Io, endpoint: channel.Endpoint, options: channel.Options) channel.Error!*Self {
            const source = try allocator.create(Self);
            errdefer allocator.destroy(source);
            source.* = try init(allocator, io, endpoint, options);
            return source;
        }
        pub fn retain(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }
        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            const allocator = self.allocator;
            self.deinit(allocator);
            allocator.destroy(self);
        }
        fn init(allocator: std.mem.Allocator, io: std.Io, endpoint: channel.Endpoint, options: channel.Options) channel.Error!Self {
            if (endpoint == .tls_host and
                (endpoint.tls_host.proxy != null or
                    endpoint.tls_host.socks5_proxy != null))
            {
                return .{
                    .allocator = allocator,
                    .endpoint = endpoint,
                    .ring_hash_weight = ring_hash.endpointWeight(endpoint),
                };
            }
            const host, const port, const push = switch (endpoint) {
                .cleartext_host => |v| .{ v.host, v.port, v.limits.enable_push },
                .tls_host => |v| .{ v.host, v.port, v.limits.enable_push },
                else => return .{
                    .allocator = allocator,
                    .endpoint = endpoint,
                    .ring_hash_weight = ring_hash.endpointWeight(endpoint),
                },
            };
            if (port == 0 or push) return error.InvalidChannelOptions;
            const parsed = try endpoint_host.parse(host, port);
            const authority = try parsed.authorityAlloc(allocator, port);
            errdefer allocator.free(authority);
            const state = try resolver.State.create(allocator, io, host, port, options.address_resolver, options.resolver_min_refresh_interval, options.backoff);
            var normalized = endpoint;
            if (normalized == .tls_host) normalized.tls_host.host = parsed.host;
            return .{
                .allocator = allocator,
                .endpoint = normalized,
                .ring_hash_weight = ring_hash.endpointWeight(endpoint),
                .resolver = state,
                .authority = authority,
            };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.resolver) |state| state.deinit();
            if (self.authority) |value| allocator.free(value);
            allocator.free(self.current);
            if (self.pending) |members| allocator.free(members);
            if (self.target_lifetime) |owner| owner.release();
        }
        pub fn latest(self: *const Self) []*Worker {
            return self.pending orelse self.current;
        }
        pub fn target(self: *const Self, address: ?std.Io.net.IpAddress) channel.Target {
            return switch (self.resolvedEndpoint(address)) {
                .cleartext_ip => |v| .{ .cleartext_ip = v },
                .cleartext_host => |v| .{ .cleartext_host = v },
                .tls_host => |v| .{ .tls_host = v },
                .tls_address => |v| .{ .tls_address = v },
                .custom => |v| .{ .custom = v },
            };
        }
        pub fn ringHashKey(
            self: *const Self,
            address: ?std.Io.net.IpAddress,
            out: []u8,
        ) error{ InvalidChannelOptions, BufferTooSmall }![]const u8 {
            if (address == null and
                (self.endpoint == .cleartext_host or self.endpoint == .tls_host))
            {
                return ring_hash.endpointKey(self.endpoint, out);
            }
            return ring_hash.endpointKey(self.resolvedEndpoint(address), out);
        }
        fn resolvedEndpoint(
            self: *const Self,
            address: ?std.Io.net.IpAddress,
        ) channel.Endpoint {
            return switch (self.endpoint) {
                .cleartext_host => |v| .{ .cleartext_ip = .{
                    .address = address.?,
                    .authority = self.authority,
                    .limits = v.limits,
                    .ring_hash_key = v.ring_hash_key,
                    .ring_hash_weight = self.ring_hash_weight,
                    .hierarchical_path = v.hierarchical_path,
                    .locality_weight = v.locality_weight,
                } },
                .tls_host => |v| if (v.proxy != null or
                    v.socks5_proxy != null)
                    .{ .tls_host = v }
                else
                    .{ .tls_address = .{
                        .address = address.?,
                        .tls_host = v.host,
                        .authority = self.authority.?,
                        .limits = v.limits,
                        .tls = v.tls,
                        .ring_hash_key = v.ring_hash_key,
                        .ring_hash_weight = self.ring_hash_weight,
                        .hierarchical_path = v.hierarchical_path,
                        .locality_weight = v.locality_weight,
                    } },
                .cleartext_ip => |v| .{ .cleartext_ip = v },
                .tls_address => |v| .{ .tls_address = v },
                .custom => |v| .{ .custom = v },
            };
        }
    };
}

test "SharedChannel source preserves hierarchical path through resolution" {
    const Worker = struct {};
    const path = [_][]const u8{ "region-west", "zone-a" };
    var source = try Source(Worker).init(
        std.testing.allocator,
        std.testing.io,
        .{ .cleartext_host = .{
            .host = "hierarchy.shared.example",
            .port = 8443,
            .hierarchical_path = &path,
        } },
        .{},
    );
    defer source.deinit(std.testing.allocator);
    const target = source.target(.{ .ip4 = .loopback(8443) });
    try std.testing.expectEqual(@as(usize, 2), target.cleartext_ip.hierarchical_path.len);
    try std.testing.expectEqualStrings(
        "region-west",
        target.cleartext_ip.hierarchical_path[0],
    );
    try std.testing.expectEqualStrings(
        "zone-a",
        target.cleartext_ip.hierarchical_path[1],
    );
}
