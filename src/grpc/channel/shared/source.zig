//! One configured endpoint and its latest resolved address membership.
const std = @import("std");
const channel = @import("../../channel.zig");
const resolver = @import("../resolver.zig");

pub fn Source(comptime Worker: type) type {
    return struct {
        endpoint: channel.Endpoint,
        resolver: ?*resolver.State = null,
        authority: ?[]u8 = null,
        current: []*Worker = &.{},
        pending: ?[]*Worker = null,
        wake: std.Io.Event = .unset,
        refresh_requested: bool = false,
        generation: u64 = 0,
        last_error: ?anyerror = null,

        const Self = @This();
        pub fn init(allocator: std.mem.Allocator, io: std.Io, endpoint: channel.Endpoint, options: channel.Options) channel.Error!Self {
            const host, const port, const push = switch (endpoint) {
                .cleartext_host => |v| .{ v.host, v.port, v.limits.enable_push },
                .tls_host => |v| .{ v.host, v.port, v.limits.enable_push },
                else => return .{ .endpoint = endpoint },
            };
            if (port == 0 or push) return error.InvalidChannelOptions;
            const authority = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
            errdefer allocator.free(authority);
            const state = try resolver.State.create(allocator, io, host, port, options.address_resolver, options.resolver_min_refresh_interval, options.backoff);
            return .{ .endpoint = endpoint, .resolver = state, .authority = authority };
        }
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.resolver) |state| state.deinit();
            if (self.authority) |value| allocator.free(value);
            allocator.free(self.current);
            if (self.pending) |members| allocator.free(members);
        }
        pub fn latest(self: *const Self) []*Worker {
            return self.pending orelse self.current;
        }
        pub fn target(self: *const Self, address: ?std.Io.net.IpAddress) channel.Target {
            return switch (self.endpoint) {
                .cleartext_host => |v| .{ .cleartext_ip = .{ .address = address.?, .authority = self.authority, .limits = v.limits } },
                .tls_host => |v| .{ .tls_address = .{ .address = address.?, .tls_host = v.host, .authority = self.authority.?, .limits = v.limits, .tls = v.tls } },
                .cleartext_ip => |v| .{ .cleartext_ip = v },
                .tls_address => |v| .{ .tls_address = v },
                .custom => |v| .{ .custom = v },
            };
        }
    };
}
