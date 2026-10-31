//! Independent peer sees A/B/A routing on two reused physical connections.
const std = @import("std");
const netz = @import("netz");

pub fn run(allocator: std.mem.Allocator, io: std.Io, endpoint: netz.grpc.ChannelEndpoint, request: netz.grpc.call.UnaryCallOptions) !usize {
    const a = [_][]const u8{"a"};
    const b = [_][]const u8{"b"};
    var endpoints = [_]netz.grpc.ChannelEndpoint{ endpoint, endpoint };
    for (&endpoints, [_][]const []const u8{ &a, &b }) |*value, path| switch (value.*) {
        .cleartext_ip => |*target| target.hierarchical_path = path,
        .tls_address => |*target| target.hierarchical_path = path,
        else => unreachable,
    };
    const cfg_a = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
    const cfg_b = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"b\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
    var channel = try netz.grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = cfg_a });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var first = try sender.unary(request);
    defer first.deinit();
    try std.testing.expectEqualStrings("pong", first.message.?.payload);
    _ = try channel.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = endpoints[1..] } }, .service_config = .{ .replace = cfg_b } }, .fromSeconds(2));
    try std.testing.expectEqual(@as(usize, 1), channel.retainedChildCount());
    var second = try sender.unary(request);
    defer second.deinit();
    try std.testing.expectEqualStrings("pong", second.message.?.payload);
    _ = try channel.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } }, .service_config = .{ .replace = cfg_a } }, .fromSeconds(2));
    var third = try sender.unary(request);
    defer third.deinit();
    try std.testing.expectEqualStrings("pong", third.message.?.payload);
    return 3;
}
