//! Live method/LB updates on one independently observed HTTP/2 connection.
const std = @import("std");
const netz = @import("netz");

pub fn run(allocator: std.mem.Allocator, io: std.Io, endpoint: netz.grpc.ChannelEndpoint, request: netz.grpc.call.UnaryCallOptions) !usize {
    const path = [_][]const u8{"kept"};
    var routed = endpoint;
    switch (routed) {
        .cleartext_ip => |*value| value.hierarchical_path = &path,
        .tls_address => |*value| value.hierarchical_path = &path,
        else => unreachable,
    }
    const target: netz.grpc.ChannelTarget = switch (routed) {
        .cleartext_ip => |value| .{ .cleartext_ip = value },
        .tls_address => |value| .{ .tls_address = value },
        else => unreachable,
    };
    var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{ .service_config_json = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"kept\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}" });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var first = try sender.unary(request);
    defer first.deinit();
    try std.testing.expectEqualStrings("pong", first.message.?.payload);
    try std.testing.expectEqual(@as(u64, 2), try channel.updateWithTimeout(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"kept\":{\"weight\":2,\"childPolicy\":[{\"round_robin\":{}}]}}}}],\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":3}]}" } }, .fromSeconds(2)));
    try std.testing.expectError(error.GrpcMessageTooLarge, sender.unary(request));
    try std.testing.expectEqual(@as(u64, 3), try channel.updateWithTimeout(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"kept\":{\"weight\":3,\"childPolicy\":[{\"round_robin\":{}}]}}}}],\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":4}]}" } }, .fromSeconds(2)));
    try std.testing.expectEqual(netz.grpc.ChannelSelectionPolicy.weighted_target, channel.selectionPolicy());
    var second = try sender.unary(request);
    defer second.deinit();
    try std.testing.expectEqualStrings("pong", second.message.?.payload);
    return 2;
}
