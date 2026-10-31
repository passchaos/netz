//! Live method/LB updates on one independently observed HTTP/2 connection.
const std = @import("std");
const netz = @import("netz");

pub fn run(allocator: std.mem.Allocator, io: std.Io, endpoint: netz.grpc.ChannelEndpoint, request: netz.grpc.call.UnaryCallOptions) !usize {
    const target: netz.grpc.ChannelTarget = switch (endpoint) {
        .cleartext_ip => |value| .{ .cleartext_ip = value },
        .tls_address => |value| .{ .tls_address = value },
        else => unreachable,
    };
    var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var first = try sender.unary(request);
    defer first.deinit();
    try std.testing.expectEqualStrings("pong", first.message.?.payload);
    try std.testing.expectEqual(@as(u64, 2), try channel.updateWithTimeout(.{ .service_config = .{ .replace = "{\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":3}]}" } }, .fromSeconds(2)));
    try std.testing.expectError(error.GrpcMessageTooLarge, sender.unary(request));
    try std.testing.expectEqual(@as(u64, 3), try channel.updateWithTimeout(.{ .service_config = .{ .replace = "{\"loadBalancingConfig\":[{\"round_robin\":{}}],\"methodConfig\":[{\"name\":[{}],\"maxRequestMessageBytes\":4}]}" } }, .fromSeconds(2)));
    try std.testing.expectEqual(netz.grpc.ChannelSelectionPolicy.round_robin, channel.selectionPolicy());
    var second = try sender.unary(request);
    defer second.deinit();
    try std.testing.expectEqualStrings("pong", second.message.?.payload);
    return 2;
}
