const std = @import("std");
pub const grpc = @import("../../../mod.zig");
pub const shared = @import("../../shared.zig");
pub const allocator = std.testing.allocator;
pub const Peer = @import("../resolution/test_support.zig").Peer;
pub const ready = @import("../resolution/test_support.zig").ready;
pub const cfg_a = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
pub const cfg_b = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"b\":{\"weight\":1,\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
pub const path_a = [_][]const u8{"a"};
pub const path_b = [_][]const u8{"b"};

pub fn endpoint(address: std.Io.net.IpAddress, path: []const []const u8) grpc.ChannelEndpoint {
    return .{ .cleartext_ip = .{ .address = address, .hierarchical_path = path } };
}
pub fn unary(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Retention/Unary", .authority = "localhost", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
