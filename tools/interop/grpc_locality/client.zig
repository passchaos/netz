//! Ordinary and shared locality routing against independent gRPC servers.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const allocator = std.heap.c_allocator;
const config_json = "{\"loadBalancingConfig\":[{\"xds_wrr_locality_experimental\":{\"childPolicy\":[{\"round_robin\":{}}]}}]}";

fn count(client: anytype, total: usize) ![3]usize {
    var result = [_]usize{ 0, 0, 0 };
    for (0..total) |_| {
        var response = try client.unary(.{ .path = "/fixture.Locality/Unary", .authority = "localhost", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
        defer response.deinit();
        const payload = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, payload, "a1")) 0 else if (std.mem.eql(u8, payload, "a2")) 1 else if (std.mem.eql(u8, payload, "b")) 2 else return error.UnexpectedBackend;
        result[index] += 1;
    }
    return result;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.InvalidArgument;
    const is_shared = std.mem.eql(u8, args[1], "shared");
    if (!is_shared and !std.mem.eql(u8, args[1], "ordinary")) return error.InvalidArgument;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var initial: [3]grpc.ChannelEndpoint = undefined;
    for (&initial, args[2..], 0..) |*endpoint, port, index| endpoint.* = .{ .cleartext_ip = .{
        .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, port, 10)) },
        .hierarchical_path = if (index == 2) &.{"b"} else &.{"a"},
        .locality_weight = if (index == 2) 3 else 1,
    } };
    var config = try grpc.ServiceConfig.parse(allocator, config_json);
    defer config.deinit();
    var ordinary = if (!is_shared) try grpc.Channel.initWithServiceConfig(allocator, io, .{ .resolved = .{ .endpoints = &initial } }, .{}, &config) else null;
    defer if (ordinary) |*client| client.deinit();
    var shared = if (is_shared) try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &initial } }, .{ .service_config_json = config_json }) else null;
    defer if (shared) |*client| client.deinit();
    var sender = if (shared) |client| client.sender() else null;
    defer if (sender) |*value| value.deinit();
    if (shared) |client| {
        client.connect();
        for (0..3) |index| {
            var watch = client.watchEndpointConnectivity(index).?;
            defer watch.deinit();
            while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
        }
    }
    const generated_before: [2]u32 = if (shared) |client| .{ client.state.weighted_target.?.root.kind.weighted.children[0].weight, client.state.weighted_target.?.root.kind.weighted.children[1].weight } else .{ ordinary.?.weighted_target_runtime.?.root.kind.weighted[0].weight, ordinary.?.weighted_target_runtime.?.root.kind.weighted[1].weight };
    var generated_after = generated_before;
    const before = if (sender) |value| try count(value, 400) else try count(&ordinary.?, 400);
    try std.testing.expect(before[2] > 240 and before[2] < 360);
    const delta = if (before[0] > before[1]) before[0] - before[1] else before[1] - before[0];
    try std.testing.expect(delta <= 1);
    var after = [_]usize{ 0, 0, 0 };
    var removed = after;
    var restored = after;
    if (shared) |client| {
        var changed = initial;
        changed[0].cleartext_ip.locality_weight = 3;
        changed[1].cleartext_ip.locality_weight = 3;
        changed[2].cleartext_ip.locality_weight = 1;
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &changed } } }, .fromSeconds(3));
        generated_after = .{ client.state.weighted_target.?.root.kind.weighted.children[0].weight, client.state.weighted_target.?.root.kind.weighted.children[1].weight };
        after = try count(sender.?, 400);
        try std.testing.expect(after[0] + after[1] > 240 and after[0] + after[1] < 360);
        var zero = changed;
        zero[0].cleartext_ip.locality_weight = 0;
        zero[1].cleartext_ip.locality_weight = 0;
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &zero } } }, .fromSeconds(3));
        removed = try count(sender.?, 20);
        try std.testing.expectEqual(@as(usize, 20), removed[2]);
        _ = try client.updateWithTimeout(.{ .target = .{ .resolved = .{ .endpoints = &changed } } }, .fromSeconds(3));
        restored = try count(sender.?, 100);
        try std.testing.expect(restored[0] + restored[1] > 50);
    }
    std.debug.print("LOCALITY_RESULT {{\"mode\":\"{s}\",\"before\":[{d},{d},{d}],\"after\":[{d},{d},{d}],\"removed\":[{d},{d},{d}],\"restored\":[{d},{d},{d}],\"generated_before\":[{d},{d}],\"generated_after\":[{d},{d}]}}\n", .{ args[1], before[0], before[1], before[2], after[0], after[1], after[2], removed[0], removed[1], removed[2], restored[0], restored[1], restored[2], generated_before[0], generated_before[1], generated_after[0], generated_after[1] });
}
