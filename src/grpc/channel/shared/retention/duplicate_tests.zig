const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC retained child keeps distinct duplicate resolver owners on reactivation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    const Peer = struct {
        fn serve(connection: *grpc.runtime.ServerConnection, reply: []const u8) !void {
            for (0..2) |_| {
                var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
                defer request.deinit();
                try connection.writeUnary(request.request.stream_id, .{ .message = reply });
            }
            try @import("../resolution/test_support.zig").closed(connection);
        }
        fn run(server: *grpc.runtime.Server) !void {
            var first = try server.acceptWithTimeout(.fromSeconds(5));
            defer first.deinit();
            const peer_io = first.connection.io;
            var first_task = try peer_io.concurrent(serve, .{ &first, "first" });
            defer _ = first_task.cancel(peer_io) catch {};
            var second = try server.acceptWithTimeout(.fromSeconds(5));
            defer second.deinit();
            var second_task = try peer_io.concurrent(serve, .{ &second, "second" });
            defer _ = second_task.cancel(peer_io) catch {};
            try first_task.await(peer_io);
            try second_task.await(peer_io);
        }
    };
    var a_task = io.async(Peer.run, .{&a});
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 1 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(a.address(), &support.path_a), support.endpoint(a.address(), &support.path_a), support.endpoint(b.address(), &support.path_b) };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = support.cfg_a });
    var live = true;
    defer if (live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    var first_watch = client.watchEndpointConnectivity(0).?;
    defer first_watch.deinit();
    var second_watch = client.watchEndpointConnectivity(1).?;
    defer second_watch.deinit();
    try support.ready(&first_watch);
    try support.ready(&second_watch);
    const first_owner = client.state.sources[0];
    const second_owner = client.state.sources[1];
    var sender = client.sender();
    defer sender.deinit();
    var first = try support.unary(sender);
    defer first.deinit();
    var second = try support.unary(sender);
    defer second.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.message.?.payload, second.message.?.payload));
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = endpoints[2..] } }, .service_config = .{ .replace = support.cfg_b } });
    var switched = try support.unary(sender);
    defer switched.deinit();
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } }, .service_config = .{ .replace = support.cfg_a } });
    try std.testing.expect(client.state.sources[0] == first_owner);
    try std.testing.expect(client.state.sources[1] == second_owner);
    var restored_first = try support.unary(sender);
    defer restored_first.deinit();
    var restored_second = try support.unary(sender);
    defer restored_second.deinit();
    try std.testing.expectEqualStrings(first.message.?.payload, restored_first.message.?.payload);
    try std.testing.expectEqualStrings(second.message.?.payload, restored_second.message.?.payload);
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}
