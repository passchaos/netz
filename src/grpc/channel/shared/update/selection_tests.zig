const std = @import("std");
const grpc = @import("../../../mod.zig");
const http2 = @import("../../../../http2/mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const allocator = std.testing.allocator;

test "gRPC shared update keeps a healthy pick first selection after primary recovery" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    const Connector = struct {
        address: std.Io.net.IpAddress,
        attempts: std.atomic.Value(usize) = .init(0),
        fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, backend: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.attempts.fetchAdd(1, .acq_rel) == 0) return error.ConnectionRefused;
            return http2.runtime.Client.connectWithDeadline(gpa, backend, self.address, .{}, deadline);
        }
    };
    const Peer = struct {
        fn run(server: *grpc.runtime.Server) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            while (true) {
                var request = connection.readUnaryWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                    error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                    else => return err,
                };
                defer request.deinit();
                try connection.writeUnary(request.request.stream_id, .{ .message = "A" });
            }
        }
    };
    var connector = Connector{ .address = a.address() };
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } },
        .{ .cleartext_ip = .{ .address = b.address() } },
    };
    const reordered = [_]grpc.ChannelEndpoint{ endpoints[1], endpoints[0] };
    var a_task = io.async(Peer.run, .{&a});
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 3 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .channel = .{ .backoff = .{ .initial_backoff = .fromSeconds(60), .max_backoff = .fromSeconds(60), .jitter = 0, .min_connect_timeout = .fromSeconds(2) } } });
    var live = true;
    defer if (live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try support.ready(&b_watch);
    while (a_watch.snapshot().state != .transient_failure) _ = try a_watch.nextWithTimeout(.fromSeconds(3));
    var sender = client.sender();
    defer sender.deinit();
    for (0..3) |phase| {
        if (phase == 1) {
            try client.resetConnectionBackoff();
            try support.ready(&a_watch);
            _ = try client.update(.{});
        } else if (phase == 2) _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = &reordered } } });
        var response = try sender.unary(.{ .path = "/demo.Update/Unary", .authority = "localhost", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
        defer response.deinit();
        try std.testing.expectEqualStrings("B", response.message.?.payload);
    }
    try std.testing.expectEqual(@as(usize, 2), connector.attempts.load(.acquire));
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}
