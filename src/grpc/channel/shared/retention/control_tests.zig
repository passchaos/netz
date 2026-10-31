const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test "gRPC retained child continues ORCA reports while inactive without reopening control" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var publish: std.Io.Event = .unset;
    var closed: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, next_report: *std.Io.Event, shutdown: *std.Io.Event) anyerror!void {
            errdefer |err| std.debug.print("retained ORCA server failed: {s}\n", .{@errorName(err)});
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var reports: ?grpc.orca_oob.ServerSession = null;
            defer if (reports) |*stream| stream.deinit();
            var business = false;
            while (reports == null or !business) {
                var accepted = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
                if (std.mem.eql(u8, accepted.path, grpc.orca_oob.path)) {
                    reports = try grpc.orca_oob.accept(accepted);
                    try std.testing.expect(try reports.?.writeReport(.{ .cpu_utilization = 1, .rps_fractional = 5 }) == .complete);
                } else {
                    defer accepted.deinit();
                    const Consumer = struct {
                        fn consume(_: void, _: grpc.StreamingMessage) !void {}
                    };
                    while (true) {
                        var event = try accepted.readRequestEventWithTimeout(.fromSeconds(5), {}, Consumer.consume);
                        defer event.deinit();
                        if (event == .finished) break;
                    }
                    try accepted.startResponse(.{});
                    try std.testing.expect(try accepted.writeMessage("A") == .complete);
                    try accepted.finishOk();
                    business = true;
                }
            }
            try next_report.wait(connection.connection.io);
            try std.testing.expect(try reports.?.writeReport(.{ .cpu_utilization = 1, .rps_fractional = 9 }) == .complete);
            var request = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try std.testing.expectEqualStrings("/demo.Retention/Unary", request.path);
            const Consumer = struct {
                fn consume(_: void, _: grpc.StreamingMessage) !void {}
            };
            while (true) {
                var event = try request.readRequestEventWithTimeout(.fromSeconds(5), {}, Consumer.consume);
                defer event.deinit();
                if (event == .finished) break;
            }
            try request.startResponse(.{});
            try std.testing.expect(try request.writeMessage("A") == .complete);
            try request.finishOk();
            try shutdown.wait(connection.connection.io);
        }
    };
    var a_task = io.async(Peer.run, .{ &a, &publish, &closed });
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 1 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{ support.endpoint(a.address(), &support.path_a), support.endpoint(b.address(), &support.path_b) };
    const cfg = "{\"loadBalancingConfig\":[{\"weighted_target_experimental\":{\"targets\":{\"a\":{\"weight\":1,\"childPolicy\":[{\"weighted_round_robin\":{\"enableOobLoadReport\":true,\"blackoutPeriod\":\"0s\"}}]}}}}]}";
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = cfg });
    var live = true;
    defer if (live) client.deinit();
    var watch = client.watchEndpointOrca(0).?;
    defer watch.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var first = try support.unary(sender);
    defer first.deinit();
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = endpoints[1..] } }, .service_config = .{ .replace = support.cfg_b } });
    var current = try support.unary(sender);
    defer current.deinit();
    try std.testing.expectEqualStrings("B", current.message.?.payload);
    publish.set(io);
    while (true) {
        var update = try watch.nextWithTimeout(.fromSeconds(5));
        defer update.deinit();
        if (update.report != null and update.report.?.report.rps_fractional == 9) break;
    }
    _ = try client.update(.{ .target = .{ .resolved = .{ .endpoints = &endpoints } }, .service_config = .{ .replace = cfg } });
    var restored = try support.unary(sender);
    defer restored.deinit();
    try std.testing.expectEqualStrings("A", restored.message.?.payload);
    client.deinit();
    live = false;
    closed.set(io);
    try a_task.await(io);
    try b_task.await(io);
}
