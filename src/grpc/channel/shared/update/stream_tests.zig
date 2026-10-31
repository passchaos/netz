const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const support = @import("../resolution/test_support.zig");
const Peer = @import("../weighted_target/test_support.zig").Peer;
const allocator = std.testing.allocator;

test "gRPC shared update lets a removed duplex owner finish later request and response data" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var stop: std.Io.Event = .unset;
    var a_task = io.async(Peer.run, .{ &a, &stop, "old-stream", @as(?std.Io.Duration, null) });
    defer _ = a_task.cancel(io) catch {};
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "new-endpoint", .requests = 1 };
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = a.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var stream = try sender.startDuplex(.{ .path = "/demo.Update/Duplex", .authority = "localhost", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer stream.deinit();
    var writer = stream.writer();
    defer writer.deinit();
    var reader = stream.reader();
    defer reader.deinit();
    _ = try client.update(.{ .target = .{ .cleartext_ip = .{ .address = b.address() } } });
    var newer = try sender.unary(.{ .path = "/demo.Update/Unary", .authority = "localhost", .message = "new", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer newer.deinit();
    try std.testing.expectEqualStrings("new-endpoint", newer.message.?.payload);
    // Both request DATA and response DATA follow endpoint removal.
    try writer.writeFinalMessage("request");
    var messages: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings("old-stream", message.payload);
                messages += 1;
            },
            .terminal => |response| {
                try std.testing.expectEqual(grpc.Status.ok, response.status);
                try std.testing.expectEqual(@as(usize, 1), messages);
                break;
            },
            else => {},
        }
    }
    // The removed transport retires while the updated channel remains open.
    try a_task.await(io);
    client.deinit();
    live = false;
    try b_task.await(io);
}
