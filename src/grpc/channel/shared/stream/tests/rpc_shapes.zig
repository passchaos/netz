const std = @import("std");
const grpc = @import("../../../../mod.zig");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const allocator = std.testing.allocator;

test "gRPC shared duplex supports client and server streaming RPC shapes" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        count: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            const expected = [_][]const u8{ "one", "two", "three" };
            try std.testing.expectEqualStrings(expected[self.count], message.payload);
            self.count += 1;
        }
        fn run(self: *@This(), server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var upload = try connection.readStreamingWithTimeout(.fromSeconds(5), self, consume);
            defer upload.deinit();
            try std.testing.expectEqual(@as(usize, 3), self.count);
            try connection.writeUnary(upload.transport.stream_id, .{ .message = "uploaded" });
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try std.testing.expectEqualStrings("download", request.request.message.payload);
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(allocator);
            for ([_][]const u8{ "first", "", "last" }) |value| try grpc.wire.writeMessage(&body, allocator, value, false);
            try connection.connection.writeResponseWithTimeout(request.request.stream_id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }}, .body = body.items, .trailers = &.{.{ .name = "grpc-status", .value = "0" }} }, .fromSeconds(5));
            var end = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer end.deinit(allocator);
            return error.UnexpectedReset;
        }
    };
    var peer_state: Peer = .{};
    var peer = io.async(Peer.run, .{ &peer_state, &server });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const options: grpc.StreamingRequestOptions = .{ .path = "/demo.Shared/Stream", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true };
    var upload = try sender.startDuplex(options);
    defer upload.deinit();
    var uw = upload.writer();
    defer uw.deinit();
    var ur = upload.reader();
    defer ur.deinit();
    try uw.writeMessage("one");
    try uw.writeMessage("two");
    try uw.writeFinalMessage("three");
    try @import("../testing.zig").readReply(ur, "uploaded");
    var download = try sender.startDuplex(options);
    defer download.deinit();
    var dw = download.writer();
    defer dw.deinit();
    var dr = download.reader();
    defer dr.deinit();
    try dw.writeFinalMessage("download");
    var count: usize = 0;
    while (true) {
        var event = try dr.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(allocator);
        if (event == .message) {
            const expected = [_][]const u8{ "first", "", "last" };
            try std.testing.expectEqualStrings(expected[count], event.message.payload);
            count += 1;
        } else if (event == .terminal) {
            try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
            break;
        }
    }
    try std.testing.expectEqual(@as(usize, 3), count);
    client.deinit();
    live = false;
    try peer.await(io);
}
