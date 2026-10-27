const std = @import("std");
const grpc = @import("../../../../mod.zig");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const allocator = std.testing.allocator;
const testing = @import("../testing.zig");
const readReply = testing.readReply;
const readOne = testing.readOne;
const wait = testing.wait;

test "gRPC shared duplex capabilities multiplex concurrent writes and receive events" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        bodies: [2]std.ArrayList(u8) = .{ .empty, .empty },
        fn consume(self: *@This(), id: u31, bytes: []const u8) !void {
            try self.bodies[(id - 1) / 2].appendSlice(allocator, bytes);
        }
        fn run(self: *@This(), server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            defer for (&self.bodies) |*body| body.deinit(allocator);
            var requests: [2]@import("../../../../../http2/mod.zig").runtime.StreamingRequest = undefined;
            try connection.connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(5), self, consume);
            defer for (&requests) |*request| request.deinit(allocator);
            for ([_]usize{ 1, 0 }) |index| {
                var iterator = grpc.MessageIterator.init(self.bodies[index].items, 4096);
                const message = (try iterator.next()).?;
                try std.testing.expect((try iterator.next()) == null);
                try connection.writeUnary(requests[index].stream_id, .{ .message = message.payload });
            }
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer reset.deinit(allocator);
            return error.UnexpectedReset;
        }
    };
    var peer_state: Peer = .{};
    var peer = io.async(Peer.run, .{ &peer_state, &server });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var a = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer a.deinit();
    var b = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer b.deinit();
    var aw = a.writer();
    defer aw.deinit();
    var bw = b.writer();
    defer bw.deinit();
    var ar = a.reader();
    defer ar.deinit();
    var br = b.reader();
    defer br.deinit();
    var a_write = try io.concurrent(stream.Writer.writeFinalMessage, .{ aw, "a" });
    defer _ = a_write.cancel(io) catch {};
    var b_write = try io.concurrent(stream.Writer.writeFinalMessage, .{ bw, "b" });
    defer _ = b_write.cancel(io) catch {};
    var a_read = try io.concurrent(readReply, .{ ar, "a" });
    defer _ = a_read.cancel(io) catch {};
    var b_read = try io.concurrent(readReply, .{ br, "b" });
    defer _ = b_read.cancel(io) catch {};
    try a_write.await(io);
    try b_write.await(io);
    try b_read.await(io);
    try a_read.await(io);
    client.deinit();
    client_live = false;
    try peer.await(io);
}

test "gRPC shared duplex slow reader keeps sibling progress and decodes beyond its window" {
    const http2 = @import("../../../../../http2/mod.zig");
    const payload = "q" ** (128 * 1024);
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, payload.len);
    defer server.deinit();
    const Peer = struct {
        fn ignore(_: void, _: u31, _: []const u8) !void {}
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var requests: [2]http2.runtime.StreamingRequest = undefined;
            try connection.connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(5), {}, ignore);
            defer for (&requests) |*request| request.deinit(allocator);
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try grpc.wire.writeMessage(&encoded, allocator, payload, false);
            var writer = try connection.connection.startResponseWithTimeout(requests[0].stream_id, .{ .headers = &.{.{ .name = "content-type", .value = "application/grpc" }} }, .fromSeconds(5));
            defer writer.deinit();
            // Exhaust A's initial stream window. Connection credit must still
            // let the sibling response through before A's reader consumes it.
            try writer.writeWithTimeout(encoded.items[0..65535], .fromSeconds(5));
            try connection.writeUnary(requests[1].stream_id, .{ .message = "sibling" });
            try writer.writeWithTimeout(encoded.items[65535..], .fromSeconds(5));
            try writer.finishTrailersWithTimeout(&.{.{ .name = "grpc-status", .value = "0" }}, .fromSeconds(5));
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer reset.deinit(allocator);
            return error.UnexpectedReset;
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const options: grpc.StreamingRequestOptions = .{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true };
    var a = try sender.startDuplex(options);
    defer a.deinit();
    var b = try sender.startDuplex(options);
    defer b.deinit();
    var aw = a.writer();
    defer aw.deinit();
    var bw = b.writer();
    defer bw.deinit();
    var ar = a.reader();
    defer ar.deinit();
    var br = b.reader();
    defer br.deinit();
    try aw.writeFinalMessage("a");
    try bw.writeFinalMessage("b");
    try readReply(br, "sibling");
    try readReply(ar, payload);
    client.deinit();
    live = false;
    try peer.await(io);
}
