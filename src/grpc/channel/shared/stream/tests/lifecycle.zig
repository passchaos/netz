const std = @import("std");
const grpc = @import("../../../../mod.zig");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const allocator = std.testing.allocator;
const testing = @import("../testing.zig");
const readReply = testing.readReply;
const readOne = testing.readOne;
const wait = testing.wait;

test "gRPC shared duplex cancellation joins transport and permits unary reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("held", message.payload);
        }
        fn run(server_ptr: *grpc.runtime.Server, signal: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            {
                var rpc = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
                defer rpc.deinit();
                while (true) {
                    var event = try rpc.readRequestEventWithTimeout(.fromSeconds(5), {}, consume);
                    defer event.deinit();
                    if (event == .messages and event.messages.count != 0) break;
                }
                signal.set(connection.connection.io);
                var reset = try rpc.readRequestEventWithTimeout(.fromSeconds(5), {}, consume);
                defer reset.deinit();
                try std.testing.expect(reset == .reset);
                try std.testing.expectEqual(@import("../../../../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
            }
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = "reused" });
            var end = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer end.deinit(allocator);
            return error.UnexpectedReset;
        }
    };
    var peer = io.async(Peer.run, .{ &server, &admitted });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .limits = .{ .terminal_cleanup_timeout = .fromSeconds(1) } } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    try writer.writeMessage("held");
    try wait(&admitted, io);
    var pending = try io.concurrent(stream.Reader.next, .{reader});
    defer _ = pending.cancel(io) catch {};
    rpc.cancel();
    try std.testing.expectError(error.Canceled, pending.await(io));
    try std.testing.expectError(error.Canceled, writer.writeMessage("after-cancel"));
    var reply = try sender.unary(.{ .path = "/demo.Shared/Unary", .message = "next", .timeout = .{ .value = 5, .unit = .second } });
    defer reply.deinit();
    try std.testing.expectEqualStrings("reused", reply.message.?.payload);
    client.deinit();
    live = false;
    try peer.await(io);
}

test "gRPC shared duplex channel destruction closes retained capabilities" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server, signal: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            signal.set(connection.connection.io);
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer reset.deinit(allocator);
            try std.testing.expectEqual(@import("../../../../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &admitted });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("closed");
    try wait(&admitted, io);
    client.deinit();
    live = false;
    try std.testing.expectError(error.SharedChannelClosed, reader.next());
    try std.testing.expectError(error.SharedChannelClosed, writer.writeMessage("late"));
    try peer.await(io);
}
