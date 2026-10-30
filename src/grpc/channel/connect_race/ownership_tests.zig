const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const http2 = @import("../../../http2/mod.zig");
const allocator = support.allocator;

test "gRPC connection competition closes a successful result returned during cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    const Unused = struct {
        server: *grpc.runtime.Server,
        closed: std.Io.Event = .unset,
        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = connection.readUnaryWithTimeout(.fromSeconds(3)) catch |err| {
                if (err != error.ConnectionClosed) return err;
                self.closed.set(connection.connection.io);
                return;
            };
            defer request.deinit();
            return error.UnexpectedApplicationRequest;
        }
    };
    var unused = Unused{ .server = &a };
    var a_task = io.async(Unused.run, .{&unused});
    defer _ = a_task.cancel(io) catch {};
    var echo = support.Echo{ .server = .{ .tcp = &b }, .requests = 1 };
    var b_task = io.async(support.Echo.run, .{&echo});
    defer _ = b_task.cancel(io) catch {};
    const Connectors = struct {
        a: std.Io.net.IpAddress,
        b: std.Io.net.IpAddress,
        connected: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        fn delayed(pointer: ?*anyopaque, gpa: std.mem.Allocator, child_io: std.Io, until: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(pointer.?));
            var connection = try http2.runtime.Client.connectWithDeadline(gpa, child_io, self.a, .{}, until);
            errdefer connection.close();
            self.connected.set(child_io);
            self.release.wait(child_io) catch |err| switch (err) {
                error.Canceled => return connection,
            };
            return connection;
        }
        fn winner(pointer: ?*anyopaque, gpa: std.mem.Allocator, child_io: std.Io, until: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(pointer.?));
            try self.connected.wait(child_io);
            return http2.runtime.Client.connectWithDeadline(gpa, child_io, self.b, .{}, until);
        }
    };
    var connectors = Connectors{ .a = a.address(), .b = b.address() };
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .custom = .{ .context = &connectors, .connect_fn = Connectors.delayed } },
        .{ .custom = .{ .context = &connectors, .connect_fn = Connectors.winner } },
    };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .connection_attempt_delay = .fromMilliseconds(10) });
    defer channel.deinit();
    var response = try support.unary(&channel);
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    try support.wait(&unused.closed, io);
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC connection competition progresses when the async budget is exhausted" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    var stalled = try support.Stalled.init(io, false);
    defer stalled.deinit(io);
    var a_task = try io.concurrent(support.Stalled.run, .{ &stalled, io });
    defer _ = a_task.cancel(io) catch {};
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var echo = support.Echo{ .server = .{ .tcp = &server }, .requests = 1 };
    var b_task = try io.concurrent(support.Echo.run, .{&echo});
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{ .{ .cleartext_ip = .{ .address = stalled.address() } }, .{ .cleartext_ip = .{ .address = server.address() } } };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .connection_attempt_delay = .fromMilliseconds(20) });
    defer channel.deinit();
    var response = try support.unary(&channel);
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    try support.wait(&stalled.closed, io);
    try a_task.await(io);
    try b_task.await(io);
}
