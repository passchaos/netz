const std = @import("std");
const grpc = @import("../../mod.zig");
const allocator = std.testing.allocator;

test "ordinary Channel health gate cancelWaits wakes an unbounded caller and reset restores admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var publish_status: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {}
        fn run(listener: *grpc.runtime.Server, io: std.Io, publish: *std.Io.Event) !void {
            var watch_connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer watch_connection.deinit();
            var watch = try watch_connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer watch.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, watch.path);
            try publish.wait(io);
            var writer = try watch_connection.startStreamingResponse(watch.transport.stream_id, .{});
            defer writer.deinit();
            const serving = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(serving);
            try writer.writeMessage(serving);

            var application = try listener.acceptWithTimeout(.fromSeconds(3));
            defer application.deinit();
            var request = try application.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            try writer.finishWithOptions(.{ .status = .unimplemented });
        }
    };
    var peer = try base.concurrent(Peer.run, .{ &server, base, &publish_status });
    defer _ = peer.cancel(base) catch {};
    var channel = try grpc.Channel.init(allocator, base, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();

    const Probe = struct {
        base: std.Io,
        signal: *std.Io.Event,
        entered: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (pointer == @as(*const u32, @ptrCast(self.signal))) self.entered.set(self.base);
            return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
        }
    };
    var probe = Probe{ .base = base, .signal = &channel.health_sync.?.changed };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.futexWait = Probe.wait;
    channel.io = .{ .userdata = base.userdata, .vtable = &table };
    const Caller = struct {
        channel: *grpc.Channel,
        io: std.Io,
        done: std.Io.Event = .unset,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            var response = self.channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .wait_for_ready = true }) catch |err| {
                self.failure = err;
                self.done.set(self.io);
                return;
            };
            response.deinit();
            self.done.set(self.io);
        }
    };
    var caller = Caller{ .channel = &channel, .io = base };
    var task = try base.concurrent(Caller.run, .{&caller});
    defer task.cancel(base);
    try probe.entered.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    channel.cancelWaits();
    try caller.done.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    task.await(base);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), caller.failure);
    try std.testing.expectEqual(@as(?bool, null), channel.healthServingAt(0));

    channel.resetCancellation();
    publish_status.set(base);
    var recovered = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer recovered.deinit();
    try std.testing.expectEqualStrings("pong", recovered.message.?.payload);
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    try peer.await(base);
}
