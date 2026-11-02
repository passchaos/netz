const std = @import("std");
const grpc = @import("../../mod.zig");
const http2 = @import("../../../http2/mod.zig");
const allocator = std.testing.allocator;

test "ordinary Channel health gate retains SERVING during active Watch read admission backoff" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Probe = struct {
        base: std.Io,
        address: std.Io.net.IpAddress,
        owner: std.atomic.Value(std.Thread.Id) = .init(0),
        enabled: std.atomic.Value(bool) = .init(false),
        hits: std.atomic.Value(usize) = .init(0),
        paused: std.Io.Event = .unset,
        permitted: std.Io.Event = .unset,
        var active: ?*@This() = null;
        fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            _ = self.owner.cmpxchgStrong(0, std.Thread.getCurrentId(), .acq_rel, .acquire);
            return http2.runtime.Client.connectWithDeadline(gpa, io, self.address, .{}, deadline);
        }
        fn read(userdata: ?*anyopaque, batch: *std.Io.Batch, timeout: std.Io.Timeout) std.Io.Batch.AwaitConcurrentError!void {
            const self = active.?;
            if (self.owner.load(.acquire) == std.Thread.getCurrentId() and self.enabled.swap(false, .acq_rel)) {
                _ = self.hits.fetchAdd(1, .acq_rel);
                return error.ConcurrencyUnavailable;
            }
            return self.base.vtable.batchAwaitConcurrent(userdata, batch, timeout);
        }
        fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (self.owner.load(.acquire) == std.Thread.getCurrentId() and self.hits.load(.acquire) != 0) {
                self.paused.set(self.base);
                try self.permitted.wait(self.base);
            }
            return self.base.vtable.sleep(userdata, timeout);
        }
    };
    var finish: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn run(listener: *grpc.runtime.Server, io: std.Io, completed: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(4));
            defer connection.deinit();
            var watch = try connection.readStreamingWithTimeout(.fromSeconds(4), {}, consume);
            defer watch.deinit();
            var writer = try connection.startStreamingResponse(watch.transport.stream_id, .{});
            defer writer.deinit();
            const status = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(status);
            try writer.writeMessage(status);
            var application = try listener.acceptWithTimeout(.fromSeconds(4));
            defer application.deinit();
            var request = try application.readUnaryWithTimeout(.fromSeconds(4));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            try completed.wait(io);
            try writer.finishWithOptions(.{ .status = .unimplemented });
        }
    };
    var peer = try base.concurrent(Peer.run, .{ &server, base, &finish });
    defer _ = peer.cancel(base) catch {};
    var probe = Probe{ .base = base, .address = server.address() };
    Probe.active = &probe;
    defer Probe.active = null;
    var table = base.vtable.*;
    table.batchAwaitConcurrent = Probe.read;
    table.sleep = Probe.sleep;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var channel = try grpc.Channel.init(allocator, io, .{ .custom = .{ .context = &probe, .connect_fn = Probe.connect } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();
    const sync = channel.health_sync.?;
    const until: std.Io.Clock.Timestamp = .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(4) });
    while (true) {
        const generation = sync.snapshot();
        if (channel.healthServingAt(0) == true) break;
        if (until.durationFromNow(base).raw.nanoseconds <= 0) return error.Timeout;
        try sync.wait(base, generation, until);
    }
    probe.enabled.store(true, .release);
    try probe.paused.waitTimeout(base, .{ .deadline = until });
    try std.testing.expectEqual(@as(usize, 1), probe.hits.load(.acquire));
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    const watch = &channel.slots[0].health_gate.?.watch.?;
    try std.testing.expect(watch.watch != null);
    try std.testing.expectEqual(@as(u31, 1), watch.watch.?.stream.transport.streamId());
    var response = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .timeout = .{ .value = 2, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    probe.permitted.set(base);
    finish.set(base);
    try peer.await(base);
}
