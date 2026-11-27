const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const Broker = context.BrokerType;

test "MQTT listener connection end observer preserves transport close policy and borrowed identity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{ .limits = .{ .max_connections = 1, .max_queued_deliveries_per_connection = 1, .runtime = .{ .max_packet_size = 4096 } } });
    defer broker.deinit();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();
    const Observer = struct {
        broker: *Broker,
        observed: std.Io.Event = .unset,
        client_id: [64]u8 = undefined,
        len: usize = 0,
        event: ?mqtt.broker.ListenerConnectionEndEvent = null,
        count: std.atomic.Value(usize) = .init(0),
        errors: std.atomic.Value(usize) = .init(0),

        fn end(ptr: *anyopaque, value: mqtt.broker.ListenerConnectionEndEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            // Re-entering stats proves the callback runs outside the state lock.
            _ = self.broker.stats();
            @memcpy(self.client_id[0..value.client_id.len], value.client_id);
            self.len = value.client_id.len;
            self.event = value;
            self.event.?.client_id = self.client_id[0..self.len];
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.broker.io);
        }
        fn errorEvent(ptr: *anyopaque, _: mqtt.broker.ListenerErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            _ = self.errors.fetchAdd(1, .release);
        }
    };
    const Serve = struct {
        broker: *Broker,
        endpoint: mqtt.broker.ListenerEndpoint,
        observer: *Observer,
        shutdown: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.broker.serveListenersUntil(&.{self.endpoint}, .{
                .shutdown = &self.shutdown,
                .connection_error_policy = .stop,
                .error_observer = .{ .context = self.observer, .observe = Observer.errorEvent },
                .connection_end_observer = .{ .context = self.observer, .observe = Observer.end },
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var observer = Observer{ .broker = &broker };
    var serving = Serve{ .broker = &broker, .endpoint = .{ .source = server.pendingSource() }, .observer = &observer };
    const thread = try std.Thread.spawn(.{}, Serve.run, .{&serving});
    defer {
        serving.shutdown.set(io);
        thread.join();
    }
    var first = try runtime.Client.connect(allocator, io, server.address(), .{ .protocol = .v5, .client_id = "observed-close" });
    try first.ping();
    first.close();
    try observer.observed.wait(io);
    try std.testing.expectEqualStrings("observed-close", observer.client_id[0..observer.len]);
    try std.testing.expectEqual(@as(usize, 1), observer.count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), observer.errors.load(.acquire));
    try std.testing.expect(observer.event.?.read_error != null);
    try std.testing.expect(!observer.event.?.graceful_disconnect);
    try std.testing.expect(!observer.event.?.keep_alive_timed_out);
    // Cleanup follows observation; wait for the slot to become reusable.
    for (0..2000) |_| {
        if (broker.stats().active_connections == 0) break;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    var second = try runtime.Client.connect(allocator, io, server.address(), .{ .protocol = .v5, .client_id = "healthy-after-observed-close" });
    defer second.close();
    try second.ping();
    observer.observed.reset();
    try second.disconnect(0);
    try observer.observed.wait(io);
    try std.testing.expectEqualStrings("healthy-after-observed-close", observer.client_id[0..observer.len]);
    try std.testing.expectEqual(@as(usize, 2), observer.count.load(.acquire));
    try std.testing.expect(observer.event.?.graceful_disconnect);
    try std.testing.expectEqual(@as(usize, 0), observer.errors.load(.acquire));
    try std.testing.expect(serving.err == null);
}
