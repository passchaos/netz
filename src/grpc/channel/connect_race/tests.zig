const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const allocator = support.allocator;

test "gRPC connection competition reaches a third endpoint while both earlier handshakes stall" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try support.Stalled.init(io, false);
    defer a.deinit(io);
    var b = try support.Stalled.init(io, false);
    defer b.deinit(io);
    var a_task = io.async(support.Stalled.run, .{ &a, io });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Stalled.run, .{ &b, io });
    defer _ = b_task.cancel(io) catch {};
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Echo{ .server = .{ .tcp = &server } };
    var peer_task = io.async(support.Echo.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};
    const targets = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a.address() } },
        .{ .cleartext_ip = .{ .address = b.address() } },
        .{ .cleartext_ip = .{ .address = server.address() } },
    };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &targets } }, .{});
    var live = true;
    defer if (live) channel.deinit();
    var first = try support.unary(&channel);
    defer first.deinit();
    try std.testing.expectEqualStrings("pong", first.message.?.payload);
    try support.wait(&a.closed, io);
    try support.wait(&b.closed, io);
    try a_task.await(io);
    try b_task.await(io);
    var second = try support.unary(&channel);
    defer second.deinit();
    try std.testing.expectEqualStrings("pong", second.message.?.payload);
    try std.testing.expectEqual(@as(?usize, 2), channel.selected_index);
    // Owned responses must remain usable after connector-allocator teardown.
    channel.deinit();
    live = false;
    try std.testing.expectEqualStrings("pong", first.message.?.payload);
    try peer_task.await(io);
}

test "gRPC connection competition skips the launch delay after an immediate failure" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Echo{ .server = .{ .tcp = &server } };
    var task = io.async(support.Echo.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const Failed = struct {
        calls: std.atomic.Value(usize) = .init(0),
        fn connect(pointer: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../../http2/mod.zig").runtime.Error!@import("../../../http2/mod.zig").runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(pointer.?));
            _ = self.calls.fetchAdd(1, .monotonic);
            return error.ConnectionRefused;
        }
    };
    var failed: Failed = .{};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .custom = .{ .context = &failed, .connect_fn = Failed.connect } },
        .{ .cleartext_ip = .{ .address = server.address() } },
    };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .connection_attempt_delay = .fromSeconds(5) });
    defer channel.deinit();
    for (0..2) |_| {
        var response = try support.unary(&channel);
        defer response.deinit();
        try std.testing.expectEqualStrings("pong", response.message.?.payload);
    }
    try std.testing.expectEqual(@as(usize, 1), failed.calls.load(.acquire));
    try task.await(io);
}

test "gRPC connection competition cancels pending handshakes before its operation deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try support.Stalled.init(io, false);
    defer a.deinit(io);
    var b = try support.Stalled.init(io, false);
    defer b.deinit(io);
    var peer = io.async(support.Stalled.run, .{ &a, io });
    defer _ = peer.cancel(io) catch {};
    const targets = [_]grpc.ChannelEndpoint{ .{ .cleartext_ip = .{ .address = a.address() } }, .{ .cleartext_ip = .{ .address = b.address() } } };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &targets } }, .{ .connection_attempt_delay = .fromSeconds(5) });
    defer channel.deinit();
    const Call = struct {
        channel: *grpc.Channel,
        done: std.Io.Event = .unset,
        result: ?anyerror = null,
        fn run(self: *@This()) void {
            defer self.done.set(self.channel.io);
            _ = self.channel.connectWithDeadline(.fromNow(self.channel.io, .{ .raw = .fromSeconds(10), .clock = .awake })) catch |err| {
                self.result = err;
                return;
            };
        }
    };
    var call = Call{ .channel = &channel };
    var task = io.async(Call.run, .{&call});
    defer task.cancel(io);
    try support.wait(&a.started, io);
    channel.cancelWaits();
    try support.wait(&call.done, io);
    task.await(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), call.result);
    try std.testing.expectEqual(grpc.ChannelConnectivityState.transient_failure, channel.connectivityState());
    try support.wait(&a.closed, io);
    try peer.await(io);
}

test "gRPC connection competition retries a per-attempt timeout under its original RPC budget" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Echo{ .server = .{ .tcp = &server }, .requests = 1 };
    var task = io.async(support.Echo.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const Connector = struct {
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(usize) = .init(0),
        fn connect(pointer: ?*anyopaque, gpa: std.mem.Allocator, child_io: std.Io, until: std.Io.Clock.Timestamp) @import("../../../http2/mod.zig").runtime.Error!@import("../../../http2/mod.zig").runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(pointer.?));
            if (self.calls.fetchAdd(1, .monotonic) == 0) {
                try until.wait(child_io);
                return error.Timeout;
            }
            return @import("../../../http2/mod.zig").runtime.Client.connectWithDeadline(gpa, child_io, self.address, .{}, until);
        }
        fn refuse(_: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../../http2/mod.zig").runtime.Error!@import("../../../http2/mod.zig").runtime.Connection {
            return error.ConnectionRefused;
        }
    };
    var connector = Connector{ .address = server.address() };
    const endpoints = [_]grpc.ChannelEndpoint{ .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, .{ .custom = .{ .context = null, .connect_fn = Connector.refuse } } };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .connection_attempt_delay = .fromMilliseconds(5),
        .backoff = .{ .initial_backoff = .fromMilliseconds(10), .max_backoff = .fromMilliseconds(10), .multiplier = 1, .jitter = 0, .min_connect_timeout = .fromMilliseconds(40) },
    });
    defer channel.deinit();
    var response = try support.unary(&channel);
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    try std.testing.expectEqual(@as(usize, 2), connector.calls.load(.acquire));
    try task.await(io);
}

test "gRPC connection competition rejects unavailable concurrency before invoking connectors" {
    var threaded = std.Io.Threaded.init(allocator, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    const Connector = struct {
        calls: usize = 0,
        fn connect(pointer: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../../http2/mod.zig").runtime.Error!@import("../../../http2/mod.zig").runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(pointer.?));
            self.calls += 1;
            return error.ConnectionRefused;
        }
    };
    var connector: Connector = .{};
    const endpoint: grpc.ChannelEndpoint = .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } };
    const endpoints = [_]grpc.ChannelEndpoint{ endpoint, endpoint };
    var channel = try grpc.Channel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{});
    defer channel.deinit();
    try std.testing.expectError(error.ConcurrencyUnavailable, channel.connectWithDeadline(.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake })));
    try std.testing.expectEqual(@as(usize, 0), connector.calls);
    try std.testing.expectEqual(grpc.ChannelConnectivityState.transient_failure, channel.connectivityState());
}

test "gRPC connection competition validates its delay before allocation" {
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const target: grpc.ChannelTarget = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(9) } } };
    for ([_]std.Io.Duration{ .zero, .fromNanoseconds(-1) }) |delay| {
        try std.testing.expectError(error.InvalidChannelOptions, grpc.Channel.init(failing.allocator(), undefined, target, .{ .connection_attempt_delay = delay }));
        try std.testing.expectError(error.InvalidChannelOptions, grpc.SharedChannel.init(failing.allocator(), undefined, target, .{ .channel = .{ .connection_attempt_delay = delay } }));
    }
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(i96, 250 * std.time.ns_per_ms), (grpc.ChannelOptions{}).connection_attempt_delay.?.nanoseconds);
}
