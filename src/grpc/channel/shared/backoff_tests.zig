const std = @import("std");
const grpc = @import("../../mod.zig");
const http2 = @import("../../../http2/mod.zig");
const shared = @import("../shared.zig");
const support = @import("resolution/test_support.zig");
const allocator = std.testing.allocator;

const Connector = struct {
    address: std.Io.net.IpAddress,
    calls: std.atomic.Value(usize) = .init(0),
    refuse_first: bool = false,
    entered: ?*std.Io.Event = null,
    release: ?*std.Io.Event = null,

    fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
        const self: *Connector = @ptrCast(@alignCast(context.?));
        const previous = self.calls.fetchAdd(1, .acq_rel);
        if (self.refuse_first and previous == 0) {
            if (self.entered) |event| event.set(io);
            if (self.release) |event| try event.waitTimeout(io, .{ .deadline = deadline });
            return error.ConnectionRefused;
        }
        return http2.runtime.Client.connectWithDeadline(gpa, io, self.address, .{}, deadline);
    }

    fn endpoint(self: *Connector) grpc.ChannelEndpoint {
        return .{ .custom = .{ .context = self, .connect_fn = connect } };
    }
};

fn options() shared.Options {
    return .{ .channel = .{
        .selection_policy = .round_robin,
        .backoff = .{
            .initial_backoff = .fromSeconds(60),
            .max_backoff = .fromSeconds(60),
            .multiplier = 1,
            .jitter = 0,
            .min_connect_timeout = .fromSeconds(2),
        },
    } };
}

fn failed(watch: *grpc.ChannelConnectivityWatch) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(watch.tracker.io, .{
        .clock = .awake,
        .raw = .fromSeconds(3),
    });
    while (watch.snapshot().state != .transient_failure) {
        _ = try watch.nextWithDeadline(deadline);
    }
}

test "gRPC shared backoff reset retries failed endpoint and preserves healthy connection" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a.deinit();
    var b = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b.deinit();
    var a_peer = support.Peer{ .server = &a, .authority = "localhost", .reply = "A", .requests = 1 };
    var b_peer = support.Peer{ .server = &b, .authority = "localhost", .reply = "B", .requests = 2 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    var recovering = Connector{ .address = a.address(), .refuse_first = true };
    var healthy = Connector{ .address = b.address() };
    const endpoints = [_]grpc.ChannelEndpoint{ recovering.endpoint(), healthy.endpoint() };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, options());
    var live = true;
    defer if (live) client.deinit();
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try failed(&a_watch);
    try support.ready(&b_watch);
    var sender = client.sender();
    defer sender.deinit();
    var first = try sender.unary(.{ .path = "/demo.Shared/Unary", .authority = "localhost", .message = "before", .timeout = .{ .value = 3, .unit = .second } });
    defer first.deinit();
    try std.testing.expectEqualStrings("B", first.message.?.payload);
    try std.testing.expectEqual(@as(usize, 1), recovering.calls.load(.acquire));
    try client.resetConnectionBackoffWithTimeout(.fromSeconds(1));
    try a_watch.waitForReadyWithTimeout(.fromSeconds(3));
    var saw_a = false;
    var saw_b = false;
    for (0..2) |_| {
        var response = try sender.unary(.{ .path = "/demo.Shared/Unary", .authority = "localhost", .message = "after", .timeout = .{ .value = 3, .unit = .second } });
        defer response.deinit();
        saw_a = saw_a or std.mem.eql(u8, "A", response.message.?.payload);
        saw_b = saw_b or std.mem.eql(u8, "B", response.message.?.payload);
    }
    try std.testing.expect(saw_a and saw_b);
    try std.testing.expectEqual(@as(usize, 2), recovering.calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), healthy.calls.load(.acquire));
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared backoff reset bypasses failed DNS backoff and refresh throttling" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{server.address().getPort()});
    defer allocator.free(authority);
    var peer = support.Peer{ .server = &server, .authority = authority, .reply = "resolved", .requests = 1 };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const addresses = [_]std.Io.net.IpAddress{server.address()};
    var resolver = support.Resolver{ .addresses = &addresses, .failure = error.NameServerFailure };
    var opts = options();
    opts.channel.address_resolver = resolver.interface();
    opts.channel.resolver_min_refresh_interval = .fromSeconds(60);
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = server.address().getPort() } }, opts);
    var live = true;
    defer if (live) client.deinit();
    var watch = client.watchConnectivity();
    defer watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try failed(&watch);
    resolver.set(io, &addresses, null);
    try client.resetConnectionBackoff();
    try watch.waitForReadyWithTimeout(.fromSeconds(3));
    var sender = client.sender();
    defer sender.deinit();
    var response = try support.unary(sender, "recovered");
    defer response.deinit();
    try std.testing.expectEqualStrings("resolved", response.message.?.payload);
    try std.testing.expectEqual(@as(usize, 2), resolver.calls.load(.acquire));
    client.deinit();
    live = false;
    try task.await(io);
}

test "gRPC shared backoff reset preserves an in-progress connection attempt" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Peer{ .server = &server, .authority = "localhost", .reply = "preserved", .requests = 1 };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var entered: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var connector = Connector{ .address = server.address(), .refuse_first = true, .entered = &entered, .release = &release };
    var client = try shared.SharedChannel.init(allocator, io, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, options());
    var live = true;
    defer if (live) client.deinit();
    var watch = client.watchConnectivity();
    defer watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try support.wait(&entered, io);
    try client.resetConnectionBackoffWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 1), connector.calls.load(.acquire));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.connecting, client.connectivityState());
    release.set(io);
    try watch.waitForReadyWithTimeout(.fromSeconds(3));
    var sender = client.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = "/demo.Shared/Unary", .authority = "localhost", .message = "after", .timeout = .{ .value = 3, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqualStrings("preserved", response.message.?.payload);
    try std.testing.expectEqual(@as(usize, 2), connector.calls.load(.acquire));
    client.deinit();
    live = false;
    try task.await(io);
}

test "gRPC shared backoff reset keeps idle demand and validates closed and expired calls" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var connector = Connector{ .address = .{ .ip4 = .loopback(1) } };
    var client = try shared.SharedChannel.init(allocator, io, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, options());
    var sender = client.sender();
    defer sender.deinit();
    try client.resetConnectionBackoff();
    try client.resetConnectionBackoffWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.idle, client.connectivityState());
    try std.testing.expectEqual(@as(usize, 0), connector.calls.load(.acquire));
    try std.testing.expect(!client.state.demand);
    try std.testing.expectError(error.Timeout, client.resetConnectionBackoffWithTimeout(.zero));
    try std.testing.expectError(error.Timeout, client.resetConnectionBackoffWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) })));
    client.deinit();
    const retained = shared.SharedChannel{ .state = sender.state };
    try std.testing.expectError(error.SharedChannelClosed, retained.resetConnectionBackoff());
}
