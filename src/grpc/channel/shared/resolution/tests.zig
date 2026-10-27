const std = @import("std");
const support = @import("test_support.zig");
const grpc = support.grpc;
const shared = support.shared;
const allocator = support.allocator;

test {
    _ = @import("allocation_failure_tests.zig");
}

test "gRPC shared hostname expands unique addresses and retains connections across reorder" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    const port = a_server.address().getPort();
    const authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{port});
    defer allocator.free(authority);
    var a_peer = support.Peer{ .server = &a_server, .authority = authority, .reply = "A", .requests = 3 };
    var b_peer = support.Peer{ .server = &b_server, .authority = authority, .reply = "B", .requests = 3 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const initial = [_]support.Address{ a_server.address(), b_server.address(), a_server.address() };
    const reordered = [_]support.Address{ b_server.address(), a_server.address() };
    var resolver = support.Resolver{ .addresses = &initial };
    var opts = support.options(&resolver);
    opts.channel.selection_policy = .round_robin;
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = port } }, opts);
    var live = true;
    defer if (live) client.deinit();
    try std.testing.expectEqual(@as(usize, 0), client.endpointCount());
    try std.testing.expectEqual(@as(usize, 0), resolver.calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), try client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try support.ready(&a_watch);
    try support.ready(&b_watch);
    var sender = client.sender();
    defer sender.deinit();
    for ([_][]const u8{ "A", "B", "A", "B" }) |expected| {
        var reply = try support.unary(sender, "before");
        defer reply.deinit();
        try std.testing.expectEqualStrings(expected, reply.message.?.payload);
    }
    resolver.set(io, &reordered, null);
    try std.testing.expectEqual(@as(usize, 2), try client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    for ([_][]const u8{ "B", "A" }) |expected| {
        var reply = try support.unary(sender, "after");
        defer reply.deinit();
        try std.testing.expectEqualStrings(expected, reply.message.?.payload);
    }
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC shared hostname keeps healthy membership on failure and drains an empty update" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const port = server.address().getPort();
    const authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{port});
    defer allocator.free(authority);
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var peer = support.Peer{ .server = &server, .authority = authority, .reply = "kept", .requests = 3, .admitted = &admitted, .release = &release };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    const addresses = [_]support.Address{server.address()};
    var resolver = support.Resolver{ .addresses = &addresses };
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = port } }, support.options(&resolver));
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var first = try support.unary(sender, "first");
    defer first.deinit();
    var watch = client.watchEndpointConnectivity(0).?;
    defer watch.deinit();
    resolver.set(io, &addresses, error.NameServerFailure);
    try std.testing.expectError(error.NameServerFailure, client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, client.connectivityState());
    var second = try support.unary(sender, "after-failure");
    defer second.deinit();
    var pending = try io.concurrent(support.unary, .{ sender, "active" });
    defer _ = pending.cancel(io) catch {};
    try support.wait(&admitted, io);
    resolver.set(io, &.{}, null);
    try std.testing.expectError(error.NoAddressReturned, client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    try std.testing.expectEqual(@as(usize, 0), client.endpointCount());
    try std.testing.expectEqual(grpc.ChannelConnectivityState.shutdown, (try watch.nextWithTimeout(.fromSeconds(5))).state);
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/demo.Shared/Unary", .message = "new", .wait_for_ready = false }));
    release.set(io);
    var final = try pending.await(io);
    defer final.deinit();
    try std.testing.expectEqualStrings("kept", final.message.?.payload);
    // The removed owner closes its transport and is reclaimed before the
    // SharedChannel itself is destroyed.
    try task.await(io);
}

test "gRPC shared hostname candidate waits for health while removed active RPC drains" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var active_admitted: std.Io.Event = .unset;
    var release_active: std.Io.Event = .unset;
    var b_health: std.Io.Event = .unset;
    var b_serving: std.Io.Event = .unset;
    const Peer = struct {
        fn a(server: *grpc.runtime.Server, admitted: *std.Io.Event, release: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var health = try connection.readStreamingWithTimeout(.fromSeconds(5), {}, support.healthRequest);
            defer health.deinit();
            var writer = try connection.startStreamingResponse(health.transport.stream_id, .{});
            defer writer.deinit();
            try support.serving(&writer);
            var warm = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer warm.deinit();
            try connection.writeUnary(warm.request.stream_id, .{ .message = "warm" });
            var active = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer active.deinit();
            admitted.set(connection.connection.io);
            var pending = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer pending.deinit();
            try connection.writeUnary(pending.request.stream_id, .{ .message = "old-ready" });
            try support.wait(release, connection.connection.io);
            try connection.writeUnary(active.request.stream_id, .{ .message = "active-finished" });
            try support.healthClosed(&connection, &writer, health.transport.stream_id);
            try support.closed(&connection);
        }
        fn b(server: *grpc.runtime.Server, entered: *std.Io.Event, serving: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var health = try connection.readStreamingWithTimeout(.fromSeconds(5), {}, support.healthRequest);
            defer health.deinit();
            var writer = try connection.startStreamingResponse(health.transport.stream_id, .{});
            defer writer.deinit();
            entered.set(connection.connection.io);
            try support.wait(serving, connection.connection.io);
            try support.serving(&writer);
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = "new-ready" });
            try support.healthClosed(&connection, &writer, health.transport.stream_id);
        }
    };
    var a_task = io.async(Peer.a, .{ &a_server, &active_admitted, &release_active });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Peer.b, .{ &b_server, &b_health, &b_serving });
    defer _ = b_task.cancel(io) catch {};
    const first = [_]support.Address{a_server.address()};
    const second = [_]support.Address{b_server.address()};
    var resolver = support.Resolver{ .addresses = &first };
    var opts = support.options(&resolver);
    opts.health_service = "demo.Shared";
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = a_server.address().getPort() } }, opts);
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var warm = try support.unary(sender, "warm");
    defer warm.deinit();
    var old_watch = client.watchEndpointConnectivity(0).?;
    defer old_watch.deinit();
    var active = try io.concurrent(support.unary, .{ sender, "active" });
    defer _ = active.cancel(io) catch {};
    try support.wait(&active_admitted, io);
    resolver.set(io, &second, null);
    try std.testing.expectEqual(@as(usize, 1), try client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    try support.wait(&b_health, io);
    var new_watch = client.watchEndpointConnectivity(0).?;
    defer new_watch.deinit();
    var pending = try support.unary(sender, "while-pending");
    defer pending.deinit();
    try std.testing.expectEqualStrings("old-ready", pending.message.?.payload);
    b_serving.set(io);
    try support.ready(&new_watch);
    while ((try old_watch.nextWithTimeout(.fromSeconds(5))).state != .shutdown) {}
    var next = try support.unary(sender, "new");
    defer next.deinit();
    try std.testing.expectEqualStrings("new-ready", next.message.?.payload);
    release_active.set(io);
    var result = try active.await(io);
    defer result.deinit();
    try std.testing.expectEqualStrings("active-finished", result.message.?.payload);
    try a_task.await(io);
    client.deinit();
    live = false;
    try b_task.await(io);
}

test "gRPC shared hostname shutdown joins a blocked resolver after queued deadlines" {
    const Blocking = struct {
        entered: std.Io.Event = .unset,
        stopped: std.Io.Event = .unset,
        block: std.Io.Event = .unset,
        fn resolve(context: *anyopaque, _: std.mem.Allocator, io: std.Io, _: []const u8, _: u16, _: ?std.Io.Clock.Timestamp) grpc.ChannelAddressResolver.ResolveError![]support.Address {
            const self: *@This() = @ptrCast(@alignCast(context));
            defer self.stopped.set(io);
            self.entered.set(io);
            try self.block.wait(io);
            return error.NoAddressReturned;
        }
    };
    // The resolver must retain real concurrency even when async() would run
    // inline. It waits for the manager to acknowledge each published result.
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .limited(0) });
    defer threaded.deinit();
    const io = threaded.io();
    var blocking: Blocking = .{};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = 80 } }, .{ .channel = .{ .address_resolver = .{ .context = &blocking, .resolve = Blocking.resolve } } });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    client.connect();
    try support.wait(&blocking.entered, io);
    try std.testing.expectError(error.Timeout, sender.unary(.{ .path = "/demo.Shared/Unary", .message = "queued", .wait_for_ready = true, .timeout = .{ .value = 10, .unit = .millisecond } }));
    try std.testing.expectError(error.Timeout, client.refreshNameResolutionWithTimeout(.fromMilliseconds(10)));
    try std.testing.expect(!blocking.stopped.isSet());
    client.deinit();
    live = false;
    try std.testing.expect(blocking.stopped.isSet());
    try std.testing.expectError(error.SharedChannelClosed, support.unary(sender, "closed"));
}

test "gRPC shared hostname constructor and resolver admission release owned state" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var resolver = support.Resolver{ .addresses = &.{} };
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, io: std.Io, resolver_ptr: *support.Resolver) !void {
            var opts = support.options(resolver_ptr);
            opts.service_config_json = "{\"healthCheckConfig\":{\"serviceName\":\"demo.Shared\"}}";
            var client = try shared.SharedChannel.init(gpa, io, .{ .cleartext_host = .{ .host = "resolve.test", .port = 80 } }, opts);
            defer client.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{ threaded.io(), &resolver });
    try std.testing.expectEqual(@as(usize, 0), resolver.calls.load(.acquire));
    var limited = std.Io.Threaded.init(allocator, .{ .async_limit = .limited(0), .concurrent_limit = .limited(1) });
    defer limited.deinit();
    var client = try shared.SharedChannel.init(allocator, limited.io(), .{ .cleartext_host = .{ .host = "resolve.test", .port = 80 } }, support.options(&resolver));
    defer client.deinit();
    try std.testing.expectError(error.ConcurrencyUnavailable, client.refreshNameResolutionWithTimeout(.fromSeconds(1)));
    try std.testing.expectEqual(grpc.ChannelConnectivityState.transient_failure, client.connectivityState());
    try std.testing.expectEqual(@as(usize, 0), resolver.calls.load(.acquire));
}

test "gRPC shared hostname sources coexist with static endpoints and preserve authorities" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var c_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer c_server.deinit();
    const a_authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{a_server.address().getPort()});
    defer allocator.free(a_authority);
    const b_authority = try std.fmt.allocPrint(allocator, "resolve.test:{d}", .{b_server.address().getPort()});
    defer allocator.free(b_authority);
    var a_peer = support.Peer{ .server = &a_server, .authority = a_authority, .reply = "A", .requests = 1 };
    var b_peer = support.Peer{ .server = &b_server, .authority = b_authority, .reply = "B", .requests = 1 };
    var c_peer = support.Peer{ .server = &c_server, .authority = "static.test", .reply = "C", .requests = 1 };
    var a_task = io.async(support.Peer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(support.Peer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    var c_task = io.async(support.Peer.run, .{&c_peer});
    defer _ = c_task.cancel(io) catch {};
    const Routes = struct {
        addresses: [2]support.Address,
        fn resolve(context: *anyopaque, gpa: std.mem.Allocator, _: std.Io, _: []const u8, port: u16, _: ?std.Io.Clock.Timestamp) grpc.ChannelAddressResolver.ResolveError![]support.Address {
            const self: *@This() = @ptrCast(@alignCast(context));
            for (self.addresses) |address| if (address.getPort() == port) return gpa.dupe(support.Address, &.{address});
            return error.NoAddressReturned;
        }
    };
    var routes = Routes{ .addresses = .{ a_server.address(), b_server.address() } };
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_host = .{ .host = "resolve.test", .port = a_server.address().getPort() } },
        .{ .cleartext_ip = .{ .address = c_server.address(), .authority = "static.test" } },
        .{ .cleartext_host = .{ .host = "resolve.test", .port = b_server.address().getPort() } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints, .policy = .round_robin } }, .{ .channel = .{ .address_resolver = .{ .context = &routes, .resolve = Routes.resolve } } });
    var live = true;
    defer if (live) client.deinit();
    try std.testing.expectEqual(@as(usize, 3), try client.refreshNameResolutionWithTimeout(.fromSeconds(5)));
    for (0..3) |index| {
        var watch = client.watchEndpointConnectivity(index).?;
        defer watch.deinit();
        try support.ready(&watch);
    }
    var sender = client.sender();
    defer sender.deinit();
    for ([_][]const u8{ "A", "C", "B" }) |expected| {
        var reply = try support.unary(sender, "mixed");
        defer reply.deinit();
        try std.testing.expectEqualStrings(expected, reply.message.?.payload);
    }
    client.deinit();
    live = false;
    try a_task.await(io);
    try b_task.await(io);
    try c_task.await(io);
}

test "gRPC shared owner retries connector cancellation without losing membership" {
    const http2 = @import("../../../../http2/mod.zig");
    const Connector = struct {
        address: support.Address,
        calls: std.atomic.Value(usize) = .init(0),
        fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.calls.fetchAdd(1, .monotonic) == 0) return error.Canceled;
            var connection = try http2.runtime.Client.connectWithDeadline(gpa, io, self.address, .{}, deadline);
            errdefer connection.close();
            try connection.replaceDefaultAuthority("static.test");
            return connection;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var peer = support.Peer{ .server = &server, .authority = "static.test", .reply = "reconnected", .requests = 1 };
    var task = io.async(support.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var connector = Connector{ .address = server.address() };
    var client = try shared.SharedChannel.init(allocator, io, .{ .custom = .{ .context = &connector, .connect_fn = Connector.connect } }, .{ .channel = .{ .backoff = .{ .initial_backoff = .fromMilliseconds(50), .max_backoff = .fromMilliseconds(50), .multiplier = 1, .jitter = 0 } } });
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var reply = try support.unary(sender, "retry");
    defer reply.deinit();
    try std.testing.expectEqualStrings("reconnected", reply.message.?.payload);
    try std.testing.expectEqual(@as(usize, 2), connector.calls.load(.acquire));
    client.deinit();
    live = false;
    try task.await(io);
}
