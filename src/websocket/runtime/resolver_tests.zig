const std = @import("std");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "WebSocket URI resolver falls back and bypasses IP literals" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var unavailable = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    const unavailable_address = unavailable.socket.address;
    unavailable.deinit(io);

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([2][]const u8{ "/resolved", "/literal" }) |target| {
                var pending = try self.server.receiveUpgradeRequest(.{});
                try std.testing.expectEqualStrings(target, pending.target());
                var connection = try pending.accept();
                connection.close();
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const Resolver = struct {
        unavailable_address: net.IpAddress,
        server_address: net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "ws.resolver.test") or
                port != self.server_address.getPort() or deadline == null)
            {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(net.IpAddress, 2);
            addresses[0] = self.unavailable_address;
            addresses[1] = self.server_address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .unavailable_address = unavailable_address,
        .server_address = server.address(),
    };
    const resolver_option: runtime.AddressResolver = .{
        .context = &resolver,
        .resolve = Resolver.resolve,
    };
    const resolved_uri = try std.fmt.allocPrint(
        allocator,
        "ws://ws.resolver.test:{d}/resolved",
        .{server.address().getPort()},
    );
    defer allocator.free(resolved_uri);
    var resolved = try runtime.Client.connectUriWithTimeout(
        allocator,
        io,
        resolved_uri,
        .{
            .address_resolver = resolver_option,
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromSeconds(5),
            } },
        },
        .fromSeconds(3),
    );
    resolved.close();

    const literal_uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/literal",
        .{server.address().getPort()},
    );
    defer allocator.free(literal_uri);
    var literal = try runtime.Client.connectUriWithTimeout(
        allocator,
        io,
        literal_uri,
        .{ .address_resolver = resolver_option },
        .fromSeconds(3),
    );
    literal.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "WebSocket redirect chain retains resolver and caller deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var redirector = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer redirector.deinit();
    var destination = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer destination.deinit();
    const destination_uri = try std.fmt.allocPrint(
        allocator,
        "ws://redirect-b.resolver.test:{d}/final",
        .{destination.address().getPort()},
    );
    defer allocator.free(destination_uri);

    const RedirectWorker = struct {
        server: *runtime.Server,
        destination_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/start", pending.target());
            try pending.reject(
                302,
                "Found",
                &.{.{ .name = "Location", .value = self.destination_uri }},
                &.{},
            );
        }
    };
    const DestinationWorker = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequest(.{});
            try std.testing.expectEqualStrings("/final", pending.target());
            var connection = try pending.accept();
            connection.close();
        }
    };
    var redirect_worker = RedirectWorker{
        .server = &redirector,
        .destination_uri = destination_uri,
    };
    var destination_worker = DestinationWorker{ .server = &destination };
    const redirect_thread = try std.Thread.spawn(
        .{},
        RedirectWorker.run,
        .{&redirect_worker},
    );
    var redirect_joined = false;
    defer if (!redirect_joined) redirect_thread.join();
    const destination_thread = try std.Thread.spawn(
        .{},
        DestinationWorker.run,
        .{&destination_worker},
    );
    var destination_joined = false;
    defer if (!destination_joined) destination_thread.join();

    const Resolver = struct {
        redirect_address: net.IpAddress,
        destination_address: net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            const address = if (std.mem.eql(
                u8,
                host,
                "redirect-a.resolver.test",
            ))
                self.redirect_address
            else if (std.mem.eql(u8, host, "redirect-b.resolver.test"))
                self.destination_address
            else
                return error.UnknownHostName;
            if (address.getPort() != port or deadline == null) {
                return error.Timeout;
            }
            const addresses = try resolve_allocator.alloc(net.IpAddress, 1);
            addresses[0] = address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .redirect_address = redirector.address(),
        .destination_address = destination.address(),
    };
    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "ws://redirect-a.resolver.test:{d}/start",
        .{redirector.address().getPort()},
    );
    defer allocator.free(initial_uri);
    var connection = try runtime.Client.connectUriFollowingRedirectsWithTimeout(
        allocator,
        io,
        initial_uri,
        .{ .address_resolver = .{
            .context = &resolver,
            .resolve = Resolver.resolve,
        } },
        .{},
        .fromSeconds(3),
    );
    connection.close();

    redirect_thread.join();
    redirect_joined = true;
    destination_thread.join();
    destination_joined = true;
    if (redirect_worker.err) |err| return err;
    if (destination_worker.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));
}

test "WebSocket URI resolver consumes the caller deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Resolver = struct {
        never: std.Io.Event = .unset,
        saw_deadline: std.atomic.Value(bool) = .init(false),

        fn resolve(
            context: *anyopaque,
            _: std.mem.Allocator,
            resolve_io: std.Io,
            host: []const u8,
            _: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "deadline.ws.resolver.test")) {
                return error.UnknownHostName;
            }
            const absolute = deadline orelse return error.Timeout;
            self.saw_deadline.store(true, .release);
            self.never.waitTimeout(
                resolve_io,
                .{ .deadline = absolute },
            ) catch |err| return err;
            return error.UnknownHostName;
        }
    };
    var resolver = Resolver{};
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectUriWithTimeout(
            allocator,
            io,
            "ws://deadline.ws.resolver.test/",
            .{ .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            } },
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expect(resolver.saw_deadline.load(.acquire));
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
}
