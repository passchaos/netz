const std = @import("std");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "MQTT URI resolver falls back and bypasses IP literals" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
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
            for ([2][]const u8{ "resolved-mqtt", "literal-mqtt" }) |client_id| {
                var accepted = try self.server.accept(.{ .protocol = .v5 });
                try std.testing.expectEqualStrings(
                    client_id,
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
                accepted.deinit(self.server.allocator);
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
            if (!std.mem.eql(u8, host, "mqtt.resolver.test") or
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
        "mqtt://mqtt.resolver.test:{d}",
        .{server.address().getPort()},
    );
    defer allocator.free(resolved_uri);
    var resolved = try runtime.Client.connectUriWithTimeout(
        allocator,
        io,
        resolved_uri,
        .{
            .client_id = "resolved-mqtt",
            .address_resolver = resolver_option,
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromSeconds(5),
            } },
        },
        .fromSeconds(3),
    );
    try resolved.disconnect(0);
    resolved.close();

    const literal_uri = try std.fmt.allocPrint(
        allocator,
        "mqtt://127.0.0.1:{d}",
        .{server.address().getPort()},
    );
    defer allocator.free(literal_uri);
    var literal = try runtime.Client.connectUriWithTimeout(
        allocator,
        io,
        literal_uri,
        .{
            .client_id = "literal-mqtt",
            .address_resolver = resolver_option,
        },
        .fromSeconds(3),
    );
    try literal.disconnect(0);
    literal.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "MQTT URI resolver consumes the caller deadline" {
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
            if (!std.mem.eql(u8, host, "deadline.mqtt.resolver.test")) {
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
            "mqtt://deadline.mqtt.resolver.test",
            .{
                .client_id = "deadline-mqtt",
                .address_resolver = .{
                    .context = &resolver,
                    .resolve = Resolver.resolve,
                },
            },
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expect(resolver.saw_deadline.load(.acquire));
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
}
