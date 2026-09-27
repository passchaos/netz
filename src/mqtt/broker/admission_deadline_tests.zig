const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const broker_mod = mqtt.broker;
const runtime = context.runtime_mod;
const Broker = context.BrokerType;
const ServeState = context.ServeStateType;
const joinServer = context.joinServerFn;

const authentication_method = "deadline-auth";
const authentication_properties = [_]mqtt.Property{.{ .utf8 = .{
    .id = .authentication_method,
    .value = authentication_method,
} }};
const authentication_response = [_]mqtt.Property{
    .{ .utf8 = .{
        .id = .authentication_method,
        .value = authentication_method,
    } },
    .{ .binary = .{
        .id = .authentication_data,
        .value = "response",
    } },
};

const ClientAttempt = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    use_authentication: bool = true,
    authentication: ?runtime.ClientAuthHandler = null,
    accepted: bool = false,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        var attempt = runtime.Client.connectAttemptWithTimeout(
            self.allocator,
            self.io,
            self.address,
            .{
                .protocol = .v5,
                .client_id = self.client_id,
                .properties = if (self.use_authentication)
                    &authentication_properties
                else
                    &.{},
                .authentication = self.authentication,
            },
            .fromSeconds(1),
        ) catch |err| {
            self.err = err;
            return;
        };
        defer attempt.deinit(self.allocator);
        self.accepted = attempt.accepted();
    }
};

fn expectIdle(broker: *Broker) !void {
    const stats = broker.stats();
    try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.sessions);
    try std.testing.expectEqual(@as(usize, 0), stats.subscriptions);
    try std.testing.expectEqual(@as(usize, 0), stats.scheduled_wills);
}

fn unusedAuthenticationHandler(
    _: *anyopaque,
    _: *runtime.Connection,
    _: mqtt.Auth,
    _: bool,
) broker_mod.Error!void {
    return error.AuthenticationFailed;
}

test "broker CONNECT timeout spans authentication policy and response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Authentication = struct {
        io: std.Io,
        starts: std.atomic.Value(u32) = .init(0),

        fn start(
            context_ptr: *anyopaque,
            pending: *runtime.PendingAcceptedClient,
        ) broker_mod.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            const invocation = self.starts.fetchAdd(1, .acq_rel);
            if (invocation == 0) {
                try std.Io.sleep(self.io, .fromMilliseconds(75), .awake);
                try pending.challengeAuthentication("late-challenge");
            }
            try pending.authorizeAuthentication();
        }
    };
    var authentication = Authentication{ .io = io };
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .connect_timeout = .fromMilliseconds(50),
            },
            .authentication = .{
                .context = &authentication,
                .start = Authentication.start,
                .handle = unusedAuthenticationHandler,
            },
        },
    );
    defer broker.deinit();

    var client = ClientAttempt{
        .allocator = allocator,
        .io = io,
        .address = broker.address(),
        .client_id = "slow-broker-auth",
    };
    var client_future = try std.Io.concurrent(io, ClientAttempt.run, .{&client});
    var client_done = false;
    defer if (!client_done) client_future.cancel(io);

    try std.testing.expectError(error.Timeout, broker.serve(1));
    client_future.await(io);
    client_done = true;
    try std.testing.expectEqual(
        @as(u32, 1),
        authentication.starts.load(.acquire),
    );
    try std.testing.expect(!client.accepted);
    try expectIdle(&broker);

    var recovery_serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const recovery_thread = try std.Thread.spawn(
        .{},
        ServeState.run,
        .{&recovery_serve},
    );
    var recovery_joined = false;
    defer if (!recovery_joined) recovery_thread.join();

    var recovered = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "recovered-broker-auth",
            .properties = &authentication_properties,
        },
        .fromSeconds(1),
    );
    defer recovered.close();
    try recovered.pingWithTimeout(.fromSeconds(1));
    try recovered.disconnect(0);
    try joinServer(recovery_thread, &recovery_joined, &recovery_serve);

    try std.testing.expectEqual(
        @as(u32, 2),
        authentication.starts.load(.acquire),
    );
    try expectIdle(&broker);
}

test "broker CONNECT timeout bounds authentication response wait" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Authentication = struct {
        allocator: std.mem.Allocator,
        started: std.atomic.Value(bool) = .init(false),

        fn start(
            context_ptr: *anyopaque,
            pending: *runtime.PendingAcceptedClient,
        ) broker_mod.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.started.store(true, .release);
            try pending.challengeAuthentication("challenge");
            var response = try pending.receiveAuthentication();
            defer response.deinit(self.allocator);
            try pending.authorizeAuthentication();
        }
    };
    const Response = struct {
        io: std.Io,
        called: std.atomic.Value(bool) = .init(false),

        fn respond(
            context_ptr: *anyopaque,
            _: mqtt.Auth,
        ) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.called.store(true, .release);
            try std.Io.sleep(self.io, .fromMilliseconds(75), .awake);
            return &authentication_response;
        }
    };
    var authentication = Authentication{ .allocator = allocator };
    var response = Response{ .io = io };
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .connect_timeout = .fromMilliseconds(50),
            },
            .authentication = .{
                .context = &authentication,
                .start = Authentication.start,
                .handle = unusedAuthenticationHandler,
            },
        },
    );
    defer broker.deinit();

    var client = ClientAttempt{
        .allocator = allocator,
        .io = io,
        .address = broker.address(),
        .client_id = "slow-auth-response",
        .authentication = .{
            .context = &response,
            .respond = Response.respond,
        },
    };
    var client_future = try std.Io.concurrent(io, ClientAttempt.run, .{&client});
    var client_done = false;
    defer if (!client_done) client_future.cancel(io);

    try std.testing.expectError(error.Timeout, broker.serve(1));
    client_future.await(io);
    client_done = true;
    try std.testing.expect(authentication.started.load(.acquire));
    try std.testing.expect(response.called.load(.acquire));
    try std.testing.expect(!client.accepted);
    try expectIdle(&broker);
}

test "broker CONNECT timeout bounds successful CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Authentication = struct {
        io: std.Io,
        started: std.atomic.Value(bool) = .init(false),

        fn start(
            context_ptr: *anyopaque,
            pending: *runtime.PendingAcceptedClient,
        ) broker_mod.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.started.store(true, .release);
            try std.Io.sleep(self.io, .fromMilliseconds(75), .awake);
            try pending.authorizeAuthentication();
        }
    };
    var authentication = Authentication{ .io = io };
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .connect_timeout = .fromMilliseconds(50),
            },
            .authentication = .{
                .context = &authentication,
                .start = Authentication.start,
                .handle = unusedAuthenticationHandler,
            },
        },
    );
    defer broker.deinit();

    var client = ClientAttempt{
        .allocator = allocator,
        .io = io,
        .address = broker.address(),
        .client_id = "late-successful-connack",
    };
    var client_future = try std.Io.concurrent(io, ClientAttempt.run, .{&client});
    var client_done = false;
    defer if (!client_done) client_future.cancel(io);

    try std.testing.expectError(error.Timeout, broker.serve(1));
    client_future.await(io);
    client_done = true;
    try std.testing.expect(authentication.started.load(.acquire));
    try std.testing.expect(!client.accepted);
    try expectIdle(&broker);
}

test "broker CONNECT timeout bounds refusal CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Authorization = struct {
        io: std.Io,
        called: std.atomic.Value(bool) = .init(false),

        fn authorize(
            context_ptr: *anyopaque,
            _: mqtt.Connect,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.called.store(true, .release);
            std.Io.sleep(self.io, .fromMilliseconds(75), .awake) catch {};
            return false;
        }
    };
    var authorization = Authorization{ .io = io };
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .connect_timeout = .fromMilliseconds(50),
            },
            .connect_authorization = .{
                .context = &authorization,
                .authorize = Authorization.authorize,
            },
        },
    );
    defer broker.deinit();

    var client = ClientAttempt{
        .allocator = allocator,
        .io = io,
        .address = broker.address(),
        .client_id = "late-refusal-connack",
        .use_authentication = false,
    };
    var client_future = try std.Io.concurrent(io, ClientAttempt.run, .{&client});
    var client_done = false;
    defer if (!client_done) client_future.cancel(io);

    try std.testing.expectError(error.Timeout, broker.serve(1));
    client_future.await(io);
    client_done = true;
    try std.testing.expect(authorization.called.load(.acquire));
    try std.testing.expect(!client.accepted);
    try expectIdle(&broker);
}
