const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");

const Error = runtime.Error;
const Server = runtime.Server;
const Client = runtime.Client;

test "MQTT enhanced authentication connects and reauthenticates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const method = "mirror";
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self.server) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var pending = try server_ptr.acceptPending(.{
                .protocol = .v5,
            });
            var pending_owned = true;
            defer if (pending_owned) {
                pending.deinit(server_ptr.allocator);
            };
            try std.testing.expectEqualStrings(
                method,
                mqtt.authenticationMethod(
                    pending.connect.connect.properties,
                ).?,
            );
            try std.testing.expectEqualStrings(
                "step1",
                mqtt.authenticationData(
                    pending.connect.connect.properties,
                ).?,
            );
            try pending.challengeAuthentication("1pets");
            var response = try pending.receiveAuthentication();
            defer response.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "supercalifragilisticexpialidocious",
                mqtt.authenticationData(
                    response.auth.properties,
                ).?,
            );
            try pending.authorizeAuthenticationWithData(
                "initial-final",
            );
            var accepted = try pending.finish(.{ .protocol = .v5 });
            pending_owned = false;
            defer accepted.deinit(server_ptr.allocator);

            var reauth = try accepted.connection.acceptReauthentication();
            defer reauth.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "step1",
                mqtt.authenticationData(reauth.auth.properties).?,
            );
            try accepted.connection.continueReauthentication(
                0x18,
                "1pets",
            );
            var client_response =
                try accepted.connection.receiveReauthentication();
            defer client_response.auth.deinit(server_ptr.allocator);
            try std.testing.expect(!client_response.complete);
            try std.testing.expectEqualStrings(
                "supercalifragilisticexpialidocious",
                mqtt.authenticationData(
                    client_response.auth.auth.properties,
                ).?,
            );
            try accepted.connection.continueReauthentication(
                0,
                "server-final",
            );
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
        }
    };

    const Handler = struct {
        calls: usize = 0,

        fn respond(
            context_ptr: *anyopaque,
            challenge: mqtt.Auth,
        ) Error![]const mqtt.Property {
            const self: *@This() =
                @ptrCast(@alignCast(context_ptr));
            self.calls += 1;
            if (!std.mem.eql(
                u8,
                "1pets",
                mqtt.authenticationData(challenge.properties) orelse
                    return error.InvalidAuthenticationState,
            )) return error.InvalidAuthenticationState;
            return &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "supercalifragilisticexpialidocious",
                } },
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var handler: Handler = .{};
    var result = try Client.connectWithConnAck(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "enhanced-auth",
            .properties = &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "step1",
                } },
            },
            .authentication = .{
                .context = &handler,
                .respond = Handler.respond,
            },
        },
    );
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings(
        method,
        result.connection.authentication.method.?,
    );
    try std.testing.expectEqualStrings(
        "initial-final",
        mqtt.authenticationData(
            result.connack.connack.properties,
        ).?,
    );

    try result.connection.beginReauthentication("step1");
    try std.testing.expectError(
        error.AuthenticationInProgress,
        result.connection.ping(),
    );
    var challenge = try result.connection.receiveReauthentication();
    defer challenge.auth.deinit(allocator);
    try std.testing.expect(!challenge.complete);
    try std.testing.expectEqualStrings(
        "1pets",
        mqtt.authenticationData(challenge.auth.auth.properties).?,
    );
    try result.connection.continueReauthentication(
        0x18,
        "supercalifragilisticexpialidocious",
    );
    var complete = try result.connection.receiveReauthentication();
    defer complete.auth.deinit(allocator);
    try std.testing.expect(complete.complete);
    try std.testing.expectEqualStrings(
        "server-final",
        mqtt.authenticationData(complete.auth.auth.properties).?,
    );
    try result.connection.ping();

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT reauthentication method mismatch sends protocol error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self.server) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var pending = try server_ptr.acceptPending(.{});
            var pending_owned = true;
            defer if (pending_owned) {
                pending.deinit(server_ptr.allocator);
            };
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{});
            pending_owned = false;
            defer accepted.deinit(server_ptr.allocator);

            try std.testing.expectError(
                error.AuthenticationMethodMismatch,
                accepted.connection.acceptReauthentication(),
            );
        }
    };

    const Handler = struct {
        fn respond(
            _: *anyopaque,
            _: mqtt.Auth,
        ) Error![]const mqtt.Property {
            return error.InvalidAuthenticationState;
        }
    };
    var dummy: u8 = 0;
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "auth-method-mismatch",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
            .authentication = .{
                .context = &dummy,
                .respond = Handler.respond,
            },
        },
    );
    defer connection.close();
    try connection.writeAuth(0x19, &.{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "badmethod",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = "step1",
        } },
    });
    var disconnect = try connection.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x82),
        disconnect.disconnect.reason_code,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT enhanced auth cannot finish before explicit authorization" {
    const allocator = std.testing.allocator;
    var connection = runtime.Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
    };
    try connection.authentication.beginConnect(
        allocator,
        &.{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }},
    );
    var pending = runtime.PendingAcceptedClient{
        .connection = connection,
        .connect = undefined,
    };
    try std.testing.expectError(
        error.AuthenticationInProgress,
        pending.finish(.{}),
    );
    pending.connection.authentication.deinit(allocator);
    pending.connection = undefined;
}

test "MQTT broker event exposes and gates reauthentication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self.server) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var pending = try server_ptr.acceptPending(.{});
            var pending_owned = true;
            defer if (pending_owned) {
                pending.deinit(server_ptr.allocator);
            };
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{});
            pending_owned = false;
            defer accepted.deinit(server_ptr.allocator);

            var event = try accepted.connection.readBrokerEvent();
            defer event.deinit(server_ptr.allocator);
            try std.testing.expect(event == .auth);
            try std.testing.expectEqual(@as(u8, 0x19), event.auth.auth.reason_code);
            try std.testing.expect(!(try accepted.connection
                .applyAuthenticationEvent(event.auth.auth)));
            try std.testing.expectError(
                error.AuthenticationInProgress,
                accepted.connection.readBrokerEvent(),
            );
        }
    };

    const Handler = struct {
        fn respond(
            _: *anyopaque,
            _: mqtt.Auth,
        ) Error![]const mqtt.Property {
            return error.InvalidAuthenticationState;
        }
    };
    var dummy: u8 = 0;
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "broker-auth-event",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
            .authentication = .{
                .context = &dummy,
                .respond = Handler.respond,
            },
        },
    );
    defer connection.close();
    try connection.beginReauthentication("client-step");
    // Deliberately bypass the typed gate to prove the broker rejects ordinary
    // traffic before parsing/dispatching it while re-authentication is active.
    var ping_bytes: std.ArrayList(u8) = .empty;
    defer ping_bytes.deinit(allocator);
    try mqtt.writePing(&ping_bytes, allocator, false);
    try connection.transport.writePacket(ping_bytes.items);
    var disconnect = try connection.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x82),
        disconnect.disconnect.reason_code,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT live broker policy completes reauthentication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        calls: usize = 0,

        fn start(
            _: *anyopaque,
            pending: *runtime.PendingAcceptedClient,
        ) broker_mod.Error!void {
            try pending.authorizeAuthentication();
        }

        fn handle(
            context_ptr: *anyopaque,
            connection: *runtime.Connection,
            auth: mqtt.Auth,
            complete: bool,
        ) broker_mod.Error!void {
            const self: *@This() =
                @ptrCast(@alignCast(context_ptr));
            if (complete or auth.reason_code != 0x19) {
                return error.InvalidAuthenticationState;
            }
            self.calls += 1;
            try connection.continueReauthentication(
                0,
                "broker-final",
            );
        }
    };
    var policy: Policy = .{};
    var broker = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .authentication = .{
                .context = &policy,
                .start = Policy.start,
                .handle = Policy.handle,
            },
        },
    );
    defer broker.deinit();

    const Shared = struct {
        broker: *broker_mod.Broker,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serve(1) catch |err| {
                self.err = err;
            };
        }
    };
    const Handler = struct {
        fn respond(
            _: *anyopaque,
            _: mqtt.Auth,
        ) Error![]const mqtt.Property {
            return error.InvalidAuthenticationState;
        }
    };
    var dummy: u8 = 0;
    var shared = Shared{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "live-broker-auth",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
            .authentication = .{
                .context = &dummy,
                .respond = Handler.respond,
            },
        },
    );
    defer connection.close();
    try connection.beginReauthentication("client-step");
    var complete = try connection.receiveReauthentication();
    defer complete.auth.deinit(allocator);
    try std.testing.expect(complete.complete);
    try std.testing.expectEqualStrings(
        "broker-final",
        mqtt.authenticationData(complete.auth.auth.properties).?,
    );
    try connection.ping();
    try connection.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), policy.calls);
}
