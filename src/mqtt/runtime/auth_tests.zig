const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const broker_mod = @import("../broker.zig");
const packet_transport = @import("packet_transport.zig");

const net = std.Io.net;

const Error = runtime.Error;
const Server = runtime.Server;
const Client = runtime.Client;

test {
    _ = @import("reauth_traffic_tests.zig");
    _ = @import("reauth_receive_tests.zig");
    _ = @import("../broker/reauth_traffic_tests.zig");
}

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
            const deadline = std.Io.Clock.Timestamp.fromNow(
                server_ptr.io,
                .{ .raw = .fromSeconds(3), .clock = .awake },
            );
            var pending = try server_ptr.acceptPendingWithDeadline(
                .{ .protocol = .v5 },
                deadline,
            );
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
            try std.testing.expectError(
                error.Timeout,
                pending.challengeAuthenticationWithDeadline(
                    "not-sent",
                    .{ .raw = .zero, .clock = .awake },
                ),
            );
            try std.testing.expect(pending.connection.isUsable());
            try pending.challengeAuthenticationWithDeadline(
                "1pets",
                deadline,
            );
            var response = try pending.receiveAuthenticationWithDeadline(
                deadline,
            );
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
            var accepted = try pending.finishWithDeadline(
                .{ .protocol = .v5 },
                deadline,
            );
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
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
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
        result.connection.authentication.method().?,
    );
    try std.testing.expectEqualStrings(
        "initial-final",
        mqtt.authenticationData(
            result.connack.connack.properties,
        ).?,
    );

    try result.connection.beginReauthentication("step1");
    try result.connection.pingWithTimeout(.fromSeconds(1));
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

test "MQTT client connect deadline bounds enhanced authentication reply" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const method = "deadline-auth";
    const ServerState = struct {
        server: *Server,
        auth_received: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            defer pending.deinit(self.server.allocator);
            try pending.challengeAuthentication("challenge");
            var event = pending.connection.readBrokerEventWithTimeout(
                .fromSeconds(1),
            ) catch |err| switch (err) {
                error.Timeout,
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer event.deinit(self.server.allocator);
            self.auth_received = event == .auth;
        }
    };
    var server_state = ServerState{ .server = &server };
    var server_future = try std.Io.concurrent(
        io,
        ServerState.run,
        .{&server_state},
    );
    var server_done = false;
    defer if (!server_done) server_future.cancel(io);

    const Handler = struct {
        io: std.Io,
        called: bool = false,

        fn respond(
            context_ptr: *anyopaque,
            _: mqtt.Auth,
        ) Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.called = true;
            try std.Io.sleep(
                self.io,
                .fromMilliseconds(1100),
                .awake,
            );
            return &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "response",
                } },
            };
        }
    };
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var connection = runtime.Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
    };
    var connection_open = true;
    defer if (connection_open) connection.close();
    var handler = Handler{ .io = io };
    try std.testing.expectError(
        error.Timeout,
        connection.establishClientWithDeadline(
            .{
                .protocol = .v5,
                .client_id = "bounded-auth-reply",
                .properties = &.{
                    .{ .utf8 = .{
                        .id = .authentication_method,
                        .value = method,
                    } },
                    .{ .binary = .{
                        .id = .authentication_data,
                        .value = "initial",
                    } },
                },
                .authentication = .{
                    .context = &handler,
                    .respond = Handler.respond,
                },
            },
            .{
                .raw = .fromNanoseconds(
                    std.Io.Clock.awake.now(io).nanoseconds +
                        std.time.ns_per_s,
                ),
                .clock = .awake,
            },
        ),
    );
    try std.testing.expect(handler.called);

    connection.close();
    connection_open = false;
    server_future.await(io);
    server_done = true;
    if (server_state.err) |err| return err;
    try std.testing.expect(!server_state.auth_received);
}

test "MQTT Request Problem Information preserves AUTH protocol fields" {
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
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{});
            var pending_owned = true;
            defer if (pending_owned) {
                pending.deinit(self.server.allocator);
            };
            try pending.connection.writeAuth(0x18, &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "server-step",
                } },
                .{ .utf8 = .{
                    .id = .reason_string,
                    .value = "must be omitted",
                } },
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "trace",
                    .value = "must be omitted",
                } },
            });
            var response = try pending.receiveAuthentication();
            defer response.deinit(self.server.allocator);
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{});
            pending_owned = false;
            defer accepted.deinit(self.server.allocator);
        }
    };
    const Handler = struct {
        fn respond(
            _: *anyopaque,
            challenge: mqtt.Auth,
        ) Error![]const mqtt.Property {
            if (challenge.properties.len != 2) {
                return error.InvalidAuthenticationState;
            }
            if (!std.mem.eql(
                u8,
                method,
                mqtt.authenticationMethod(challenge.properties) orelse
                    return error.InvalidAuthenticationState,
            )) return error.InvalidAuthenticationState;
            if (!std.mem.eql(
                u8,
                "server-step",
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
                    .value = "client-step",
                } },
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var dummy: u8 = 0;
    var result = try Client.connectWithConnAck(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "auth-without-problem-information",
            .properties = &.{
                .{ .byte = .{
                    .id = .request_problem_information,
                    .value = 0,
                } },
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
            },
            .authentication = .{
                .context = &dummy,
                .respond = Handler.respond,
            },
        },
    );
    defer result.deinit(allocator);

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

test "MQTT reauthentication rejection validates before wire mutation" {
    var connection = runtime.Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
    };
    connection.authentication.phase = .active;
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        connection.rejectReauthentication(0x87),
    );
    connection.authentication.phase = .reauthenticating;
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        connection.rejectReauthentication(0),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        connection.rejectReauthentication(0x04),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        connection.rejectReauthenticationWithProperties(
            0x87,
            &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 1,
            } }},
        ),
    );
    try std.testing.expect(connection.isUsable());
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
        .connect = .{
            .packet = undefined,
            .connect = .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 0,
                .client_id = "auth-pending",
            },
        },
    };
    try std.testing.expectError(
        error.AuthenticationInProgress,
        pending.finish(.{}),
    );
    pending.connection.authentication.deinit(allocator);
    pending.connection = undefined;
}

test "MQTT pending enhanced auth rejection is validated and bound" {
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
            .value = "single",
        } }},
    );
    var pending = runtime.PendingAcceptedClient{
        .connection = connection,
        .connect = .{
            .packet = undefined,
            .connect = .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 0,
                .client_id = "auth-rejected",
            },
        },
    };
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        pending.rejectAuthentication(0),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        pending.rejectAuthentication(0x8b),
    );
    try pending.rejectAuthentication(0x87);
    try std.testing.expectEqual(
        @as(?u8, 0x87),
        pending.authenticationRejectionReason(),
    );
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        pending.authorizeAuthentication(),
    );
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        pending.setAuthenticatedUsername("too-late"),
    );
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        pending.finish(.{ .reason_code = 0x8c }),
    );
    pending.connection.authentication.deinit(allocator);
    pending.connection = undefined;
}

test "MQTT pending authentication owns and freezes established username" {
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
            .value = "change",
        } }},
    );
    var pending = runtime.PendingAcceptedClient{
        .connection = connection,
        .connect = .{
            .packet = .{
                .bytes = try allocator.alloc(u8, 0),
                .fixed = undefined,
            },
            .connect = .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 0,
                .client_id = "auth-identity",
                .properties = try allocator.alloc(mqtt.Property, 0),
                .username = "wire-user",
                .password = "wire-password",
            },
        },
    };
    var username = "new_username".*;
    try pending.setAuthenticatedUsername(&username);
    username[0] = 'x';
    try std.testing.expectEqualStrings(
        "new_username",
        pending.connect.connect.username.?,
    );
    try std.testing.expect(pending.connect.connect.password == null);
    try std.testing.expectError(
        error.InvalidUtf8,
        pending.setAuthenticatedUsername("bad\x00username"),
    );
    try std.testing.expectEqualStrings(
        "new_username",
        pending.connect.connect.username.?,
    );
    try pending.authorizeAuthentication();
    try std.testing.expectError(
        error.InvalidAuthenticationState,
        pending.setAuthenticatedUsername("too-late"),
    );

    pending.connect.deinit(allocator);
    pending.connection.authentication.deinit(allocator);
    pending.connection = undefined;
}

test "MQTT client rejects an Authentication Method omitted from CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var peer = packet_transport.Transport.initTcp(
                self.io,
                try self.listener.accept(self.io),
            );
            defer peer.close(self.allocator);
            var connect_packet = try peer.readPacket(self.allocator, 4096);
            defer connect_packet.deinit(self.allocator);
            var connect = try mqtt.Connect.parse(
                self.allocator,
                connect_packet.bytes,
            );
            defer connect.deinit(self.allocator);
            try std.testing.expect(
                mqtt.authenticationMethod(connect.properties) == null,
            );

            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(self.allocator);
            try mqtt.ConnAck.write(
                &response,
                self.allocator,
                .v5,
                false,
                0,
                &.{.{ .utf8 = .{
                    .id = .authentication_method,
                    .value = "unsolicited",
                } }},
            );
            try peer.writePacket(response.items);

            var disconnect_packet = try peer.readPacket(
                self.allocator,
                4096,
            );
            defer disconnect_packet.deinit(self.allocator);
            var disconnect = try mqtt.Disconnect.parse(
                self.allocator,
                .v5,
                disconnect_packet.bytes,
            );
            defer disconnect.deinit(self.allocator);
            try std.testing.expectEqual(
                @as(u8, 0x82),
                disconnect.reason_code,
            );
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.AuthenticationMethodMismatch,
        Client.connectAttempt(allocator, io, listener.socket.address, .{
            .protocol = .v5,
            .client_id = "no-auth-method",
            .limits = .{ .max_packet_size = 4096 },
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT broker event interleaves PING with reauthentication" {
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
            var ping = try accepted.connection.readBrokerEvent();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expect(ping == .pingreq);
            try accepted.connection.writePingResp();
            try accepted.connection.continueReauthentication(0, "done");
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
    try connection.pingWithTimeout(.fromSeconds(1));
    var complete = try connection.receiveReauthenticationWithTimeout(.fromSeconds(1));
    defer complete.auth.deinit(allocator);
    try std.testing.expect(complete.complete);

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

test "MQTT live broker policy rejects reauthentication and retires connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        calls: usize = 0,
        retired: bool = false,

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
            try connection.rejectReauthentication(0x87);
            self.retired = !connection.isUsable();
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
    var shared = Shared{ .broker = &broker };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var connection = try Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "live-broker-auth-rejection",
            .properties = &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = "repeat",
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "repeat",
                } },
            },
        },
    );
    defer connection.close();
    try connection.beginReauthentication("repeat");
    var disconnect = try connection.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x87),
        disconnect.disconnect.reason_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        disconnect.disconnect.properties.len,
    );

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), policy.calls);
    try std.testing.expect(policy.retired);
}
