const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const packet_transport = @import("packet_transport.zig");

const net = std.Io.net;

const Server = runtime.Server;
const Client = runtime.Client;

test "MQTT server honors CONNECT information preferences" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{
                .protocol = .v5,
                .response_information = "response/root",
            });
            defer accepted.deinit(self.server.allocator);
            try std.testing.expect(
                !accepted.connection.peerRequestedProblemInformation(),
            );

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try accepted.connection.writePubAckWithProperties(
                publish.publish.packet_id.?,
                0x80,
                &.{
                    .{ .utf8 = .{
                        .id = .reason_string,
                        .value = "suppressed",
                    } },
                    .{ .utf8_pair = .{
                        .id = .user_property,
                        .key = "trace",
                        .value = "suppressed",
                    } },
                },
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var result = try Client.connectWithConnAck(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "information-preferences",
            .properties = &.{
                .{ .byte = .{
                    .id = .request_problem_information,
                    .value = 0,
                } },
                .{ .byte = .{
                    .id = .request_response_information,
                    .value = 1,
                } },
            },
            .limits = .{ .max_packet_size = 4096 },
        },
    );
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings(
        "response/root",
        mqtt.responseInformation(
            result.connack.connack.properties,
        ).?,
    );

    const packet_id = (try result.connection.writePublish(
        "problem/information",
        "payload",
        .{ .qos = .at_least_once },
    )).?;
    var ack = try result.connection.readPubAck();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(packet_id, ack.ack.packet_id);
    try std.testing.expectEqual(@as(u8, 0x80), ack.ack.reason_code);
    try std.testing.expectEqual(@as(usize, 0), ack.ack.properties.len);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT Response Information requires an explicit request" {
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

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |_| {
                var accepted = try self.server.accept(.{
                    .protocol = .v5,
                    .response_information = "response/root",
                });
                accepted.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]?u8{ null, 0 }) |request_value| {
        const properties: []const mqtt.Property = if (request_value) |value|
            &.{.{ .byte = .{
                .id = .request_response_information,
                .value = value,
            } }}
        else
            &.{};
        var result = try Client.connectWithConnAck(
            allocator,
            io,
            server.address(),
            .{
                .protocol = .v5,
                .client_id = "response-information-not-requested",
                .properties = properties,
                .limits = .{ .max_packet_size = 4096 },
            },
        );
        defer result.deinit(allocator);
        try std.testing.expect(
            mqtt.responseInformation(
                result.connack.connack.properties,
            ) == null,
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT client rejects unsolicited Response Information" {
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
            for ([_]?u8{ null, 0 }) |request_value| {
                var peer = packet_transport.Transport.initTcp(
                    self.io,
                    try self.listener.accept(self.io),
                );
                defer peer.close(self.allocator);
                var packet = try peer.readPacket(self.allocator, 4096);
                defer packet.deinit(self.allocator);
                var connect = try mqtt.Connect.parse(
                    self.allocator,
                    packet.bytes,
                );
                defer connect.deinit(self.allocator);
                const expected_request: ?bool = if (request_value) |value|
                    value != 0
                else
                    null;
                try std.testing.expectEqual(
                    expected_request,
                    mqtt.requestResponseInformation(connect.properties),
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
                        .id = .response_information,
                        .value = "response/root",
                    } }},
                );
                try peer.writePacket(response.items);
            }
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

    for ([_]?u8{ null, 0 }) |request_value| {
        const properties: []const mqtt.Property = if (request_value) |value|
            &.{.{ .byte = .{
                .id = .request_response_information,
                .value = value,
            } }}
        else
            &.{};
        try std.testing.expectError(
            error.InvalidProperty,
            Client.connectAttempt(allocator, io, listener.socket.address, .{
                .protocol = .v5,
                .client_id = "response-information-client",
                .properties = properties,
                .limits = .{ .max_packet_size = 4096 },
            }),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
