const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const packet_transport = @import("packet_transport.zig");

const net = std.Io.net;

test "MQTT server enforces accepted CONNECT protocol versions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |denied_protocol| {
        var server = try runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_packet_size = 4096 },
        );
        defer server.deinit();

        const Shared = struct {
            server: *runtime.Server,
            accepted_versions: mqtt.AcceptedProtocolVersions,
            denied_protocol: mqtt.ProtocolVersion,
            err: ?anyerror = null,

            fn run(shared: *@This()) void {
                var pending = shared.server.acceptPending(.{
                    .accepted_protocol_versions = shared.accepted_versions,
                }) catch |err| {
                    shared.err = err;
                    return;
                };
                var pending_owned = true;
                defer if (pending_owned) {
                    pending.deinit(shared.server.allocator);
                };
                // A caller cannot widen the version policy between the
                // two-phase parse and finish operations or replace the
                // protocol-specific refusal with another application reason.
                var accepted = pending.finish(.{ .reason_code = 0x87 }) catch |err| {
                    shared.err = err;
                    return;
                };
                pending_owned = false;
                defer accepted.deinit(shared.server.allocator);
                if (accepted.connect.connect.protocol != shared.denied_protocol) {
                    shared.err = error.TestUnexpectedResult;
                }
            }
        };
        const accepted_versions = switch (denied_protocol) {
            .v3_1_1 => mqtt.AcceptedProtocolVersions{ .v3_1_1 = false },
            .v5 => mqtt.AcceptedProtocolVersions{ .v5 = false },
        };
        var shared = Shared{
            .server = &server,
            .accepted_versions = accepted_versions,
            .denied_protocol = denied_protocol,
        };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

        var attempt = try runtime.Client.connectAttempt(
            allocator,
            io,
            server.address(),
            .{
                .protocol = denied_protocol,
                .client_id = "version-policy-client",
                .limits = .{ .max_packet_size = 4096 },
            },
        );
        defer attempt.deinit(allocator);
        try std.testing.expect(!attempt.accepted());
        try std.testing.expectEqual(
            @as(u8, if (denied_protocol == .v3_1_1) 0x01 else 0x84),
            attempt.connack.connack.reason_code,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            attempt.connack.connack.properties.len,
        );

        thread.join();
        if (shared.err) |err| return err;
    }
}

test "MQTT server requires an assigned identifier for an empty v5 Client ID" {
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

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            defer pending.deinit(self.server.allocator);
            try std.testing.expect(pending.client_id_was_empty);
            try std.testing.expectError(
                error.InvalidProperty,
                pending.finish(.{ .protocol = .v5 }),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    if (runtime.Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
            .limits = .{ .max_packet_size = 4096 },
        },
    )) |attempt_value| {
        var attempt = attempt_value;
        defer attempt.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |_| {}

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT client validates Assigned Client Identifier against CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Case = struct {
        client_id: []const u8,
        assigned_client_id: ?[]const u8,
    };
    const cases = [_]Case{
        .{ .client_id = "", .assigned_client_id = null },
        .{ .client_id = "", .assigned_client_id = "" },
        .{ .client_id = "named-client", .assigned_client_id = "replacement" },
    };
    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        cases: []const Case,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (self.cases) |case| {
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
                try std.testing.expectEqualStrings(
                    case.client_id,
                    connect.client_id,
                );

                var properties: [1]mqtt.Property = undefined;
                const response_properties = if (case.assigned_client_id) |id| blk: {
                    properties[0] = .{ .utf8 = .{
                        .id = .assigned_client_identifier,
                        .value = id,
                    } };
                    break :blk properties[0..1];
                } else properties[0..0];
                var response: std.ArrayList(u8) = .empty;
                defer response.deinit(self.allocator);
                if (case.assigned_client_id != null and
                    case.assigned_client_id.?.len == 0)
                {
                    // Deliberately malformed peer packet: the public writer
                    // correctly refuses an empty Assigned Client Identifier.
                    try response.appendSlice(
                        self.allocator,
                        &.{ 0x20, 0x06, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00 },
                    );
                } else {
                    try mqtt.ConnAck.write(
                        &response,
                        self.allocator,
                        .v5,
                        false,
                        0,
                        response_properties,
                    );
                }
                try peer.writePacket(response.items);
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
        .cases = &cases,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (cases) |case| {
        try std.testing.expectError(
            error.InvalidProperty,
            runtime.Client.connectAttempt(
                allocator,
                io,
                listener.socket.address,
                .{
                    .protocol = .v5,
                    .client_id = case.client_id,
                    .clean_start = true,
                    .limits = .{ .max_packet_size = 4096 },
                },
            ),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
