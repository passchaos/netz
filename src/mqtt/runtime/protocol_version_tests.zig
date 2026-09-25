const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

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
