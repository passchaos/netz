const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");

test "HTTP/2 CONNECT-UDP carries fragmented DATAGRAM capsules" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .enable_connect_protocol = true,
            .max_frame_payload = 128,
            .max_body_bytes = 128 * 1024,
        },
    );
    defer server.deinit();

    const payload = [_]u8{0x5a} ** 513;
    const Shared = struct {
        server: *runtime.Server,
        expected: []const u8,
        accepted: std.Io.Event = .unset,
        allow_receive: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readConnectUdpRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            var host_storage: [128]u8 = undefined;
            var accepted = try connection.acceptConnectUdpDefault(
                request,
                &host_storage,
            );
            defer accepted.session.deinit();
            try std.testing.expectEqualStrings(
                "dns.example",
                accepted.target.host,
            );
            try std.testing.expectEqual(@as(u16, 53), accepted.target.port);
            self.accepted.set(self.server.io);
            try self.allow_receive.wait(self.server.io);
            try connection.sendWindowUpdate(0, 4096);
            try connection.sendWindowUpdate(request.stream_id, 4096);

            var incoming = try accepted.session.receiveWithTimeout(
                .fromSeconds(2),
            );
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualSlices(
                u8,
                self.expected,
                incoming.payload,
            );

            var capsule_storage: [64]u8 = undefined;
            const unknown_capsule = try http3.capsule.writeInto(
                &capsule_storage,
                0x21,
                "ignored-capsule",
            );
            try accepted.session.tunnel.write(unknown_capsule, false);
            var context_storage: [32]u8 = undefined;
            const unknown_context = try (http3.connect_udp.ContextDatagram{
                .context_id = 2,
                .payload = "ignored-context",
            }).writeInto(&context_storage);
            const unknown_datagram = try http3.capsule.writeDatagramInto(
                &capsule_storage,
                unknown_context,
            );
            try accepted.session.tunnel.write(unknown_datagram, false);
            try accepted.session.sendWithTimeout(
                "h2-server-udp",
                .fromSeconds(2),
            );
            try accepted.session.tunnel.write(&.{ 0x00, 0x00 }, false);
            try std.testing.expectError(
                error.StreamReset,
                accepted.session.receiveWithTimeout(.fromSeconds(2)),
            );
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_receive.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 128,
            .max_body_bytes = 128 * 1024,
        },
    );
    defer client.close();
    const template = try http3.connect_udp.UriTemplate.compile(
        "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var path_storage: [160]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &path_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try shared.accepted.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    runtime.testing.setSendConnectionWindow(&client, 7);
    (try runtime.testing.sendStreamWindow(
        &client,
        session.streamId(),
    )).value = 7;
    try std.testing.expectError(
        error.Timeout,
        session.sendWithTimeout(&payload, .fromMilliseconds(50)),
    );
    try std.testing.expect(session.writeInProgress());
    try std.testing.expectEqual(
        @as(usize, 7),
        session.committedBytes(),
    );
    shared.allow_receive.set(io);
    try session.sendWithTimeout(&payload, .fromSeconds(2));
    try std.testing.expect(!session.writeInProgress());

    var short_response: [1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        session.receiveIntoWithTimeout(
            &short_response,
            .fromSeconds(2),
        ),
    );
    var response_storage: [32]u8 = undefined;
    const response = try session.receiveIntoWithTimeout(
        &response_storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualStrings("h2-server-udp", response.payload);
    try std.testing.expectError(
        error.BufferTooShort,
        session.receiveWithTimeout(.fromSeconds(2)),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
