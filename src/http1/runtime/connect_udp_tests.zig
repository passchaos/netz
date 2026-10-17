const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");

test "HTTP/1 CONNECT-UDP resumes fragmented capsules after timeout" {
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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const response_payload = [_]u8{0x6b} ** 513;
    const Shared = struct {
        server: *runtime.Server,
        response_payload: []const u8,
        prefix_sent: std.Io.Event = .unset,
        allow_suffix: std.Io.Event = .unset,
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
            try std.testing.expectEqualStrings(
                "http://localhost/.well-known/masque/udp/dns.example/53/",
                request.request.target,
            );
            var host_storage: [128]u8 = undefined;
            var accepted = try connection.acceptConnectUdpDefault(
                request.request,
                &host_storage,
            );
            defer accepted.session.deinit();
            try std.testing.expectEqualStrings(
                "dns.example",
                accepted.target.host,
            );
            try std.testing.expectEqual(@as(u16, 53), accepted.target.port);

            var incoming = try accepted.session.receiveWithTimeout(
                .fromSeconds(2),
            );
            defer incoming.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "h1-client-udp",
                incoming.payload,
            );

            var capsule_storage: [1024]u8 = undefined;
            const unknown_capsule = try http3.capsule.writeInto(
                &capsule_storage,
                0x21,
                "ignored-capsule",
            );
            try accepted.session.tunnel.inner.write(unknown_capsule);

            var context_storage: [1024]u8 = undefined;
            const unknown_context = try (http3.connect_udp.ContextDatagram{
                .context_id = 2,
                .payload = "ignored-context",
            }).writeInto(&context_storage);
            const unknown_datagram = try http3.capsule.writeDatagramInto(
                &capsule_storage,
                unknown_context,
            );
            try accepted.session.tunnel.inner.write(unknown_datagram);

            const context_datagram = try (http3.connect_udp.ContextDatagram{
                .context_id = http3.connect_udp.udp_context_id,
                .payload = self.response_payload,
            }).writeInto(&context_storage);
            const datagram_capsule = try http3.capsule.writeDatagramInto(
                &capsule_storage,
                context_datagram,
            );
            try accepted.session.tunnel.inner.write(datagram_capsule[0..2]);
            self.prefix_sent.set(self.server.io);
            try self.allow_suffix.wait(self.server.io);
            for (datagram_capsule[2..]) |byte| {
                try accepted.session.tunnel.inner.write(&.{byte});
            }
            // DATAGRAM Capsule with an empty value: no Context ID.
            try accepted.session.tunnel.inner.write(&.{ 0x00, 0x00 });
        }
    };
    var shared = Shared{
        .server = &server,
        .response_payload = &response_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_suffix.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const mismatched_template = try http3.connect_udp.UriTemplate.compile(
        "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var uri_storage: [256]u8 = undefined;
    try std.testing.expectError(
        error.InvalidUriTemplate,
        client.openConnectUdp(
            mismatched_template,
            .{ .host = "dns.example", .port = 53 },
            &.{},
            &uri_storage,
        ),
    );
    const template = try http3.connect_udp.UriTemplate.compile(
        "http://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &uri_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try session.sendWithTimeout("h1-client-udp", .fromSeconds(2));
    try shared.prefix_sent.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    try std.testing.expectError(
        error.Timeout,
        session.receiveWithTimeout(.fromMilliseconds(30)),
    );
    shared.allow_suffix.set(io);
    var short_response: [512]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        session.receiveIntoWithTimeout(
            &short_response,
            .fromSeconds(2),
        ),
    );
    var response_storage: [response_payload.len]u8 = undefined;
    const response = try session.receiveIntoWithTimeout(
        &response_storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualSlices(
        u8,
        &response_payload,
        response.payload,
    );
    try std.testing.expectError(
        error.BufferTooShort,
        session.receiveWithTimeout(.fromSeconds(2)),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 CONNECT-UDP aborts a 101 without Capsule-Protocol" {
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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequestWithTimeout(
                .{},
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expect(try http3.capsule.protocolEnabled(
                request.request.headers,
            ));
            _ = try connection.acceptUpgrade(
                request.request,
                http3.connect_udp.protocol,
                &.{},
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const template = try http3.connect_udp.UriTemplate.compile(
        "http://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var uri_storage: [256]u8 = undefined;
    try std.testing.expectError(
        error.InvalidResponse,
        client.openConnectUdpWithTimeout(
            template,
            .{ .host = "dns.example", .port = 53 },
            &.{},
            &uri_storage,
            .fromSeconds(5),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
