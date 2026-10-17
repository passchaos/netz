const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");

const max_udp_payload_size = http3.connect_udp.max_udp_payload_size;

test "HTTP/1 CONNECT-UDP relay preserves datagrams and peer half-close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var echo_socket = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer echo_socket.close(io);
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        target: std.Io.net.IpAddress,
        result: ?http3.connect_udp.relay.Result = null,
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
                request.request,
                &host_storage,
            );
            defer accepted.session.deinit();
            var relay_socket = try std.Io.net.IpAddress.bind(
                &.{ .ip4 = .loopback(0) },
                self.server.io,
                .{ .mode = .dgram, .protocol = .udp },
            );
            defer relay_socket.close(self.server.io);
            var session_storage: [max_udp_payload_size]u8 = undefined;
            var udp_storage: [max_udp_payload_size]u8 = undefined;
            self.result = try http3.connect_udp.relay.run(
                runtime.ConnectUdpSession,
                self.server.io,
                &accepted.session,
                &relay_socket,
                &self.target,
                &session_storage,
                &udp_storage,
                .{ .deadline = .fromNow(self.server.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }) },
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .target = echo_socket.address,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    const Echo = struct {
        socket: *std.Io.net.Socket,
        io: std.Io,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var storage: [max_udp_payload_size]u8 = undefined;
            for (0..2) |_| {
                const message = try self.socket.receiveTimeout(
                    self.io,
                    &storage,
                    .{ .duration = .{
                        .raw = .fromSeconds(5),
                        .clock = .awake,
                    } },
                );
                try self.socket.send(self.io, &message.from, message.data);
            }
        }
    };
    var echo = Echo{ .socket = &echo_socket, .io = io };
    const echo_thread = try std.Thread.spawn(.{}, Echo.run, .{&echo});
    var echo_joined = false;
    defer if (!echo_joined) echo_thread.join();

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
    var uri_storage: [192]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &uri_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    var response_storage: [64]u8 = undefined;
    inline for (.{ "h1-relay", "" }) |payload| {
        try session.sendWithTimeout(payload, .fromSeconds(2));
        const response = try session.receiveIntoWithTimeout(
            &response_storage,
            .fromSeconds(2),
        );
        try std.testing.expectEqualStrings(payload, response.payload);
    }
    try session.closeWrite();

    server_thread.join();
    server_joined = true;
    echo_thread.join();
    echo_joined = true;
    if (shared.err) |err| return err;
    if (echo.err) |err| return err;
    const result = shared.result orelse return error.MissingRelayResult;
    try std.testing.expectEqual(
        http3.connect_udp.relay.EndReason.session_closed,
        result.reason,
    );
    try std.testing.expectEqual(@as(u64, 2), result.stats.session_to_udp_datagrams);
    try std.testing.expectEqual(@as(u64, 2), result.stats.udp_to_session_datagrams);
    try std.testing.expectEqual(@as(u64, "h1-relay".len), result.stats.session_to_udp_bytes);
    try std.testing.expectEqual(
        result.stats.session_to_udp_bytes,
        result.stats.udp_to_session_bytes,
    );
}
