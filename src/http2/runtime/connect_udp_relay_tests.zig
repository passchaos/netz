const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");

const max_udp_payload_size = http3.connect_udp.max_udp_payload_size;

test "HTTP/2 CONNECT-UDP relay preserves UDP lifecycle" {
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
        .{
            .enable_connect_protocol = true,
            .max_frame_payload = 128,
            .max_body_bytes = 128 * 1024,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        target: std.Io.net.IpAddress,
        relay_ready: std.Io.Event = .unset,
        relay_address: std.Io.net.IpAddress = undefined,
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
                request,
                &host_storage,
            );
            defer accepted.session.deinit();
            var relay_socket = try std.Io.net.IpAddress.bind(
                &.{ .ip4 = .loopback(0) },
                self.server.io,
                .{ .mode = .dgram, .protocol = .udp },
            );
            defer relay_socket.close(self.server.io);
            self.relay_address = relay_socket.address;
            self.relay_ready.set(self.server.io);
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
            for (0..3) |_| {
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
        .{ .max_frame_payload = 128, .max_body_bytes = 128 * 1024 },
    );
    defer client.close();
    const template = try http3.connect_udp.UriTemplate.compile(
        "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var path_storage: [192]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &path_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try shared.relay_ready.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });

    var spoof_socket = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer spoof_socket.close(io);
    try spoof_socket.send(io, &shared.relay_address, "spoofed");

    var response_storage: [64]u8 = undefined;
    inline for (.{ "relay-one", "", "relay-three" }) |payload| {
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
    try std.testing.expectEqual(@as(u64, 3), result.stats.session_to_udp_datagrams);
    try std.testing.expectEqual(@as(u64, 3), result.stats.udp_to_session_datagrams);
    try std.testing.expectEqual(@as(u64, 1), result.stats.dropped_unexpected_source);
    try std.testing.expectEqual(
        @as(u64, "relay-one".len + "relay-three".len),
        result.stats.session_to_udp_bytes,
    );
    try std.testing.expectEqual(
        result.stats.session_to_udp_bytes,
        result.stats.udp_to_session_bytes,
    );
}

test "HTTP/2 CONNECT-UDP relay releases reader after cancel and deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var target_socket = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer target_socket.close(io);
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

    const Shared = struct {
        server: *runtime.Server,
        target: std.Io.net.IpAddress,
        cancel: std.Io.Event = .unset,
        relay_ready: std.Io.Event = .unset,
        strict_ready: std.Io.Event = .unset,
        cancel_ready: std.Io.Event = .unset,
        relay_address: std.Io.net.IpAddress = undefined,
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
            var relay_socket = try std.Io.net.IpAddress.bind(
                &.{ .ip4 = .loopback(0) },
                self.server.io,
                .{ .mode = .dgram, .protocol = .udp },
            );
            defer relay_socket.close(self.server.io);
            var session_storage: [max_udp_payload_size]u8 = undefined;
            var udp_storage: [max_udp_payload_size]u8 = undefined;
            var short_storage: [1]u8 = undefined;
            try std.testing.expectError(
                error.BufferTooShort,
                http3.connect_udp.relay.run(
                    runtime.ConnectUdpSession,
                    self.server.io,
                    &accepted.session,
                    &relay_socket,
                    &self.target,
                    &short_storage,
                    &udp_storage,
                    .{},
                ),
            );
            const limited = try http3.connect_udp.relay.run(
                runtime.ConnectUdpSession,
                self.server.io,
                &accepted.session,
                &relay_socket,
                &self.target,
                &session_storage,
                &udp_storage,
                .{ .max_forwarded_datagrams = 0 },
            );
            try std.testing.expectEqual(
                http3.connect_udp.relay.EndReason.datagram_limit,
                limited.reason,
            );
            self.relay_address = relay_socket.address;
            self.relay_ready.set(self.server.io);
            var small_udp_storage: [4]u8 = undefined;
            const truncated = try http3.connect_udp.relay.run(
                runtime.ConnectUdpSession,
                self.server.io,
                &accepted.session,
                &relay_socket,
                &self.target,
                &session_storage,
                &small_udp_storage,
                .{ .deadline = .fromNow(self.server.io, .{
                    .raw = .fromMilliseconds(500),
                    .clock = .awake,
                }) },
            );
            try std.testing.expectEqual(
                http3.connect_udp.relay.EndReason.deadline,
                truncated.reason,
            );
            try std.testing.expectEqual(
                @as(u64, 1),
                truncated.stats.dropped_truncated,
            );
            try accepted.session.sendWithTimeout(
                "after-truncated",
                .fromSeconds(2),
            );
            self.strict_ready.set(self.server.io);
            try std.testing.expectError(
                error.DatagramTruncated,
                http3.connect_udp.relay.run(
                    runtime.ConnectUdpSession,
                    self.server.io,
                    &accepted.session,
                    &relay_socket,
                    &self.target,
                    &session_storage,
                    &small_udp_storage,
                    .{
                        .drop_truncated = false,
                        .deadline = .fromNow(self.server.io, .{
                            .raw = .fromSeconds(2),
                            .clock = .awake,
                        }),
                    },
                ),
            );
            try accepted.session.sendWithTimeout(
                "after-strict-truncation",
                .fromSeconds(2),
            );
            self.cancel_ready.set(self.server.io);
            const canceled = try http3.connect_udp.relay.run(
                runtime.ConnectUdpSession,
                self.server.io,
                &accepted.session,
                &relay_socket,
                &self.target,
                &session_storage,
                &udp_storage,
                .{
                    .cancel = &self.cancel,
                    .deadline = .fromNow(self.server.io, .{
                        .raw = .fromSeconds(2),
                        .clock = .awake,
                    }),
                },
            );
            try std.testing.expectEqual(
                http3.connect_udp.relay.EndReason.canceled,
                canceled.reason,
            );
            try accepted.session.sendWithTimeout(
                "after-cancel",
                .fromSeconds(2),
            );
            const deadline = try http3.connect_udp.relay.run(
                runtime.ConnectUdpSession,
                self.server.io,
                &accepted.session,
                &relay_socket,
                &self.target,
                &session_storage,
                &udp_storage,
                .{ .deadline = .fromNow(self.server.io, .{
                    .raw = .fromMilliseconds(30),
                    .clock = .awake,
                }) },
            );
            try std.testing.expectEqual(
                http3.connect_udp.relay.EndReason.deadline,
                deadline.reason,
            );
            try accepted.session.sendWithTimeout(
                "after-deadline",
                .fromSeconds(2),
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .target = target_socket.address,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.cancel.set(io);
        thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 128, .max_body_bytes = 128 * 1024 },
    );
    defer client.close();
    const template = try http3.connect_udp.UriTemplate.compile(
        "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/",
    );
    var path_storage: [192]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &path_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try shared.relay_ready.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    var storage: [64]u8 = undefined;
    try target_socket.send(io, &shared.relay_address, "oversized-drop");
    const after_truncated = try session.receiveIntoWithTimeout(
        &storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualStrings(
        "after-truncated",
        after_truncated.payload,
    );
    try shared.strict_ready.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    try target_socket.send(io, &shared.relay_address, "oversized-error");
    const after_strict = try session.receiveIntoWithTimeout(
        &storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualStrings(
        "after-strict-truncation",
        after_strict.payload,
    );
    try shared.cancel_ready.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
    shared.cancel.set(io);
    const after_cancel = try session.receiveIntoWithTimeout(
        &storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualStrings("after-cancel", after_cancel.payload);
    const after_deadline = try session.receiveIntoWithTimeout(
        &storage,
        .fromSeconds(2),
    );
    try std.testing.expectEqualStrings(
        "after-deadline",
        after_deadline.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
