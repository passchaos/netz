const std = @import("std");
const websocket = @import("../mod.zig");
const h3 = @import("h3.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const AdmissionDeadlineIo = struct {
    delegate: std.Io,
    now_ns: i96,
    send_calls: usize = 0,
    sleep_calls: usize = 0,

    fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn sleep(
        context: ?*anyopaque,
        _: std.Io.Timeout,
    ) std.Io.Cancelable!void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.sleep_calls += 1;
        return error.Canceled;
    }

    fn netSend(
        context: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.send_calls += 1;
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

fn countHeaders(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, name));
    }
    return count;
}

test "WebSocket HTTP3 bounds paced admission with 80 headers at 1200 MTU" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 1200,
        .max_frames_per_datagram = 16,
    } };
    var request_headers: [80]http3.Qpack.HeaderField = undefined;
    var response_headers: [80]http3.Qpack.HeaderField = undefined;
    for (&request_headers) |*header| {
        header.* = .{
            .name = "x-many-request",
            .value = large_header_value,
            .never_indexed = true,
        };
    }
    for (&response_headers) |*header| {
        header.* = .{
            .name = "x-many-response",
            .value = large_header_value,
            .never_indexed = true,
        };
    }

    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe2} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{ .allowed_origins = &.{"https://example.test"} },
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/many-headers",
                pending.target(),
            );
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqual(
                @as(usize, 80),
                countHeaders(pending.headers(), "x-many-request"),
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.header("origin") orelse
                    return error.TestUnexpectedResult,
            );
            const absolute = pending.deadline orelse
                return error.TestUnexpectedResult;
            const original_io = pending.h3.established.connection.endpoint.io;
            var fixed = AdmissionDeadlineIo{
                .delegate = original_io,
                .now_ns = absolute.raw.nanoseconds - 1,
            };
            var vtable = original_io.vtable.*;
            vtable.now = AdmissionDeadlineIo.now;
            vtable.sleep = AdmissionDeadlineIo.sleep;
            vtable.netSend = AdmissionDeadlineIo.netSend;
            pending.h3.established.connection.endpoint.io = .{
                .userdata = &fixed,
                .vtable = &vtable,
            };
            quic.one_rtt.testing.exhaustPacingAt(
                &pending.h3.established.connection,
                @intCast(fixed.now_ns),
            );
            const packet_number =
                pending.h3.established.connection.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                pending.acceptWithHeaders(self.response_headers),
            );
            try std.testing.expectEqual(@as(usize, 0), fixed.send_calls);
            try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
            try std.testing.expectEqual(
                packet_number,
                pending.h3.established.connection.next_packet_number,
            );
            try std.testing.expect(
                pending.h3.outbound_bodies.find(pending.streamId()) == null,
            );
            pending.h3.established.connection.endpoint.io = original_io;
            quic.one_rtt.testing.setPacingBudgetAt(
                &pending.h3.established.connection,
                pending.h3.established.connection.congestionWindow(),
                @intCast(std.Io.Clock.awake.now(original_io).nanoseconds),
            );
            var connection = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer connection.deinit();
            try connection.h3.waitForRecoveryIdleWithTimeout(
                .fromSeconds(2),
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/many-headers",
            .origin = "https://example.test",
            .extra_headers = &request_headers,
        },
        .fromSeconds(3),
    );
    try std.testing.expect(attempt.accepted());
    try std.testing.expectEqual(
        @as(usize, 80),
        countHeaders(attempt.response.headers, "x-many-response"),
    );
    var connection = try attempt.requireAccepted();
    defer connection.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 server deadline spans QUIC TLS and CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x55} ** 32,
            .x25519_secret_key = [_]u8{0x56} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        handshake_complete: std.Io.Event = .unset,
        send_connect: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.handshake_complete.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h3_client = try http3.runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.server.address(),
                limits,
                .{
                    .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0x57} ** 32,
                        .x25519_secret_key = [_]u8{0x58} ** 32,
                    },
                    .session = .{ .local_settings = .{
                        .enable_connect_protocol = true,
                    } },
                },
            );
            defer h3_client.deinit();
            self.handshake_complete.set(self.io);
            try self.send_connect.wait(self.io);
            _ = try h3_client.startRequest(.{
                .method = "CONNECT",
                .path = "/late-websocket",
                .scheme = "https",
                .authority = "localhost",
                .headers = &.{
                    .{ .name = ":protocol", .value = "websocket" },
                    .{ .name = "sec-websocket-version", .value = "13" },
                },
            }, null);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_connect.set(io);
        client_thread.join();
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(300), .clock = .awake },
    );
    const AcceptResult = h3.Error!h3.ServerConnection;
    const Wake = union(enum) {
        server: AcceptResult,
        client_handshake: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .server => |result| if (result) |connection_value| {
            var connection = connection_value;
            connection.deinit();
        } else |_| {},
        .client_handshake => {},
    };
    select.async(
        .server,
        h3.Server.acceptWithDeadline,
        .{ &server, h3.AcceptOptions{}, deadline },
    );
    select.async(
        .client_handshake,
        std.Io.Event.wait,
        .{ &shared.handshake_complete, io },
    );
    switch (try select.await()) {
        .server => |result| {
            if (result) |connection_value| {
                var connection = connection_value;
                connection.deinit();
                return error.TestUnexpectedResult;
            } else |err| return err;
        },
        .client_handshake => |result| try result,
    }

    // The client deliberately withholds CONNECT until the original absolute
    // deadline has expired. Restarting a phase-local timeout would accept it.
    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining > 0) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
            .awake,
        );
    }
    shared.send_connect.set(io);
    try std.testing.expectError(
        error.Timeout,
        switch (try select.await()) {
            .server => |result| result,
            .client_handshake => return error.TestUnexpectedResult,
        },
    );

    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 client deadline includes CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x85} ** 32,
            .x25519_secret_key = [_]u8{0x86} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
        received_connect: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const guard_deadline = std.Io.Clock.Timestamp.fromNow(
                self.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            );
            var session = try self.server.transport.acceptWithDeadline(
                guard_deadline,
            );
            defer session.deinit();
            try session.ensureSettingsSent();
            while (true) {
                var event = try session.receiveRequestEventWithDeadline(
                    guard_deadline,
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (head != .request or
                                !std.mem.eql(u8, head.request.method, "CONNECT") or
                                !std.mem.eql(u8, head.request.path, "/slow-response"))
                            {
                                return error.TestUnexpectedResult;
                            }
                            self.received_connect = true;
                            break;
                        },
                        else => return error.TestUnexpectedResult,
                    },
                }
            }
            const remaining = self.deadline.durationFromNow(self.io)
                .raw.nanoseconds;
            if (remaining > 0) {
                try std.Io.sleep(
                    self.io,
                    .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
                    .awake,
                );
            }
            // Intentionally omit the response. The client must reach its
            // original caller deadline rather than beginning a new wait after
            // QUIC/TLS and peer SETTINGS have completed.
        }
    };

    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(300), .clock = .awake },
    );
    var shared = Shared{
        .server = &server,
        .io = io,
        .deadline = deadline,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x87} ** 32,
                .x25519_secret_key = [_]u8{0x88} ** 32,
            } },
            .{
                .authority = "localhost",
                .path = "/slow-response",
            },
            deadline,
        ),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.received_connect);
}

test "WebSocket HTTP3 pending decision keeps the original deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };
    const client_cid = [_]u8{ 0x72, 0x73, 0x74, 0x75 };
    const server_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x89} ** 32,
            .x25519_secret_key = [_]u8{0x8a} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(1),
            );
            defer pending.deinit();
            try std.Io.sleep(
                self.server.transport.quic_server.endpoint.io,
                .fromMilliseconds(1100),
                .awake,
            );
            try std.testing.expectError(error.Timeout, pending.accept());
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    try std.testing.expectError(
        error.RequestRejected,
        h3.Client.connectWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x8b} ** 32,
                .x25519_secret_key = [_]u8{0x8c} ** 32,
            } },
            .{ .authority = "localhost", .path = "/decision-timeout" },
            .fromSeconds(3),
        ),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 deadline APIs reject invalid budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client: http3.runtime.HandshakeClient = undefined;
    var server_session: http3.runtime.HandshakeServerSession = undefined;

    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectSessionWithTimeout(
            std.testing.allocator,
            &client,
            .{ .authority = "localhost" },
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        h3.Server.acceptSessionWithTimeout(
            std.testing.allocator,
            &server_session,
            .{},
            .zero,
        ),
    );
    _ = io;
}

test "WebSocket HTTP3 URI derives authority path query and SNI" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x35} ** 32,
            .x25519_secret_key = [_]u8{0x36} ** 32,
        } },
    );
    defer server.deinit();
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();

    const Shared = struct {
        server: *h3.Server,
        expected_authority: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.transport.acceptWithTimeout(
                .fromSeconds(2),
            );
            defer session.deinit();
            try session.ensureSettingsSent();
            while (true) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(2),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqualStrings(
                                "/chat/room?token=a%2Fb",
                                head.request.path,
                            );
                            try std.testing.expectEqualStrings(
                                self.expected_authority,
                                head.request.authority.?,
                            );
                            try std.testing.expectEqualStrings(
                                "permessage-deflate",
                                for (head.request.headers) |header| {
                                    if (std.ascii.eqlIgnoreCase(
                                        header.name,
                                        "sec-websocket-extensions",
                                    )) break header.value;
                                } else return error.TestUnexpectedResult,
                            );
                            try session.startResponse(
                                message.stream_id,
                                .{
                                    .status = 200,
                                    .request_method = "CONNECT",
                                    .extended_connect = true,
                                },
                                null,
                            );
                            return;
                        },
                        else => return error.TestUnexpectedResult,
                    },
                }
            }
        }
    };

    const port = server.address().getPort();
    const Resolver = struct {
        silent_address: std.Io.net.IpAddress,
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            expected_port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) h3.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "ws-h3.resolver.test") or
                expected_port != self.address.getPort() or deadline == null)
            {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                2,
            );
            addresses[0] = self.silent_address;
            addresses[1] = self.address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .silent_address = silent.address(),
        .address = server.address(),
    };
    const authority = try std.fmt.allocPrint(
        allocator,
        "ws-h3.resolver.test:{d}",
        .{port},
    );
    defer allocator.free(authority);
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://{s}/chat/room?token=a%2Fb",
        .{authority},
    );
    defer allocator.free(uri);
    var shared = Shared{
        .server = &server,
        .expected_authority = authority,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connectUriWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .h3_limits = limits,
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .random = [_]u8{0x37} ** 32,
                    .x25519_secret_key = [_]u8{0x38} ** 32,
                },
                .address_resolver = .{
                    .context = &resolver,
                    .resolve = Resolver.resolve,
                },
                .address_attempt_timeout = .fromSeconds(2),
                .address_connect_policy = .{ .happy_eyeballs = .{
                    .attempt_delay = .fromMilliseconds(20),
                    .max_in_flight = 2,
                } },
            },
        },
        .fromSeconds(2),
    );
    defer client.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "WebSocket HTTP3 URI rejects non-HTTPS and userinfo before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const options = h3.UriConnectOptions{
        .h3 = .{ .handshake = .{
            .original_destination_connection_id = "original",
            .local_connection_id = "local",
        } },
    };
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectUri(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "http://example.com/chat",
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectUri(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://user@example.com/chat",
            options,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        h3.Client.connectUriWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://localhost/chat",
            options,
            .zero,
        ),
    );
}

test "WebSocket HTTP3 connect attempt preserves rejection metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{ .allowed_origins = &.{"https://example.test"} },
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings("/private", pending.target());
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority() orelse return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "Bearer bad-token",
                pending.header("authorization") orelse
                    return error.TestUnexpectedResult,
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.header("origin") orelse
                    return error.TestUnexpectedResult,
            );
            try pending.rejectWithBody(
                401,
                &.{.{
                    .name = "www-authenticate",
                    .value = "Bearer realm=chat",
                }},
                "token expired",
                &.{.{
                    .name = "x-rejection-code",
                    .value = "expired",
                }},
            );
            pending_owned = false;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/private",
            .origin = "https://example.test",
            .extra_headers = &.{.{
                .name = "authorization",
                .value = "Bearer bad-token",
            }},
        },
        .fromSeconds(2),
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer realm=chat",
        attempt.responseHeader("WWW-Authenticate").?,
    );
    try std.testing.expectEqualStrings("13", attempt.responseHeader(
        "content-length",
    ).?);
    try std.testing.expectEqualStrings("token expired", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-rejection-code",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "expired",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(error.InvalidResponse, attempt.requireAccepted());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller session attempt restores after rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };
    const client_cid = [_]u8{ 0x22, 0x23, 0x24, 0x25 };
    const server_cid = [_]u8{ 0x32, 0x33, 0x34, 0x35 };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x36} ** 32,
                .x25519_secret_key = [_]u8{0x37} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.ensureSettingsSent();
            var oversized_stream_ids: [2]?u62 = .{ null, null };
            var reset_seen = [_]bool{false} ** 2;
            var reset_count: usize = 0;
            for (0..5) |attempt_index| {
                while (true) {
                    var connect_event = try session
                        .receiveRequestEventWithTimeout(.fromSeconds(3));
                    defer connect_event.deinit(allocator);
                    switch (connect_event) {
                        .reset => |reset| {
                            var matched: ?usize = null;
                            for (oversized_stream_ids, 0..) |candidate, index| {
                                if (candidate == reset.stream_id) {
                                    matched = index;
                                    break;
                                }
                            }
                            const index = matched orelse
                                return error.TestUnexpectedResult;
                            if (reset_seen[index]) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqual(
                                @as(
                                    u64,
                                    http3.ApplicationErrorCode.request_cancelled,
                                ),
                                reset.application_error_code,
                            );
                            reset_seen[index] = true;
                            reset_count += 1;
                            if (reset_count > 2) {
                                return error.TestUnexpectedResult;
                            }
                        },
                        .message => |message| switch (message.value) {
                            .head => |head| {
                                if (head != .request) {
                                    return error.TestUnexpectedResult;
                                }
                                try std.testing.expectEqualStrings(
                                    "CONNECT",
                                    head.request.method,
                                );
                                try std.testing.expectEqualStrings(
                                    switch (attempt_index) {
                                        0 => "/private",
                                        1 => "/legacy",
                                        2 => "/declared-oversized",
                                        3 => "/streamed-oversized",
                                        else => "/trailers-only",
                                    },
                                    head.request.path,
                                );
                                if (attempt_index == 2 or attempt_index == 3) {
                                    oversized_stream_ids[attempt_index - 2] =
                                        message.stream_id;
                                }
                                const response_headers: []const http3.Qpack.HeaderField =
                                    if (attempt_index == 4)
                                        &.{
                                            .{
                                                .name = "www-authenticate",
                                                .value = "Bearer realm=session",
                                            },
                                            .{
                                                .name = "content-length",
                                                .value = "0",
                                            },
                                        }
                                    else
                                        &.{.{
                                            .name = "www-authenticate",
                                            .value = "Bearer realm=session",
                                        }};
                                const response: http3.Response = .{
                                    .status = 401,
                                    .headers = response_headers,
                                    .body = switch (attempt_index) {
                                        0 => "session expired",
                                        1 => "legacy expired",
                                        2 => "oversized",
                                        else => "",
                                    },
                                    .trailers = &.{.{
                                        .name = "x-rejection-code",
                                        .value = "expired",
                                    }},
                                    .request_method = "CONNECT",
                                    .extended_connect = true,
                                };
                                if (attempt_index == 0) {
                                    try session.sendResponseWithInformational(
                                        message.stream_id,
                                        &.{.{
                                            .status = 103,
                                            .headers = &.{.{
                                                .name = "link",
                                                .value = "</auth>; rel=preload",
                                            }},
                                        }},
                                        response,
                                    );
                                } else if (attempt_index == 1 or
                                    attempt_index == 3)
                                {
                                    try session.startResponse(
                                        message.stream_id,
                                        .{
                                            .status = response.status,
                                            .headers = response.headers,
                                            .request_method = "CONNECT",
                                            .extended_connect = true,
                                        },
                                        null,
                                    );
                                    try session.sendResponseBodyPaced(
                                        message.stream_id,
                                        if (attempt_index == 1)
                                            "legacy "
                                        else
                                            "over",
                                        false,
                                    );
                                    try session.sendResponseBodyPaced(
                                        message.stream_id,
                                        if (attempt_index == 1)
                                            "expired"
                                        else
                                            "sized",
                                        false,
                                    );
                                    try session.finishResponseTrailersPaced(
                                        message.stream_id,
                                        response.trailers,
                                    );
                                } else {
                                    try session.sendResponsePaced(
                                        message.stream_id,
                                        response,
                                    );
                                }
                                break;
                            },
                            .finished => {},
                            .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                        },
                    }
                }
            }

            var sibling_sent = false;
            while (!sibling_sent or reset_count != 2) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(3),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => |reset| {
                        var matched: ?usize = null;
                        for (oversized_stream_ids, 0..) |candidate, index| {
                            if (candidate == reset.stream_id) {
                                matched = index;
                                break;
                            }
                        }
                        const index = matched orelse
                            return error.TestUnexpectedResult;
                        if (reset_seen[index]) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqual(
                            @as(
                                u64,
                                http3.ApplicationErrorCode.request_cancelled,
                            ),
                            reset.application_error_code,
                        );
                        reset_seen[index] = true;
                        reset_count += 1;
                        if (reset_count > 2) {
                            return error.TestUnexpectedResult;
                        }
                    },
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (sibling_sent) {
                                return error.TestUnexpectedResult;
                            }
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqualStrings(
                                "/sibling",
                                head.request.path,
                            );
                            try session.sendResponsePaced(message.stream_id, .{
                                .status = 204,
                                .request_method = head.request.method,
                            });
                            sibling_sent = true;
                        },
                        .finished => {},
                        .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                    },
                }
            }
            try std.testing.expectEqual(@as(usize, 2), reset_count);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x38} ** 32,
                .x25519_secret_key = [_]u8{0x39} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer client.deinit();
    var attempt = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/private" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "Bearer realm=session",
        attempt.responseHeader("www-authenticate").?,
    );
    try std.testing.expectEqualStrings("session expired", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "expired",
        attempt.trailers()[0].value,
    );
    attempt.deinit();
    try std.testing.expectError(
        error.InvalidResponse,
        h3.Client.connectSessionWithTimeout(
            allocator,
            &client,
            .{ .authority = "localhost", .path = "/legacy" },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{
                .authority = "localhost",
                .path = "/declared-oversized",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{
                .authority = "localhost",
                .path = "/streamed-oversized",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
            .fromSeconds(3),
        ),
    );
    var trailers_only = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/trailers-only" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 401), trailers_only.status());
    try std.testing.expectEqual(@as(usize, 0), trailers_only.body().len);
    try std.testing.expectEqualStrings(
        "0",
        trailers_only.responseHeader("content-length").?,
    );
    try std.testing.expectEqual(@as(usize, 1), trailers_only.trailers().len);
    try std.testing.expectEqualStrings(
        "expired",
        trailers_only.trailers()[0].value,
    );
    trailers_only.deinit();

    var sibling = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller server session restores after rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 };
    const client_cid = [_]u8{ 0x52, 0x53, 0x54, 0x55 };
    const server_cid = [_]u8{ 0x62, 0x63, 0x64, 0x65 };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x66} ** 32,
                .x25519_secret_key = [_]u8{0x67} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();

            var rejected = try h3.Server.receiveSessionUpgradeRequestWithTimeout(
                allocator,
                &session,
                .{},
                .fromSeconds(3),
            );
            try std.testing.expectEqualStrings(
                "/rejected",
                rejected.target(),
            );
            var rejected_response = try rejected.rejectWithBodyRetained(
                403,
                &.{.{ .name = "x-admission", .value = "denied" }},
                "not allowed",
                &.{.{ .name = "x-final", .value = "true" }},
            );
            try std.testing.expectEqual(
                @as(u16, 403),
                rejected_response.status,
            );
            rejected_response.deinit();

            var dropped = try h3.Server.receiveSessionUpgradeRequestWithTimeout(
                allocator,
                &session,
                .{},
                .fromSeconds(3),
            );
            try std.testing.expectEqualStrings(
                "/dropped",
                dropped.target(),
            );
            dropped.deinit();

            var sibling = try session.receiveRequestWithTimeout(
                .fromSeconds(3),
            );
            defer sibling.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/sibling",
                sibling.request.path,
            );
            try session.sendResponsePaced(sibling.stream_id, .{
                .status = 204,
                .request_method = sibling.request.method,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x68} ** 32,
                .x25519_secret_key = [_]u8{0x69} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer client.deinit();

    var rejected = try h3.Client.connectSessionAttemptWithTimeout(
        allocator,
        &client,
        .{ .authority = "localhost", .path = "/rejected" },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 403), rejected.status());
    try std.testing.expectEqualStrings("denied", rejected.responseHeader(
        "x-admission",
    ).?);
    try std.testing.expectEqualStrings("not allowed", rejected.body());
    try std.testing.expectEqualStrings(
        "true",
        rejected.trailers()[0].value,
    );
    rejected.deinit();

    try std.testing.expectError(
        error.RequestRejected,
        h3.Client.connectSessionAttemptWithTimeout(
            allocator,
            &client,
            .{ .authority = "localhost", .path = "/dropped" },
            .fromSeconds(3),
        ),
    );

    var sibling = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

const H3Utf8ReceiveMode = enum {
    caller_buffer,
    owned_message,
    compressed_owned_message,
    frame,
    fragmented_frames,
};

fn expectH3InvalidUtf8RejectedBeforeFrameCompletion(
    receive_mode: H3Utf8ReceiveMode,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const transport_limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const websocket_limits: @import("common.zig").Limits = .{
        .max_frame_bytes = 1024,
        .max_message_bytes = 1024,
    };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        transport_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb5} ** 32,
                .x25519_secret_key = [_]u8{0xb6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        receive_mode: H3Utf8ReceiveMode,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = self.receive_mode == .compressed_owned_message,
                .limits = websocket_limits,
            });
            defer connection.deinit();
            switch (self.receive_mode) {
                .caller_buffer => {
                    var storage: [websocket_limits.max_message_bytes]u8 =
                        undefined;
                    try std.testing.expectError(
                        error.InvalidUtf8,
                        connection.receiveMessageIntoWithTimeout(
                            &storage,
                            .fromSeconds(5),
                        ),
                    );
                },
                .owned_message, .compressed_owned_message => try std.testing.expectError(
                    error.InvalidUtf8,
                    connection.receiveMessageWithTimeout(.fromSeconds(5)),
                ),
                .frame => try std.testing.expectError(
                    error.InvalidUtf8,
                    connection.receiveFrameWithTimeout(.fromSeconds(5)),
                ),
                .fragmented_frames => {
                    var first = try connection.receiveFrameWithTimeout(
                        .fromSeconds(5),
                    );
                    defer first.deinit(allocator);
                    try std.testing.expectEqual(
                        websocket.Opcode.text,
                        first.header.opcode,
                    );
                    try std.testing.expect(!first.header.fin);
                    try std.testing.expectEqualSlices(
                        u8,
                        &.{0xf4},
                        first.payload,
                    );
                    try std.testing.expectError(
                        error.InvalidUtf8,
                        connection.receiveFrameWithTimeout(.fromSeconds(5)),
                    );
                },
            }
            try std.testing.expect(
                h3.testing.receiveStorageReleased(&connection),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.receiveFrameWithTimeout(.fromMilliseconds(1)),
            );
        }
    };

    var shared = Shared{
        .server = &server,
        .receive_mode = receive_mode,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        transport_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb7} ** 32,
                .x25519_secret_key = [_]u8{0xb8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/utf8-fail-fast",
            .enable_permessage_deflate = receive_mode == .compressed_owned_message,
            .limits = websocket_limits,
        },
    );
    defer client.deinit();

    // Advertise a 1024-byte masked text frame, then send only the header and
    // the two bytes that prove F4 90 cannot encode a Unicode scalar. With
    // five-byte QUIC STREAM chunks, the receiver must reject this prefix
    // rather than wait forever for the other 1022 payload bytes.
    const mask_key = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    if (receive_mode == .fragmented_frames) {
        var first_header_storage: [websocket.max_frame_header_len]u8 =
            undefined;
        const first_header = try websocket.writeFrameHeaderForLengthInto(
            &first_header_storage,
            .text,
            1,
            .{ .fin = false, .mask_key = mask_key },
        );
        var second_header_storage: [websocket.max_frame_header_len]u8 =
            undefined;
        const second_header = try websocket.writeFrameHeaderForLengthInto(
            &second_header_storage,
            .continuation,
            websocket_limits.max_frame_bytes,
            .{ .mask_key = mask_key },
        );
        var wire_prefix: [2 * websocket.max_frame_header_len + 2]u8 =
            undefined;
        var wire_len: usize = 0;
        @memcpy(wire_prefix[wire_len..][0..first_header.len], first_header);
        wire_len += first_header.len;
        wire_prefix[wire_len] = 0xf4 ^ mask_key[0];
        wire_len += 1;
        @memcpy(wire_prefix[wire_len..][0..second_header.len], second_header);
        wire_len += second_header.len;
        wire_prefix[wire_len] = 0x90 ^ mask_key[0];
        wire_len += 1;
        try client.h3.sendRequestBodyPaced(
            client.stream_id,
            wire_prefix[0..wire_len],
            false,
        );
    } else if (receive_mode == .compressed_owned_message) {
        const compressed = try websocket.compressMessage(
            allocator,
            "\xc0\x80",
        );
        defer allocator.free(compressed);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .text,
            compressed.len,
            .{ .mask_key = mask_key, .rsv1 = true },
        );
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(allocator);
        try wire.ensureTotalCapacity(
            allocator,
            header.len + compressed.len,
        );
        wire.appendSliceAssumeCapacity(header);
        const masked = wire.addManyAsSliceAssumeCapacity(compressed.len);
        try websocket.applyMaskCopy(masked, compressed, mask_key, 0);
        try client.h3.sendRequestBodyPaced(
            client.stream_id,
            wire.items,
            false,
        );
    } else {
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .text,
            websocket_limits.max_frame_bytes,
            .{ .mask_key = mask_key },
        );
        var wire_prefix: [websocket.max_frame_header_len + 2]u8 = undefined;
        @memcpy(wire_prefix[0..header.len], header);
        wire_prefix[header.len] = 0xf4 ^ mask_key[0];
        wire_prefix[header.len + 1] = 0x90 ^ mask_key[1];
        try client.h3.sendRequestBodyPaced(
            client.stream_id,
            wire_prefix[0 .. header.len + 2],
            false,
        );
    }

    var close = (try client.receiveCloseFrameWithTimeout(
        .fromSeconds(5),
    )).?;
    defer close.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.invalid_payload_data,
        close.code,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 caller-buffer rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.caller_buffer);
}

test "WebSocket HTTP3 owned message rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.owned_message);
}

test "WebSocket HTTP3 compressed owned text releases invalid UTF-8 once" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(
        .compressed_owned_message,
    );
}

fn expectH3FatalPendingAbort(opcode: websocket.Opcode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x55} ** 32,
                .x25519_secret_key = [_]u8{0x56} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        opcode: websocket.Opcode,
        client_ready: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.transport.quic_server.endpoint.io);
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            try self.client_ready.wait(
                self.server.transport.quic_server.endpoint.io,
            );
            const payload: []const u8 = if (self.opcode == .close)
                "\x03\xe8"
            else if (self.opcode == .binary)
                "retained h3 payload " ** 8
            else
                "retained h3 payload";
            if (self.opcode == .binary) {
                connection.permessage_deflate = true;
                connection.compression_send_context_takeover = true;
                connection.compression_threshold = 0;
            }
            switch (self.opcode) {
                .binary => try h3.testing.beginPendingMessage(
                    &connection,
                    .binary,
                    payload,
                ),
                .ping, .close => try h3.testing.beginPendingControl(
                    &connection,
                    self.opcode,
                    payload,
                ),
                .pong => try h3.testing.queueAutomaticControl(
                    &connection,
                    .pong,
                    payload,
                ),
                else => unreachable,
            }
            if (self.opcode == .binary) {
                try std.testing.expect(
                    connection.compression_send.previewPending(),
                );
            }
            switch (self.opcode) {
                .binary => h3.testing.markPendingMessageCommitted(
                    &connection,
                    1,
                ),
                .ping, .close => h3.testing.markPendingControlCommitted(
                    &connection,
                    self.opcode,
                    1,
                ),
                .pong => {},
                else => unreachable,
            }
            h3.testing.failReceiveAndFinish(
                &connection,
                .invalid_payload_data,
            );
            try std.testing.expect(h3.testing.writeAborted(&connection));
            try std.testing.expect(
                h3.testing.outboundStorageReleased(&connection),
            );
            try std.testing.expectEqual(
                http3.ApplicationErrorCode.request_cancelled,
                connection.h3.established.connection.sendStreamStats(
                    connection.stream_id,
                ).?.reset.?.application_error_code,
            );
            try std.testing.expectEqual(
                http3.ApplicationErrorCode.request_cancelled,
                connection.h3.established.connection.recvStreamStats(
                    connection.stream_id,
                ).?.stop_sending_sent.?.application_error_code,
            );
            var progress: h3.MessageWriteProgress = .{};
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.sendBinaryWithTimeout(
                    payload,
                    &progress,
                    .fromSeconds(1),
                ),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.sendClose(.normal_closure, ""),
            );
        }
    };
    var shared = Shared{ .server = &server, .opcode = opcode };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.client_ready.set(io);
        thread.join();
    };

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x57} ** 32,
            .x25519_secret_key = [_]u8{0x58} ** 32,
        } },
        .{ .authority = "localhost", .path = "/fatal-pending" },
    );
    defer client.deinit();
    shared.client_ready.set(io);
    try shared.done.wait(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 fatal receive cancels pending stream transactions" {
    try expectH3FatalPendingAbort(.binary);
    try expectH3FatalPendingAbort(.ping);
    try expectH3FatalPendingAbort(.close);
    try expectH3FatalPendingAbort(.pong);
}

test "WebSocket HTTP3 frame rejects invalid UTF-8 before frame completion" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.frame);
}

test "WebSocket HTTP3 frame validation spans fragmented receive calls" {
    try expectH3InvalidUtf8RejectedBeforeFrameCompletion(.fragmented_frames);
}

test "WebSocket HTTP3 caller-buffer resumes a partially streamed frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const payload = "0123456789abcdef" ** 64;
    const prefix_len = 512;
    const transport_limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const websocket_limits: @import("common.zig").Limits = .{
        .max_frame_bytes = payload.len,
        .max_message_bytes = payload.len,
    };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        transport_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xe5} ** 32,
                .x25519_secret_key = [_]u8{0xe6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 2048 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        prefix_sent: std.Io.Event = .unset,
        resume_send: std.Io.Event = .unset,
        receive_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_sent.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .limits = websocket_limits,
            });
            defer connection.deinit();
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .text,
                payload.len,
                .{},
            );
            var prefix: [websocket.max_frame_header_len + prefix_len]u8 =
                undefined;
            @memcpy(prefix[0..header.len], header);
            @memcpy(
                prefix[header.len..][0..prefix_len],
                payload[0..prefix_len],
            );
            try connection.h3.sendResponseBodyPaced(
                connection.stream_id,
                prefix[0 .. header.len + prefix_len],
                false,
            );
            self.prefix_sent.set(self.io);
            try self.resume_send.wait(self.io);
            try connection.h3.sendResponseBodyPaced(
                connection.stream_id,
                payload[prefix_len..],
                false,
            );
            try self.receive_done.wait(self.io);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.resume_send.set(io);
        shared.receive_done.set(io);
        thread.join();
    };

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        transport_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xe7} ** 32,
                .x25519_secret_key = [_]u8{0xe8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 256 },
        },
        .{
            .authority = "localhost",
            .path = "/stream-into-resume",
            .limits = websocket_limits,
        },
    );
    defer client.deinit();

    try shared.prefix_sent.wait(io);
    var storage: [payload.len]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithTimeout(
            &storage,
            .fromMilliseconds(50),
        ),
    );
    try std.testing.expect(client.message_into.active());
    try std.testing.expectEqual(
        @as(usize, prefix_len),
        client.message_frame_receive.payload_written,
    );
    var other_storage: [payload.len]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        client.message_into.validateOutput(&other_storage),
    );
    try std.testing.expect(
        client.inbuf.capacity <= @import("message/buffer.zig").slab_size,
    );

    shared.resume_send.set(io);
    const message = client.receiveMessageIntoWithTimeout(
        &storage,
        .fromSeconds(5),
    ) catch |err| {
        shared.receive_done.set(io);
        thread.join();
        joined = true;
        if (shared.err) |send_err| return send_err;
        return err;
    };
    try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
    try std.testing.expectEqualStrings(payload, message.payload);
    try std.testing.expect(
        client.inbuf.capacity <= @import("message/buffer.zig").slab_size,
    );

    shared.receive_done.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP3 extended CONNECT exchanges frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const request_text = "hello over h3 hello over h3 hello over h3 hello over h3";
    const compressed_first = "h3-borrowed-prefix-";
    const compressed_second = "compressible-application-payload-" ** 32;
    const compressed_parts = compressed_first ++ compressed_second;
    const concurrent_a = "concurrent-a-" ** 32;
    const concurrent_b = "concurrent-b-" ** 32;
    const fallback_fragments = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7", "8",
        "9", "a", "b", "c", "d", "e", "f", "g",
    };
    const trailing_empty_parts = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "",
        "",
    };
    const trailing_empty_payload = "0123456789abcde";
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc4} ** 32,
                .x25519_secret_key = [_]u8{0xc5} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        io: std.Io,
        sibling_stream_id: u62 = 4,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .protocols = &.{"chat"},
                .allowed_origins = &.{"https://example.test"},
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .client_max_window_bits = 9,
                .server_max_window_bits = 9,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = compressed_parts.len,
                    .max_message_bytes = compressed_parts.len,
                },
            });
            defer connection.deinit();
            try std.testing.expectEqualStrings(
                "chat",
                connection.selectedProtocol().?,
            );
            try std.testing.expectEqualStrings(
                "h3",
                connection.negotiatedAlpn(),
            );
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                connection.compression_send_max_window_bits,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                connection.compression_receive_max_window_bits,
            );

            var receive_storage: [compressed_parts.len]u8 = undefined;
            const text = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.text, text.opcode);
            try std.testing.expectEqualStrings(request_text, text.payload);

            // A sibling request is deliberately sent before the WebSocket
            // DATA. The targeted CONNECT reader must leave that sibling
            // buffered instead of consuming it as an invalid WS event.
            var sibling_head = try connection.h3
                .receiveRequestEventForWithTimeout(
                self.sibling_stream_id,
                .fromSeconds(5),
            );
            defer sibling_head.deinit(allocator);
            try std.testing.expect(sibling_head == .message);
            try std.testing.expect(sibling_head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/sibling-while-websocket",
                sibling_head.message.value.head.request.path,
            );
            var sibling_finished = try connection.h3
                .receiveRequestEventForWithTimeout(
                self.sibling_stream_id,
                .fromSeconds(5),
            );
            defer sibling_finished.deinit(allocator);
            try std.testing.expect(sibling_finished == .message);
            try std.testing.expect(
                sibling_finished.message.value == .finished,
            );
            try connection.h3.sendResponse(
                self.sibling_stream_id,
                .{ .status = 204 },
            );

            const empty_slices = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                empty_slices.opcode,
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                empty_slices.payload.len,
            );

            const plain_parts = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, plain_parts.opcode);
            try std.testing.expectEqualStrings("abc", plain_parts.payload);

            const in_place = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, in_place.opcode);
            try std.testing.expectEqualStrings("mutable-h3", in_place.payload);
            const fallback = try connection.receiveMessageIntoWithTimeout(
                &receive_storage,
                .fromSeconds(5),
            );
            try std.testing.expectEqual(websocket.Opcode.binary, fallback.opcode);
            try std.testing.expectEqualStrings(
                "0123456789abcdefg",
                fallback.payload,
            );
            try connection.sendText("in-place-received");

            for (0..2) |_| {
                const compressed = try connection.receiveMessageIntoWithTimeout(
                    &receive_storage,
                    .fromSeconds(5),
                );
                try std.testing.expectEqual(
                    websocket.Opcode.binary,
                    compressed.opcode,
                );
                try std.testing.expectEqualStrings(
                    compressed_parts,
                    compressed.payload,
                );
            }
            var dependent = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer dependent.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                dependent.header.opcode,
            );
            try std.testing.expect(dependent.header.rsv1);
            try std.testing.expectError(
                error.InvalidFrame,
                websocket.decompressMessage(
                    allocator,
                    dependent.payload,
                    compressed_parts.len,
                ),
            );
            var owned = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer owned.deinit(allocator);
            try std.testing.expectEqualStrings(
                compressed_parts,
                owned.payload,
            );
            try std.testing.expect(owned.was_compressed);
            try connection.sendBinarySlices(&.{});
            try connection.sendBinarySlices(&.{ "a", "", "b", "c" });
            connection.permessage_deflate = false;
            try connection.sendBinarySlices(&trailing_empty_parts);
            connection.permessage_deflate = true;
            try connection.sendBinarySlices(&.{
                compressed_first,
                "",
                compressed_second[0..21],
                compressed_second[21..],
            });
            const compressed_ptr = connection.compression_send.payload
                .allocatedSlice().ptr;
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            connection.allocator = failing.allocator();
            {
                defer connection.allocator = allocator;
                failing.fail_index = failing.alloc_index;
                try connection.sendBinarySlices(&.{
                    compressed_first,
                    compressed_second[0..21],
                    "",
                    compressed_second[21..],
                });
                try std.testing.expect(!failing.has_induced_failure);
                try std.testing.expectEqual(
                    compressed_ptr,
                    connection.compression_send.payload.allocatedSlice().ptr,
                );
            }
            try connection.sendBinarySlices(&.{
                compressed_first,
                compressed_second,
            });
            try connection.sendBinary(compressed_parts);
            try h3.testing.writeFrame(&connection, .binary, "split-", false);
            try connection.sendPing("between-fragments");
            try h3.testing.writeFrame(
                &connection,
                .continuation,
                "message",
                true,
            );
            try connection.sendText("hello client");

            const Sender = struct {
                connection: *h3.ServerConnection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            var start: std.Io.Event = .unset;
            var senders = [_]Sender{
                .{
                    .connection = &connection,
                    .io = self.io,
                    .start = &start,
                    .payload = concurrent_a,
                },
                .{
                    .connection = &connection,
                    .io = self.io,
                    .start = &start,
                    .payload = concurrent_b,
                },
            };
            const sender_a = try std.Thread.spawn(.{}, Sender.run, .{&senders[0]});
            const sender_b = std.Thread.spawn(.{}, Sender.run, .{&senders[1]}) catch |err| {
                start.set(self.io);
                sender_a.join();
                return err;
            };
            start.set(self.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            var interleaved_pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer interleaved_pong.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.pong,
                interleaved_pong.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "between-fragments",
                interleaved_pong.payload,
            );

            var ping = try connection.pingWithTimeout(
                "server-probe",
                .fromSeconds(5),
            );
            defer ping.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.text,
                ping.application.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "client in flight",
                ping.application.payload,
            );
            var pong = try connection.continuePingWithTimeout(
                "server-probe",
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expect(pong == .pong);

            var close = try connection.closeWithTimeout(
                .{ .code = .normal_closure, .reason = "server-done" },
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.text,
                close.application.header.opcode,
            );
            try std.testing.expectEqualStrings(
                "before close",
                close.application.payload,
            );
            var closed = try connection.continueCloseWithTimeout(
                .fromSeconds(5),
            );
            defer closed.deinit(allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                closed.closed.?.code,
            );
            try std.testing.expectEqualStrings(
                "server-done",
                closed.closed.?.reason,
            );
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/chat",
            .origin = "https://example.test",
            .protocols = &.{"chat"},
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .client_max_window_bits = 9,
            .server_max_window_bits = 9,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = compressed_parts.len,
                .max_message_bytes = compressed_parts.len,
            },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings("chat", client.selectedProtocol().?);
    try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
    try std.testing.expect(client.permessage_deflate);
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_receive_max_window_bits,
    );
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_send_max_window_bits,
    );

    const sibling_stream_id = try client.h3.sendRequest(.{
        .method = "GET",
        .path = "/sibling-while-websocket",
        .authority = "localhost",
    });
    try std.testing.expectEqual(shared.sibling_stream_id, sibling_stream_id);
    try client.sendFragmented(.text, &.{
        request_text[0..20],
        request_text[20..],
    });
    var sibling_response = try client.h3.receiveResponseWithTimeout(
        sibling_stream_id,
        .fromSeconds(5),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 204),
        sibling_response.response.status,
    );
    try client.sendBinarySlices(&.{});
    try client.sendBinarySlices(&.{ "a", "", "b", "c" });
    // Compression is negotiated for later messages, but an individual frame
    // may remain uncompressed. Temporarily select that legal path to exercise
    // the mutable-buffer masking contract on this established H3 connection.
    client.permessage_deflate = false;
    var mutable_payload = [_]u8{ 'm', 'u', 't', 'a', 'b', 'l', 'e', '-', 'h', '3' };
    const original_payload = mutable_payload;
    try client.sendBinaryInPlace(&mutable_payload);
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_payload,
        &mutable_payload,
    ));
    try client.sendFragmented(.binary, &fallback_fragments);
    client.permessage_deflate = true;
    var in_place_ack = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer in_place_ack.deinit(allocator);
    try std.testing.expectEqualStrings("in-place-received", in_place_ack.payload);
    try client.sendBinarySlices(&.{
        compressed_first,
        "",
        compressed_second[0..21],
        compressed_second[21..],
    });
    const compressed_ptr = client.compression_send.payload.allocatedSlice().ptr;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    client.allocator = failing.allocator();
    {
        defer client.allocator = allocator;
        failing.fail_index = failing.alloc_index;
        try client.sendBinarySlices(&.{
            compressed_first,
            compressed_second[0..21],
            "",
            compressed_second[21..],
        });
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(
            compressed_ptr,
            client.compression_send.payload.allocatedSlice().ptr,
        );
    }
    try client.sendBinarySlices(&.{
        compressed_first,
        compressed_second,
    });
    try client.sendBinary(compressed_parts);
    var receive_storage: [compressed_parts.len]u8 = undefined;
    const empty_slices = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, empty_slices.opcode);
    try std.testing.expectEqual(@as(usize, 0), empty_slices.payload.len);
    const plain_parts = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, plain_parts.opcode);
    try std.testing.expect(!plain_parts.was_compressed);
    try std.testing.expectEqualStrings("abc", plain_parts.payload);
    const trailing_empty = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, trailing_empty.opcode);
    try std.testing.expect(!trailing_empty.was_compressed);
    try std.testing.expectEqualStrings(
        trailing_empty_payload,
        trailing_empty.payload,
    );
    for (0..2) |_| {
        const compressed = try client.receiveMessageIntoWithTimeout(
            &receive_storage,
            .fromSeconds(5),
        );
        try std.testing.expectEqual(websocket.Opcode.binary, compressed.opcode);
        try std.testing.expect(compressed.was_compressed);
        try std.testing.expectEqualStrings(compressed_parts, compressed.payload);
    }
    var dependent = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer dependent.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, dependent.header.opcode);
    try std.testing.expect(dependent.header.rsv1);
    try std.testing.expectError(
        error.InvalidFrame,
        websocket.decompressMessage(
            allocator,
            dependent.payload,
            compressed_parts.len,
        ),
    );
    var owned = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer owned.deinit(allocator);
    try std.testing.expectEqualStrings(compressed_parts, owned.payload);
    try std.testing.expect(owned.was_compressed);
    const fragmented = try client.receiveMessageIntoWithTimeout(
        &receive_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.binary, fragmented.opcode);
    try std.testing.expect(!fragmented.was_compressed);
    try std.testing.expectEqualStrings("split-message", fragmented.payload);
    var reply = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, reply.header.opcode);
    try std.testing.expectEqualStrings("hello client", reply.payload);
    var concurrent_first = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendText("client in flight");
    var server_ping = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer server_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, server_ping.header.opcode);
    try std.testing.expectEqualStrings("server-probe", server_ping.payload);
    try client.sendText("before close");
    var server_close = (try client.receiveCloseFrameWithTimeout(
        .fromSeconds(5),
    )).?;
    defer server_close.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        server_close.code,
    );
    try std.testing.expectEqualStrings("server-done", server_close.reason);
    // Receiving Close automatically echoes its exact payload. The server's
    // typed progress event therefore owns the same code and reason inspected
    // above rather than requiring an otherwise-invalid second Close frame.

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 compression defaults to no context takeover" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49 };
    const client_cid = [_]u8{ 0x52, 0x53, 0x54, 0x55 };
    const server_cid = [_]u8{ 0x62, 0x63, 0x64, 0x65 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x66} ** 32,
            .x25519_secret_key = [_]u8{0x67} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
            });
            defer connection.deinit();
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(
                !connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                !connection.compression_receive_context_takeover,
            );
            try connection.sendText("default-no-context");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x68} ** 32,
            .x25519_secret_key = [_]u8{0x69} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/default-no-context",
            .enable_permessage_deflate = true,
        },
    );
    defer client.deinit();
    try std.testing.expect(client.permessage_deflate);
    try std.testing.expect(!client.compression_send_context_takeover);
    try std.testing.expect(!client.compression_receive_context_takeover);
    var message = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("default-no-context", message.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 client rejects unoffered compression window" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79 };
    const client_cid = [_]u8{ 0x82, 0x83, 0x84, 0x85 };
    const server_cid = [_]u8{ 0x92, 0x93, 0x94, 0x95 };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x96} ** 32,
                .x25519_secret_key = [_]u8{0x97} ** 32,
            },
            .session = .{ .local_settings = .{
                .enable_connect_protocol = true,
            } },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            try session.ensureSettingsSent();
            while (true) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(5),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => return error.TestUnexpectedResult,
                    .message => |message| switch (message.value) {
                        .head => |head| {
                            if (head != .request) {
                                return error.TestUnexpectedResult;
                            }
                            try std.testing.expectEqualStrings(
                                "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
                                for (head.request.headers) |header| {
                                    if (std.ascii.eqlIgnoreCase(
                                        header.name,
                                        "sec-websocket-extensions",
                                    )) break header.value;
                                } else return error.TestUnexpectedResult,
                            );
                            try session.startResponse(
                                message.stream_id,
                                .{
                                    .status = 200,
                                    .headers = &.{.{
                                        .name = "sec-websocket-extensions",
                                        .value = "permessage-deflate; " ++
                                            "server_no_context_takeover; " ++
                                            "client_no_context_takeover; " ++
                                            "client_max_window_bits=15",
                                    }},
                                    .request_method = "CONNECT",
                                    .extended_connect = true,
                                },
                                null,
                            );
                            return;
                        },
                        else => return error.TestUnexpectedResult,
                    },
                }
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.InvalidExtension,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x98} ** 32,
                .x25519_secret_key = [_]u8{0x99} ** 32,
            } },
            .{
                .authority = "localhost",
                .path = "/invalid-takeover",
                .enable_permessage_deflate = true,
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP3 rejects reserved handshake metadata before IO" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xf4} ** 32,
            .x25519_secret_key = [_]u8{0xf5} ** 32,
        } },
    );
    defer server.deinit();

    try std.testing.expectError(
        error.InvalidHandshake,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xf2} ** 32,
                .x25519_secret_key = [_]u8{0xf3} ** 32,
            } },
            .{
                .authority = "localhost",
                .extra_headers = &.{.{
                    .name = "sec-websocket-version",
                    .value = "12",
                }},
            },
        ),
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        server.transport.acceptWithTimeout(.fromMilliseconds(20)),
    );
}

test "WebSocket over HTTP3 rejects peer without extended CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x85} ** 32,
            .x25519_secret_key = [_]u8{0x86} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            session.ensureSettingsSent() catch |err| {
                self.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.ExtendedConnectDisabled,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x83} ** 32,
                .x25519_secret_key = [_]u8{0x84} ** 32,
            } },
            .{ .authority = "localhost" },
        ),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP3 peer SETTINGS wait rejects an expired budget" {
    var client: http3.runtime.HandshakeClient = undefined;
    client.dispatcher_bound = false;
    try std.testing.expectError(
        error.Timeout,
        client.receivePeerSettingsWithTimeout(.zero),
    );
}

test "WebSocket HTTP3 control progress APIs reject expired budgets" {
    var client: h3.ClientConnection = undefined;
    client.receive_failed = .init(false);
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout("probe", .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.continuePingWithTimeout("probe", .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithTimeout(null, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveCloseFrameWithTimeout(.zero),
    );
    var message_storage: [1]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithTimeout(&message_storage, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.continueCloseWithTimeout(.zero),
    );

    // Empty Close is represented by an absent typed payload. This checks the
    // API contract independently of transport framing; the end-to-end test
    // above covers owned non-empty metadata and automatic echo.
    try std.testing.expect(
        (try websocket.parseClosePayloadOwned(
            std.testing.allocator,
            &.{},
        )) == null,
    );
}

test "WebSocket HTTP3 close deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(
            context: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            self.now_ns += 2 * std.time.ns_per_s;
            return result;
        }
    };

    const original_dcid =
        [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const client_cid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c };
    const server_cid = [_]u8{ 0x2d, 0x2e, 0x2f, 0x30 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x31} ** 32,
                .x25519_secret_key = [_]u8{0x32} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const reason = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{ .limits = .{
                .max_frame_bytes = 256,
                .max_message_bytes = 256,
            } });
            defer connection.deinit();
            var close = (try connection.receiveCloseFrameWithTimeout(
                .fromSeconds(5),
            )) orelse return error.TestUnexpectedResult;
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.CloseCode.normal_closure,
                close.code,
            );
            try std.testing.expectEqualStrings(reason, close.reason);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x33} ** 32,
                .x25519_secret_key = [_]u8{0x34} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/close-deadline" },
    );
    defer client.deinit();

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(
            .{ .code = .normal_closure, .reason = reason },
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + 1),
            },
        ),
    );
    const progress = h3.testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expect(fixed.send_calls > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    const send_calls_before_mismatch = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.closeWithDeadline(
            .{ .code = .going_away, .reason = "different" },
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(fixed.now_ns + std.time.ns_per_s),
            },
        ),
    );
    try std.testing.expectEqual(
        progress,
        h3.testing.pendingCloseProgress(&client).?,
    );
    try std.testing.expectEqual(
        send_calls_before_mismatch,
        fixed.send_calls,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.initiateKeyUpdate(),
    );

    client.h3.endpoint.io = fixed.delegate;
    var closed = try client.closeWithTimeout(
        .{ .code = .normal_closure, .reason = reason },
        .fromSeconds(5),
    );
    defer closed.deinit(allocator);
    try std.testing.expectEqual(
        websocket.CloseCode.normal_closure,
        closed.closed.?.code,
    );
    try std.testing.expectEqualStrings(reason, closed.closed.?.reason);
    try std.testing.expect(h3.testing.pendingCloseProgress(&client) == null);
    try std.testing.expect(client.close_sent.load(.acquire));
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    const send_calls_after_close = fixed.send_calls;
    try std.testing.expectError(
        error.ConnectionClosed,
        client.pingWithDeadline("after-close", .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + std.time.ns_per_s),
        }),
    );
    try std.testing.expectEqual(send_calls_after_close, fixed.send_calls);
    client.h3.endpoint.io = fixed.delegate;

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 ping deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,
        sleep_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            context: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.sleep_calls += 1;
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x51} ** 32,
                .x25519_secret_key = [_]u8{0x52} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = payload.len,
                    .max_message_bytes = payload.len,
                },
            });
            defer connection.deinit();
            var frame = try connection.receiveFrameWithDeadline(
                .fromNow(connection.h3.established.connection.endpoint.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            defer frame.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, frame.header.opcode);
            try std.testing.expectEqualStrings(payload, frame.payload);
            try connection.sendPong(payload);
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("after-ping", message.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x53} ** 32,
                .x25519_secret_key = [_]u8{0x54} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/ping-deadline" },
    );
    defer client.deinit();

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.pingWithDeadline(payload, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const progress = h3.testing.pendingPingProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(fixed.send_calls > 0);
    try std.testing.expectEqual(@as(usize, 0), fixed.sleep_calls);
    const send_calls_before_mismatch = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.pingWithTimeout("different", .fromSeconds(1)),
    );
    try std.testing.expectEqual(
        progress,
        h3.testing.pendingPingProgress(&client).?,
    );
    try std.testing.expectEqual(
        send_calls_before_mismatch,
        fixed.send_calls,
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromSeconds(1)),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.initiateKeyUpdate(),
    );

    client.h3.endpoint.io = fixed.delegate;
    var pong = try client.pingWithTimeout(payload, .fromSeconds(5));
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    try std.testing.expect(h3.testing.pendingPingProgress(&client) == null);
    try client.sendText("after-ping");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 bounded auto Pong resumes and returns one Ping" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(
            _: ?*anyopaque,
            _: std.Io.Timeout,
        ) std.Io.Cancelable!void {
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "automatic-pong-" ** 8;
    const Shared = struct {
        server: *h3.Server,
        accepted: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            self.accepted.set(
                self.server.transport.quic_server.endpoint.io,
            );
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings(payload, pong.payload);
            try connection.sendText("after-auto-pong");
            var second_pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer second_pong.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.pong,
                second_pong.header.opcode,
            );
            try std.testing.expectEqualStrings(payload, second_pong.payload);
            try connection.sendText("after-auto-pong-into");
            var close = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.close,
                close.header.opcode,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x73} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/auto-pong-deadline",
            .limits = .{
                .max_frame_bytes = 256,
                .max_message_bytes = 256,
            },
        },
    );
    defer client.deinit();
    try shared.accepted.wait(io);
    var encoded_ping: [websocket.max_frame_header_len + 125]u8 = undefined;
    const ping_bytes = try websocket.writeFrameInto(
        &encoded_ping,
        .ping,
        payload,
        .{},
    );
    try h3.testing.bufferInitial(&client, ping_bytes);

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, progress.opcode);
    try std.testing.expect(progress.committed > 0);
    try std.testing.expect(progress.committed < progress.total);
    try std.testing.expect(progress.retains_frame);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );

    client.h3.endpoint.io = fixed.delegate;
    var ping = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings(payload, ping.payload);
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );
    var message = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings("after-auto-pong", message.payload);

    // The caller-buffer path must resume its own retained automatic control
    // before checking for unrelated pending writers. The old ordering returned
    // WriteInProgress forever here.
    try h3.testing.bufferInitial(&client, ping_bytes);
    fixed.now_ns = @intCast(
        quic.one_rtt.testing.pacingBlockedUntil(
            &client.h3.established.connection,
        ) orelse @as(u64, @intCast(fixed.now_ns)),
    );
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    var into_storage: [256]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageIntoWithDeadline(&into_storage, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const into_progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.pong, into_progress.opcode);
    try std.testing.expect(into_progress.committed > 0);
    try std.testing.expect(into_progress.committed < into_progress.total);

    client.h3.endpoint.io = fixed.delegate;
    const into_message = try client.receiveMessageIntoWithTimeout(
        &into_storage,
        .fromSeconds(5),
    );
    try std.testing.expectEqual(websocket.Opcode.text, into_message.opcode);
    try std.testing.expectEqualStrings(
        "after-auto-pong-into",
        into_message.payload,
    );
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );

    var close_payload_storage: [125]u8 = undefined;
    const close_payload = try websocket.writeClosePayloadInto(
        &close_payload_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    var encoded_close: [websocket.max_frame_header_len + 125]u8 = undefined;
    const close_bytes = try websocket.writeFrameInto(
        &encoded_close,
        .close,
        close_payload,
        .{},
    );
    try h3.testing.bufferInitial(&client, close_bytes);
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveFrameWithDeadline(.{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    const close_progress = h3.testing
        .pendingAutomaticControlProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.Opcode.close, close_progress.opcode);
    try std.testing.expect(close_progress.committed > 0);
    try std.testing.expect(close_progress.committed < close_progress.total);
    try std.testing.expect(close_progress.retains_frame);
    try std.testing.expect(!client.close_sent.load(.acquire));

    client.h3.endpoint.io = fixed.delegate;
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    const close_detail = (try websocket.parseClosePayload(close.payload)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(websocket.CloseCode.going_away, close_detail.code);
    try std.testing.expectEqualStrings("restart", close_detail.reason);
    try std.testing.expect(client.close_sent.load(.acquire));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 Pong deadline resumes a partially sent frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c };
    const client_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x85} ** 32,
                .x25519_secret_key = [_]u8{0x86} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings(payload, pong.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x87} ** 32,
                .x25519_secret_key = [_]u8{0x88} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{ .authority = "localhost", .path = "/pong-deadline" },
    );
    defer client.deinit();

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendPongWithDeadline(payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    const send_calls = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendPongWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls);

    client.h3.endpoint.io = fixed.delegate;
    try client.sendPongWithTimeout(payload, &progress, .fromSeconds(5));
    try std.testing.expect(progress.frame_committed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 bounded in-place send masks once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const plain = "0123456789" ** 12;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .limits = .{
                    .max_frame_bytes = plain.len,
                    .max_message_bytes = plain.len,
                },
            });
            defer connection.deinit();
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualStrings(plain, message.payload);
            try connection.sendText("in-place-ok");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc3} ** 32,
                .x25519_secret_key = [_]u8{0xc4} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/in-place-deadline",
            .limits = .{
                .max_frame_bytes = plain.len,
                .max_message_bytes = plain.len,
            },
        },
    );
    defer client.deinit();

    var payload: [plain.len]u8 = undefined;
    @memcpy(&payload, plain);
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithDeadline(&payload, &progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqualStrings(plain, &payload);

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryInPlaceWithDeadline(&payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!std.mem.eql(u8, plain, &payload));
    const send_calls = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryInPlaceWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls);

    client.h3.endpoint.io = fixed.delegate;
    try client.sendBinaryInPlaceWithTimeout(
        &payload,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    var response = try client.receiveMessageWithTimeout(.fromSeconds(10));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("in-place-ok", response.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 message deadline resumes one masked frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "0123456789" ** 12;
    var first_part: [101]u8 = undefined;
    var second_part: [103]u8 = undefined;
    for (&first_part, 0..) |*byte, index| {
        byte.* = @truncate(index *% 37 +% 11);
    }
    for (&second_part, 0..) |*byte, index| {
        byte.* = @truncate(index *% 53 +% 19);
    }
    const parts = [_][]const u8{
        first_part[0..37],
        &.{},
        first_part[37..],
        second_part[0..51],
        second_part[51..],
    };
    const parts_len = first_part.len + second_part.len;
    const Shared = struct {
        server: *h3.Server,
        first_part: []const u8,
        second_part: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = parts_len,
                    .max_message_bytes = parts_len,
                },
            });
            defer connection.deinit();
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualStrings(payload, message.payload);
            var pong = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer pong.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
            try std.testing.expectEqualStrings("queued", pong.payload);
            var slices_message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer slices_message.deinit(allocator);
            try std.testing.expectEqual(
                websocket.Opcode.binary,
                slices_message.opcode,
            );
            try std.testing.expectEqual(parts_len, slices_message.payload.len);
            try std.testing.expectEqualSlices(
                u8,
                self.first_part,
                slices_message.payload[0..self.first_part.len],
            );
            try std.testing.expectEqualSlices(
                u8,
                self.second_part,
                slices_message.payload[self.first_part.len..],
            );
            const response_parts = [_][]const u8{
                "server-",
                &.{},
                "slices",
            };
            var progress: h3.MessageWriteProgress = .{};
            try connection.sendBinarySlicesWithTimeout(
                &response_parts,
                &progress,
                .fromSeconds(5),
            );
            try std.testing.expect(progress.frame_committed);
        }
    };
    var shared = Shared{
        .server = &server,
        .first_part = &first_part,
        .second_part = &second_part,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x73} ** 32,
                .x25519_secret_key = [_]u8{0x74} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/message-deadline",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = parts_len,
                .max_message_bytes = parts_len,
            },
        },
    );
    defer client.deinit();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);

    var invalid_progress: h3.MessageWriteProgress = .{
        .committed_bytes = 99,
        .total_bytes = 99,
        .frame_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithDeadline(payload, &invalid_progress, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectEqual(
        h3.MessageWriteProgress{},
        invalid_progress,
    );

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinaryWithDeadline(payload, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinaryWithTimeout(
            payload[1..],
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(
        (h3.testing.pendingMessageProgress(&client) orelse
            return error.TestUnexpectedResult).committed_bytes,
        progress.committed_bytes,
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave"),
    );
    try std.testing.expectError(
        error.WriteInProgress,
        client.receiveFrameWithTimeout(.fromSeconds(1)),
    );
    try h3.testing.queueAutomaticControl(&client, .pong, "queued");

    client.h3.endpoint.io = fixed.delegate;
    try client.sendBinaryWithTimeout(payload, &progress, .fromSeconds(10));
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(h3.testing.pendingMessageProgress(&client) == null);
    try std.testing.expect(!client.compression_send.previewPending());
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) != null,
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveMessageWithTimeout(.fromMilliseconds(100)),
    );
    try std.testing.expect(
        h3.testing.pendingAutomaticControlProgress(&client) == null,
    );
    fixed.now_ns = @intCast(
        quic.one_rtt.testing.pacingBlockedUntil(
            &client.h3.established.connection,
        ) orelse
            @as(u64, @intCast(fixed.now_ns)),
    );
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    progress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendBinarySlicesWithDeadline(&parts, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    const different_parts = [_][]const u8{ &first_part, &second_part };
    const send_calls_before_mismatch = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendBinarySlicesWithTimeout(
            &different_parts,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls_before_mismatch, fixed.send_calls);
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendText("must-not-interleave-slices"),
    );

    client.h3.endpoint.io = fixed.delegate;
    try client.sendBinarySlicesWithTimeout(
        &parts,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(h3.testing.pendingMessageProgress(&client) == null);

    var server_message = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer server_message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, server_message.opcode);
    try std.testing.expectEqualStrings(
        "server-slices",
        server_message.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 fragmented deadline resumes exact suffix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const FixedSendIo = struct {
        delegate: std.Io,
        now_ns: i96 = 1_000_000,
        send_calls: usize = 0,

        fn now(context: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            return error.Canceled;
        }

        fn netSend(
            context: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    const server_cid = [_]u8{ 0x9d, 0x9e, 0x9f, 0xa0 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
    );
    defer server.deinit();

    const payload = "fragmented-context-takeover-" ** 16;
    const fragments = [_][]const u8{
        payload[0..73],
        &.{},
        payload[73..181],
        payload[181..317],
        payload[317..],
    };
    const total = payload.len;
    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 1,
                .limits = .{
                    .max_frame_bytes = total,
                    .max_message_bytes = total,
                },
            });
            defer connection.deinit();
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(10),
            );
            defer message.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expect(message.was_compressed);
            try std.testing.expectEqualStrings(payload, message.payload);
            try connection.sendText("fragmented-ok");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 5,
                .max_frames_per_packet = 1,
            },
        },
        .{
            .authority = "localhost",
            .path = "/fragmented-deadline",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 1,
            .limits = .{
                .max_frame_bytes = total,
                .max_message_bytes = total,
            },
        },
    );
    defer client.deinit();
    try std.testing.expect(client.compression_send_context_takeover);

    var fixed = FixedSendIo{ .delegate = client.h3.endpoint.io };
    var vtable = fixed.delegate.vtable.*;
    vtable.now = FixedSendIo.now;
    vtable.sleep = FixedSendIo.sleep;
    vtable.netSend = FixedSendIo.netSend;
    client.h3.endpoint.io = .{ .userdata = &fixed, .vtable = &vtable };
    quic.one_rtt.testing.setPacingBudgetAt(
        &client.h3.established.connection,
        64,
        @intCast(fixed.now_ns),
    );
    var progress: h3.MessageWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendFragmentedWithDeadline(.binary, &fragments, &progress, .{
            .clock = .awake,
            .raw = .fromNanoseconds(fixed.now_ns + 1),
        }),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < progress.total_bytes);
    try std.testing.expect(!progress.frame_committed);
    try std.testing.expect(client.compression_send.previewPending());
    const different = [_][]const u8{payload};
    const send_calls = fixed.send_calls;
    try std.testing.expectError(
        error.WriteInProgress,
        client.sendFragmentedWithTimeout(
            .binary,
            &different,
            &progress,
            .fromSeconds(1),
        ),
    );
    try std.testing.expectEqual(send_calls, fixed.send_calls);

    client.h3.endpoint.io = fixed.delegate;
    try client.sendFragmentedWithTimeout(
        .binary,
        &fragments,
        &progress,
        .fromSeconds(10),
    );
    try std.testing.expect(progress.frame_committed);
    try std.testing.expectEqual(progress.total_bytes, progress.committed_bytes);
    try std.testing.expect(!client.compression_send.previewPending());
    var response = try client.receiveMessageWithTimeout(.fromSeconds(10));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("fragmented-ok", response.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 in-place binary send rejects unsupported modes" {
    var server: h3.ServerConnection = undefined;
    server.permessage_deflate = false;
    server.close_sent = .init(false);
    server.close_received = .init(false);
    server.receive_failed = .init(false);
    server.write_aborted = .init(false);
    server.application_write_pending = .init(false);
    server.automatic_write_pending = .init(false);
    server.limits = .{};
    const payload = [_]u8{1};
    try std.testing.expectError(
        error.InvalidFrame,
        h3.testing.validateBinaryInPlace(&server, payload.len),
    );

    var client: h3.ClientConnection = undefined;
    client.permessage_deflate = true;
    client.close_sent = .init(false);
    client.close_received = .init(false);
    client.receive_failed = .init(false);
    client.write_aborted = .init(false);
    client.application_write_pending = .init(false);
    client.automatic_write_pending = .init(false);
    client.limits = .{};
    try std.testing.expectError(
        error.InvalidFrame,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
    client.permessage_deflate = false;
    client.close_sent.store(true, .release);
    try std.testing.expectError(
        error.ConnectionClosed,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
    client.close_sent.store(false, .release);
    client.receive_failed.store(true, .release);
    try std.testing.expectError(
        error.ConnectionClosed,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
    try std.testing.expectError(error.ConnectionClosed, client.sendText("x"));
    client.receive_failed.store(false, .release);
    client.limits.max_frame_bytes = 0;
    try std.testing.expectError(
        error.MessageTooLarge,
        h3.testing.validateBinaryInPlace(&client, payload.len),
    );
}

test "WebSocket HTTP3 sends enforce configured outbound limits before IO" {
    var client: h3.ClientConnection = undefined;
    client.close_sent = .init(false);
    client.close_received = .init(false);
    client.receive_failed = .init(false);
    client.write_aborted = .init(false);
    client.application_write_pending = .init(false);
    client.automatic_write_pending = .init(false);
    client.permessage_deflate = true;
    client.limits = .{
        .max_frame_bytes = 4,
        .max_message_bytes = 6,
    };

    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendText("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinary("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinaryParts("abc", "de"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinarySlices(&.{ "a", "", "bc", "de" }),
    );
    client.permessage_deflate = false;
    var in_place_payload = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendBinaryInPlace(&in_place_payload),
    );
    client.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendPing("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendClose(.normal_closure, "abc"),
    );
}

test "WebSocket HTTP3 failed unbounded compressed send clears transaction" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad };
    const client_cid = [_]u8{ 0xb6, 0xb7, 0xb8, 0xb9 };
    const server_cid = [_]u8{ 0xc6, 0xc7, 0xc8, 0xc9 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xca} ** 32,
            .x25519_secret_key = [_]u8{0xcb} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        accepted: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.accepted.set(
                    self.server.transport.quic_server.endpoint.io,
                );
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 0,
            });
            defer connection.deinit();
            self.accepted.set(
                self.server.transport.quic_server.endpoint.io,
            );
            var head = try connection.h3.receiveRequestEventForWithTimeout(
                4,
                .fromSeconds(3),
            );
            defer head.deinit(allocator);
            try std.testing.expect(head == .message);
            try std.testing.expect(head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/after-failed-send",
                head.message.value.head.request.path,
            );
            var finished = try connection.h3
                .receiveRequestEventForWithTimeout(4, .fromSeconds(3));
            defer finished.deinit(allocator);
            try std.testing.expect(finished == .message);
            try std.testing.expect(finished.message.value == .finished);
            try connection.h3.sendResponse(4, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.accepted.set(io);
        thread.join();
    };

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xcc} ** 32,
            .x25519_secret_key = [_]u8{0xcd} ** 32,
        } },
        .{
            .authority = "localhost",
            .path = "/failed-compressed-send",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 0,
        },
    );
    defer client.deinit();
    try shared.accepted.wait(io);

    client.h3.abandonExtendedConnect(client.stream_id);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendText("compressible payload " ** 16),
    );
    try std.testing.expect(h3.testing.writeAborted(&client));
    try std.testing.expect(h3.testing.outboundStorageReleased(&client));
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendText("must-not-write"),
    );
    try std.testing.expect(client.h3.isReusable());

    var sibling = try client.h3.requestWithTimeout(.{
        .method = "GET",
        .path = "/after-failed-send",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 failed ordinary Close does not commit close state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        accepted: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            self.accepted.set(
                self.server.transport.quic_server.endpoint.io,
            );
            try self.done.wait(
                self.server.transport.quic_server.endpoint.io,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.done.set(io);
        thread.join();
    };

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
        .{ .authority = "localhost", .path = "/failed-close" },
    );
    defer client.deinit();
    try shared.accepted.wait(io);

    client.h3.abandonExtendedConnect(client.stream_id);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendClose(.normal_closure, "done"),
    );
    try std.testing.expect(!client.close_sent.load(.acquire));
    try std.testing.expect(h3.testing.writeAborted(&client));
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendClose(.normal_closure, "done"),
    );

    shared.done.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 abrupt FIN aborts only its request stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99 };
    const client_cid = [_]u8{ 0xa2, 0xa3, 0xa4, 0xa5 };
    const server_cid = [_]u8{ 0xb2, 0xb3, 0xb4, 0xb5 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb6} ** 32,
            .x25519_secret_key = [_]u8{0xb7} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.deinit();
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.receiveMessageWithTimeout(.fromSeconds(3)),
            );
            try std.testing.expect(h3.testing.receiveStorageReleased(&connection));
            try std.testing.expect(h3.testing.writeAborted(&connection));
            try std.testing.expect(h3.testing.outboundStorageReleased(&connection));
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.sendText("late"),
            );

            var head = try connection.h3.receiveRequestEventForWithTimeout(
                4,
                .fromSeconds(3),
            );
            defer head.deinit(allocator);
            try std.testing.expect(head == .message);
            try std.testing.expect(head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/sibling-after-abrupt-fin",
                head.message.value.head.request.path,
            );
            var finished = try connection.h3.receiveRequestEventForWithTimeout(
                4,
                .fromSeconds(3),
            );
            defer finished.deinit(allocator);
            try std.testing.expect(finished == .message);
            try std.testing.expect(finished.message.value == .finished);
            try connection.h3.sendResponse(4, .{ .status = 204 });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xb8} ** 32,
            .x25519_secret_key = [_]u8{0xb9} ** 32,
        } },
        .{ .authority = "localhost", .path = "/abrupt-fin" },
    );
    defer client.deinit();
    try h3.testing.writeFrame(&client, .text, "partial", false);
    try client.h3.sendRequestBodyPaced(client.stream_id, &.{}, true);

    const sibling_stream_id = try client.h3.sendRequest(.{
        .method = "GET",
        .path = "/sibling-after-abrupt-fin",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 4), sibling_stream_id);
    var sibling_response = try client.h3.receiveResponseWithTimeout(
        sibling_stream_id,
        .fromSeconds(3),
    );
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 fragmented compression has no plaintext join" {
    const allocator = std.testing.allocator;
    const payload = "h3-fragmented-payload-h3-fragmented-payload-" ** 64;
    const fragments = [_][]const u8{
        payload[0..777],
        payload[777..1555],
        payload[1555..],
    };
    const total = payload.len;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var scratch: @import("compression_scratch.zig").SendScratch = .{};
    defer scratch.deinit(failing.allocator());

    try scratch.prepare(failing.allocator(), total);
    _ = try websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
        &scratch.encoder.?,
        &scratch.payload,
        &fragments,
        15,
    );
    failing.fail_index = failing.alloc_index;
    try scratch.prepare(failing.allocator(), total);
    const compressed = try websocket
        .compressMessageFragmentsVortIntoWindowWithEncoder(
        &scratch.encoder.?,
        &scratch.payload,
        &fragments,
        15,
    );
    try std.testing.expect(compressed.len < total);
    try std.testing.expect(!failing.has_induced_failure);

    const valid_prefix = [_]u8{ 'v', 'a', 'l', 'i', 'd', ' ', 0xe2 };
    const valid_middle = [_]u8{0x82};
    const valid_suffix = [_]u8{ 0xac, ' ', 't', 'e', 'x', 't' };
    const invalid_prefix = [_]u8{ 'i', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 0xe2 };
    const invalid_suffix = [_]u8{'('};
    const split_utf8 = [_][]const u8{
        &valid_prefix,
        &valid_middle,
        &valid_suffix,
    };
    const invalid_utf8 = [_][]const u8{ &invalid_prefix, &invalid_suffix };
    try std.testing.expect(h3.testing.fragmentedTextIsValid(&split_utf8));
    try std.testing.expect(!h3.testing.fragmentedTextIsValid(&invalid_utf8));
    const first = h3.testing.compressedFragmentRangeForTest(10, 3, 0);
    const second = h3.testing.compressedFragmentRangeForTest(10, 3, 1);
    const third = h3.testing.compressedFragmentRangeForTest(10, 3, 2);
    try std.testing.expectEqual(@as(usize, 0), first.start);
    try std.testing.expectEqual(first.end, second.start);
    try std.testing.expectEqual(second.end, third.start);
    try std.testing.expectEqual(@as(usize, 10), third.end);
}
