const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const operation_timeout: std.Io.Duration = .fromSeconds(5);
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

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

test "WebTransport server admission exposes request and response metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xa0, 0x01, 0x57, 0x54, 0xa0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xa0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xa0, 0x04 };
    var request_headers: [80]http3.Qpack.HeaderField = undefined;
    request_headers[0] = .{
        .name = "authorization",
        .value = "Bearer permitted",
    };
    request_headers[1] = .{
        .name = "user-agent",
        .value = "netz-admission-test",
    };
    for (request_headers[2..]) |*header| {
        header.* = .{
            .name = "x-many-request",
            .value = large_header_value,
            .never_indexed = true,
        };
    }
    var response_headers: [80]http3.Qpack.HeaderField = undefined;
    response_headers[0] = .{ .name = "x-admission", .value = "accepted" };
    for (response_headers[1..]) |*header| {
        header.* = .{
            .name = "x-many-response",
            .value = large_header_value,
            .never_indexed = true,
        };
    }

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{ .quic = .{ .max_datagram_size = 1200 } },
            .origin_policy = .{
                .exact = &.{"https://example.test"},
            },
        },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
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
        server: *runtime.HandshakeServer,
        exporter: *[48]u8,
        exporter_ready: *std.atomic.Value(bool),
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequestWithTimeout(
                operation_timeout,
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expect(std.mem.startsWith(
                u8,
                pending.authority().?,
                "webtransport.resolver.test:",
            ));
            try std.testing.expectEqualStrings(
                "/authorized?room=7",
                pending.path(),
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.origin().?,
            );
            try std.testing.expectEqualStrings(
                "netz-admission-test",
                pending.userAgent().?,
            );
            try std.testing.expectEqualStrings(
                "Bearer permitted",
                findHeader(pending.headers(), "authorization").?,
            );
            try std.testing.expectEqual(
                @as(usize, 78),
                countHeaders(pending.headers(), "x-many-request"),
            );

            var accepted = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer accepted.deinit();
            try std.testing.expectEqual(
                @TypeOf(accepted.negotiatedCipherSuite()).aes_128_gcm_sha256,
                accepted.negotiatedCipherSuite(),
            );
            try std.testing.expectEqual(
                @TypeOf(accepted.negotiatedTranscriptHash()).sha256,
                accepted.negotiatedTranscriptHash(),
            );
            try accepted.exportKeyingMaterial(
                "EXPORTER-netz-webtransport",
                "admission",
                self.exporter,
            );
            self.exporter_ready.store(true, .release);
            const event = try accepted.receiveSessionEventWithTimeout(
                operation_timeout,
            );
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 71), event.closed.code);
        }
    };
    var server_exported: [48]u8 = undefined;
    var exporter_ready: std.atomic.Value(bool) = .init(false);
    var shared = Shared{
        .server = &server,
        .exporter = &server_exported,
        .exporter_ready = &exporter_ready,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const Resolver = struct {
        silent_address: std.Io.net.IpAddress,
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "webtransport.resolver.test") or
                port != self.address.getPort() or deadline == null)
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
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://webtransport.resolver.test:{d}/authorized?room=7",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.HandshakeClientSession.connectUriWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .origin = "https://example.test",
            .headers = &request_headers,
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 1200,
            } } },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .random = [_]u8{0xa1} ** 32,
                    .x25519_secret_key = [_]u8{0xa2} ** 32,
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
        operation_timeout,
    );
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 200), client.response.status);
    try std.testing.expectEqual(client.session_id, client.sessionId());
    try std.testing.expectEqual(server.address(), client.remoteAddress());
    try std.testing.expect(client.remoteAddressValidated());
    try std.testing.expect(client.rttNanos() != null);
    try std.testing.expectEqual(
        @TypeOf(client.negotiatedCipherSuite()).aes_128_gcm_sha256,
        client.negotiatedCipherSuite(),
    );
    try std.testing.expectEqual(
        @TypeOf(client.negotiatedTranscriptHash()).sha256,
        client.negotiatedTranscriptHash(),
    );
    var client_exported: [48]u8 = undefined;
    try client.exportKeyingMaterial(
        "EXPORTER-netz-webtransport",
        "admission",
        &client_exported,
    );
    while (!exporter_ready.load(.acquire)) std.atomic.spinLoopHint();
    try std.testing.expectEqualSlices(
        u8,
        &client_exported,
        &server_exported,
    );
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-admission").?,
    );
    try std.testing.expectEqual(
        @as(usize, 79),
        countHeaders(client.response.headers, "x-many-response"),
    );
    try client.close(71, "done");
    const peer_fin = try client.receiveSessionEventWithTimeout(
        operation_timeout,
    );
    try std.testing.expect(peer_fin == .closed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "WebTransport server admission sends explicit rejection response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xb0, 0x01, 0x57, 0x54, 0xb0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xb0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xb0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb3} ** 32,
            .x25519_secret_key = [_]u8{0xb4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequestWithTimeout(
                operation_timeout,
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/missing",
                pending.path(),
            );
            var rejected = try pending.rejectWithBody(
                404,
                &.{.{
                    .name = "x-rejection",
                    .value = "route-not-found",
                }},
                "missing session",
                &.{.{ .name = "x-final", .value = "true" }},
            );
            pending_owned = false;
            defer rejected.deinit();
            try std.testing.expectEqual(@as(u16, 404), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.HandshakeClientSession.connectAttempt(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/missing",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            } },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 404), attempt.status());
    try std.testing.expectEqualStrings(
        "route-not-found",
        attempt.responseHeader("x-rejection").?,
    );
    try std.testing.expectEqualStrings(
        "15",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("missing session", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport caller-owned H3 session survives rejected CONNECT attempts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xc0, 0x01, 0x57, 0x54, 0xc0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x04 };

    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc3} ** 32,
                .x25519_secret_key = [_]u8{0xc4} ** 32,
            },
            .session = .{ .local_settings = webtransport.defaultSettings(.{}) },
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
            for (0..4) |attempt_index| {
                while (true) {
                    var event = try session
                        .receiveRequestEventWithTimeout(.fromSeconds(3));
                    defer event.deinit(allocator);
                    switch (event) {
                        .reset => continue,
                        .message => |message| switch (message.value) {
                            .head => |head| {
                                if (head != .request) {
                                    return error.TestUnexpectedResult;
                                }
                                try std.testing.expectEqualStrings(
                                    switch (attempt_index) {
                                        0 => "/attempt",
                                        1 => "/legacy",
                                        2 => "/declared-oversized",
                                        else => "/streamed-oversized",
                                    },
                                    head.request.path,
                                );
                                const response: http3.Response = .{
                                    .status = 404,
                                    .headers = &.{.{
                                        .name = "x-rejection",
                                        .value = "missing",
                                    }},
                                    .body = switch (attempt_index) {
                                        0 => "attempt missing",
                                        1 => "legacy missing",
                                        2 => "declared oversized",
                                        else => "streamed oversized",
                                    },
                                    .trailers = &.{.{
                                        .name = "x-final",
                                        .value = "true",
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
                                                .value = "</quota>; rel=preload",
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
                                            "streamed ",
                                        false,
                                    );
                                    try session.sendResponseBodyPaced(
                                        message.stream_id,
                                        if (attempt_index == 1)
                                            "missing"
                                        else
                                            "oversized",
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

            while (true) {
                var event = try session.receiveRequestEventWithTimeout(
                    .fromSeconds(3),
                );
                defer event.deinit(allocator);
                switch (event) {
                    .reset => {},
                    .message => |message| switch (message.value) {
                        .head => |head| {
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
                            break;
                        },
                        .finished => {},
                        .data_available, .trailers, .push_promise => return error.TestUnexpectedResult,
                    },
                }
            }
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
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            },
            .session = .{ .local_settings = webtransport.defaultSettings(.{}) },
        },
    );
    defer client.deinit();

    var attempt = try runtime.HandshakeClientSession
        .connectSessionAttemptWithTimeout(
        &client,
        .{
            .authority = "localhost",
            .path = "/attempt",
            .origin = "https://localhost",
        },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(@as(u16, 404), attempt.status());
    try std.testing.expectEqualStrings(
        "missing",
        attempt.responseHeader("x-rejection").?,
    );
    try std.testing.expectEqualStrings("attempt missing", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    attempt.deinit();

    try std.testing.expectError(
        error.SessionRejected,
        runtime.HandshakeClientSession.connectSessionWithTimeout(
            &client,
            .{
                .authority = "localhost",
                .path = "/legacy",
                .origin = "https://localhost",
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        runtime.HandshakeClientSession.connectSessionAttemptWithTimeout(
            &client,
            .{
                .authority = "localhost",
                .path = "/declared-oversized",
                .origin = "https://localhost",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        runtime.HandshakeClientSession.connectSessionAttemptWithTimeout(
            &client,
            .{
                .authority = "localhost",
                .path = "/streamed-oversized",
                .origin = "https://localhost",
                .limits = .{ .max_rejection_body_bytes = 4 },
            },
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

test "WebTransport caller-owned server H3 session survives rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xd0, 0x01, 0x57, 0x54, 0xd0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xd0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xd0, 0x04 };

    var server = try http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
            .session = .{ .local_settings = webtransport.defaultSettings(.{}) },
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

            var rejected = try runtime.HandshakeServer
                .receiveSessionRequestFromSessionWithTimeout(
                &session,
                .{},
                operation_timeout,
            );
            try std.testing.expectEqualStrings("/rejected", rejected.path());
            var response = try rejected.rejectWithBody(
                403,
                &.{.{ .name = "x-admission", .value = "denied" }},
                "not allowed",
                &.{.{ .name = "x-final", .value = "true" }},
            );
            response.deinit();

            var dropped = try runtime.HandshakeServer
                .receiveSessionRequestFromSessionWithTimeout(
                &session,
                .{},
                operation_timeout,
            );
            try std.testing.expectEqualStrings("/dropped", dropped.path());
            dropped.deinit();

            var sibling = try session.receiveRequestWithTimeout(
                operation_timeout,
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
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
            },
            .session = .{ .local_settings = webtransport.defaultSettings(.{}) },
        },
    );
    defer client.deinit();

    var rejected = try runtime.HandshakeClientSession
        .connectSessionAttemptWithTimeout(
        &client,
        .{
            .authority = "localhost",
            .path = "/rejected",
            .origin = "https://localhost",
        },
        operation_timeout,
    );
    try std.testing.expectEqual(@as(u16, 403), rejected.status());
    try std.testing.expectEqualStrings("not allowed", rejected.body());
    try std.testing.expectEqualStrings(
        "true",
        rejected.trailers()[0].value,
    );
    rejected.deinit();

    try std.testing.expectError(
        error.RequestRejected,
        runtime.HandshakeClientSession.connectSessionAttemptWithTimeout(
            &client,
            .{
                .authority = "localhost",
                .path = "/dropped",
                .origin = "https://localhost",
            },
            operation_timeout,
        ),
    );

    var sibling = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/sibling",
        .authority = "localhost",
    }, operation_timeout);
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.response.status);
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test {
    _ = @import("admission/deadline_tests.zig");
}
