const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "HTTP/3 handshake serveConnection handles bounded persistent requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x51} ** 32,
            .x25519_secret_key = [_]u8{0x52} ** 32,
        } },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            request: runtime.OwnedHandshakeRequest,
        ) runtime.Error!http3.Response {
            self.calls += 1;
            if (std.mem.eql(u8, request.request.path, "/first")) {
                return .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "14",
                    }},
                    .body = "representation",
                };
            }
            if (std.mem.eql(u8, request.request.path, "/second")) {
                return .{
                    .status = 202,
                    .body = "second-response",
                    .trailers = &.{.{
                        .name = "x-finished",
                        .value = "yes",
                    }},
                };
            }
            return .{ .status = 404 };
        }
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        context: Context = .{},
        served: ?usize = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(
                Context,
                &shared.context,
                Context.handle,
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x53} ** 32,
            .x25519_secret_key = [_]u8{0x54} ** 32,
        } },
    );
    defer client.deinit();

    var first = try client.request(.{
        .method = "HEAD",
        .path = "/first",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), first.response.status);
    try std.testing.expectEqualStrings("", first.response.body);
    try std.testing.expectEqualStrings(
        "14",
        responseHeader(first.response.headers, "content-length") orelse
            return error.MissingHeader,
    );

    var second = try client.request(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
        .body = "request-body",
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 202), second.response.status);
    try std.testing.expectEqualStrings("second-response", second.response.body);
    try std.testing.expectEqualStrings(
        "yes",
        second.response.trailers[0].value,
    );

    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 8)
    {
        try client.receiveProgress();
    }
    try std.testing.expectEqual(@as(?u64, 8), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.sendRequest(.{
        .method = "GET",
        .path = "/third",
        .authority = "localhost",
    }));

    server_thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.calls);
}

fn responseHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP/3 handshake client rejects DATA on a HEAD response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    const server_cid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x91} ** 32,
            .x25519_secret_key = [_]u8{0x92} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings("HEAD", request.request.method);
            // Bypass the request-aware serving helper to emulate a peer that
            // violates HEAD semantics with an actual DATA frame.
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "illegal",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        } },
    );
    defer client.deinit();

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "HEAD",
        .path = "/illegal-head-data",
        .authority = "localhost",
    }));
    server_thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake serveOne propagates handler failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        } },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            request: runtime.OwnedHandshakeRequest,
        ) runtime.Error!http3.Response {
            if (!std.mem.eql(u8, request.request.path, "/handler-error")) {
                return error.InvalidUri;
            }
            return error.InvalidHeader;
        }
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var context = Context{};
            try std.testing.expectError(
                error.InvalidHeader,
                session.serveOne(Context, &context, Context.handle),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        } },
    );
    defer client.deinit();

    _ = try client.sendRequest(.{
        .method = "GET",
        .path = "/handler-error",
        .authority = "localhost",
    });
    server_thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake admission owns generated CID and Initial lifecycle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "template-cid" } },
    );
    defer server.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server.quic_server.endpoint,
    );
    const bytes = try allocator.dupe(u8, "owned-initial");
    var event = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(4567) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer event.deinit(allocator);
    var admission = try server.beginHandshakeAdmission(
        &dispatcher,
        101,
        &event,
        .{ .max_pending_handshakes = 1, .inbox_capacity = 2 },
    );
    defer dispatcher.deinit();
    defer admission.deinit();

    try std.testing.expect(event == .consumed);
    try std.testing.expectEqual(
        @as(usize, quic.endpoint_dispatcher.default_server_connection_id_len),
        admission.serverConnectionId().len,
    );
    try std.testing.expectEqual(@as(usize, 1), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqualStrings(
        "owned-initial",
        admission.initial.bytes,
    );
}

test "HTTP/3 handshake supervisor bounds and reports failed workers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "template-cid" } },
    );
    defer server.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server.quic_server.endpoint,
    );
    defer dispatcher.deinit();
    var supervisor = try runtime.HandshakeSupervisor.init(
        &server,
        &dispatcher,
        .{ .max_pending_handshakes = 1, .inbox_capacity = 1 },
    );
    defer supervisor.deinit();

    const first_bytes = try allocator.alloc(
        u8,
        quic.initial_exchange.min_initial_udp_datagram_size,
    );
    @memset(first_bytes, 0);
    var first = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(4567) },
            .bytes = first_bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = first_bytes[0..8],
        .source_connection_id = first_bytes[8..12],
        .first_packet_len = first_bytes.len,
    } };
    defer first.deinit(allocator);
    _ = try supervisor.admit(&first);
    try std.testing.expect(first == .consumed);

    const second_bytes = try allocator.alloc(
        u8,
        quic.initial_exchange.min_initial_udp_datagram_size,
    );
    @memset(second_bytes, 1);
    var second = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(4568) },
            .bytes = second_bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = second_bytes[0..8],
        .source_connection_id = second_bytes[8..12],
        .first_packet_len = second_bytes.len,
    } };
    defer second.deinit(allocator);
    try std.testing.expectError(
        error.PendingHandshakeLimitReached,
        supervisor.admit(&second),
    );
    try std.testing.expect(second == .new_initial);

    var completion: runtime.HandshakeCompletion = undefined;
    while (true) {
        var ready = try supervisor.receive(
            &.{quic.Version.version_1.wireValue()},
            .{ .clock = .awake, .raw = .fromMilliseconds(1) },
        );
        defer ready.deinit(allocator);
        switch (ready) {
            .completed => {
                completion = ready.takeCompletion().?;
                break;
            },
            .consumed => unreachable,
            .endpoint => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(completion.result == .failure);
    try std.testing.expectEqual(
        error.InvalidEncoding,
        completion.result.failure,
    );
    try std.testing.expectEqual(@as(usize, 0), supervisor.pendingCount());
    // The worker never mutates dispatcher maps. Cleanup occurs when the sole
    // owner consumes or discards its completion.
    try std.testing.expectEqual(@as(usize, 1), dispatcher.pendingHandshakeCount());
    supervisor.discardCompletion(&completion);
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
}

test "HTTP/3 handshake supervisor expires a silent pending worker" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "template-cid" } },
    );
    defer server.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server.quic_server.endpoint,
    );
    defer dispatcher.deinit();
    var supervisor = try runtime.HandshakeSupervisor.init(
        &server,
        &dispatcher,
        .{
            .max_pending_handshakes = 1,
            .inbox_capacity = 1,
            .handshake_timeout_ms = 1,
        },
    );
    defer supervisor.deinit();

    const bytes = try allocator.dupe(u8, "partial-initial");
    var event = quic.endpoint_dispatcher.Event{ .new_initial = .{
        .datagram = .{
            .from = .{ .ip4 = .loopback(4567) },
            .bytes = bytes,
        },
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = bytes[0..8],
        .source_connection_id = bytes[8..],
        .first_packet_len = bytes.len,
    } };
    defer event.deinit(allocator);
    _ = try supervisor.admit(&event);
    try std.testing.expectEqual(
        @as(usize, 1),
        supervisor.expireAt(std.math.maxInt(u64)),
    );

    var completion: runtime.HandshakeCompletion = undefined;
    while (true) {
        if (supervisor.pollCompleted()) |ready| {
            completion = ready;
            break;
        }
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch |err| switch (err) {
            error.Canceled => return err,
        };
    }
    defer completion.deinit();
    try std.testing.expect(completion.result == .failure);
    try std.testing.expect(
        completion.result.failure == error.SocketUnconnected or
            completion.result.failure == error.InvalidInitialPacket,
    );
}

test "HTTP/3 handshake supervisor establishes concurrent clients" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                // Admission replaces this template with a unique CID before each
                // worker starts. Keeping a fixed value here verifies that contract.
                .local_connection_id = "server-template",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
            },
        },
    );
    defer server.deinit();
    var dispatcher = quic.endpoint_dispatcher.Dispatcher.init(
        allocator,
        &server.quic_server.endpoint,
    );
    defer dispatcher.deinit();
    var supervisor = try runtime.HandshakeSupervisor.init(
        &server,
        &dispatcher,
        .{ .max_pending_handshakes = 2, .inbox_capacity = 8 },
    );
    var supervisor_owned = true;
    defer if (supervisor_owned) supervisor.deinit();

    const ClientTask = struct {
        io: std.Io,
        server_address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        random: [32]u8,
        secret: [32]u8,
        established: ?runtime.HandshakeClient = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.established = runtime.HandshakeClient.connect(
                allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.server_address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 16,
                } },
                .{ .handshake = .{
                    .original_destination_connection_id = self.original_dcid,
                    .local_connection_id = self.local_cid,
                    .server_name = "localhost",
                    .random = self.random,
                    .x25519_secret_key = self.secret,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                } },
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var clients = [_]ClientTask{
        .{
            .io = io,
            .server_address = server.address(),
            .original_dcid = "route-one",
            .local_cid = "client-one",
            .random = [_]u8{0xe3} ** 32,
            .secret = [_]u8{0xe4} ** 32,
        },
        .{
            .io = io,
            .server_address = server.address(),
            .original_dcid = "route-two",
            .local_cid = "client-two",
            .random = [_]u8{0xe5} ** 32,
            .secret = [_]u8{0xe6} ** 32,
        },
    };
    const client_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var clients_joined = false;
    defer if (!clients_joined) {
        if (supervisor_owned) {
            supervisor.deinit();
            supervisor_owned = false;
        }
        client_a.join();
        client_b.join();
        for (&clients) |*client| {
            if (client.established) |*established| established.deinit();
        }
    };

    var promoted: [2]?runtime.PromotedHandshakeSession = .{ null, null };
    defer for (&promoted) |*session| {
        if (session.*) |*value| value.deinit();
    };
    var admitted: usize = 0;
    var completed: usize = 0;
    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    while (completed < promoted.len) {
        var event = try supervisor.receive(
            &versions,
            .{ .clock = .awake, .raw = .fromMilliseconds(5) },
        );
        defer event.deinit(allocator);
        switch (event) {
            .consumed => unreachable,
            .completed => {
                var completion = event.takeCompletion().?;
                var owned = true;
                defer if (owned) completion.deinit();
                promoted[completed] = try supervisor.promote(&completion);
                owned = false;
                completed += 1;
            },
            .endpoint => |*endpoint_event| switch (endpoint_event.*) {
                .new_initial => {
                    _ = try supervisor.admit(endpoint_event);
                    admitted += 1;
                },
                .pending_handshake,
                .discarded_long_header,
                .consumed,
                .timer,
                => {},
                .packet, .unrouted => return error.TestUnexpectedResult,
            },
        }
    }

    client_a.join();
    client_b.join();
    clients_joined = true;
    var request_ids: [clients.len]u62 = undefined;
    for (&clients, 0..) |*client, index| {
        if (client.err) |err| return err;
        const established = &(client.established orelse
            return error.TestUnexpectedResult);
        try std.testing.expectEqualStrings(
            "h3",
            established.negotiatedAlpn(),
        );
        request_ids[index] = try established.sendRequest(.{
            .method = "GET",
            .path = if (index == 0) "/one" else "/two",
            .authority = "localhost",
        });
    }

    var responses_sent: usize = 0;
    while (responses_sent < promoted.len) {
        var event = try dispatcher.receive(&versions);
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*routed| {
                var found = false;
                for (&promoted) |*maybe_promoted| {
                    const promoted_session = &(maybe_promoted.* orelse continue);
                    if (promoted_session.handle != routed.connection_handle) continue;
                    try promoted_session.session.processRequestPacket(
                        &routed.packet,
                    );
                    try dispatcher.refreshConnectionTimer(
                        routed.connection_handle,
                    );
                    while (try promoted_session.session.pollRequestEvent()) |request_value| {
                        var request = request_value;
                        defer request.deinit(allocator);
                        if (request != .message) return error.TestUnexpectedResult;
                        switch (request.message.value) {
                            .head => |head| {
                                if (head != .request) {
                                    return error.TestUnexpectedResult;
                                }
                                const body = if (std.mem.eql(
                                    u8,
                                    head.request.path,
                                    "/one",
                                )) "response-one" else if (std.mem.eql(
                                    u8,
                                    head.request.path,
                                    "/two",
                                )) "response-two" else return error.TestUnexpectedResult;
                                try promoted_session.session.sendResponse(
                                    request.message.stream_id,
                                    .{ .status = 200, .body = body },
                                );
                                responses_sent += 1;
                            },
                            .finished => {},
                            else => return error.TestUnexpectedResult,
                        }
                    }
                    found = true;
                    break;
                }
                if (!found) return error.TestUnexpectedResult;
            },
            .consumed, .timer, .discarded_long_header => {},
            .pending_handshake, .new_initial, .unrouted => return error.TestUnexpectedResult,
        }
    }

    for (&clients, request_ids, 0..) |*client, request_id, index| {
        var established = client.established orelse
            return error.TestUnexpectedResult;
        var response = try established.receiveResponse(request_id);
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        try std.testing.expectEqualStrings(
            if (index == 0) "response-one" else "response-two",
            response.response.body,
        );
        established.deinit();
        client.established = null;
    }
    try std.testing.expectEqual(@as(usize, 2), admitted);
    try std.testing.expectEqual(@as(usize, 2), completed);
    try std.testing.expectEqual(@as(usize, 0), supervisor.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), dispatcher.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 2), dispatcher.connectionCount());
}
