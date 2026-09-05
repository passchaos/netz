const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const runtime = @import("../runtime.zig");

const Observation = struct {
    statuses: [2]u16 = undefined,
    headers_valid: bool = true,
    saw_automatic_date: bool = false,
    count: usize = 0,

    fn observe(
        context_ptr: *anyopaque,
        response: http3.InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context_ptr));
        if (self.count >= self.statuses.len) {
            self.headers_valid = false;
            return;
        }
        const expected_name = if (response.status == 103)
            "link"
        else
            "x-progress";
        const expected_value = if (response.status == 103)
            "</runtime.css>"
        else
            "half";
        self.headers_valid = self.headers_valid and std.mem.eql(
            u8,
            findHeader(response.headers, expected_name) orelse "",
            expected_value,
        );
        self.saw_automatic_date = self.saw_automatic_date or
            findHeader(response.headers, "date") != null;
        self.statuses[self.count] = response.status;
        self.count += 1;
    }
};

const MultiplexedObservation = struct {
    const Entry = struct { stream_id: u62, status: u16 };

    entries: [4]Entry = undefined,
    count: usize = 0,

    fn observe(
        context_ptr: *anyopaque,
        stream_id: u62,
        response: http3.InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context_ptr));
        if (self.count >= self.entries.len) return;
        self.entries[self.count] = .{
            .stream_id = stream_id,
            .status = response.status,
        };
        self.count += 1;
    }
};

const PushObservation = struct {
    const Entry = struct {
        push_id: u64,
        request_stream_id: u62,
        stream_id: u62,
        status: u16,
    };

    entries: [2]Entry = undefined,
    count: usize = 0,

    fn observe(
        context_ptr: *anyopaque,
        push_id: u64,
        request_stream_id: u62,
        stream_id: u62,
        response: http3.InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context_ptr));
        if (self.count >= self.entries.len) return;
        self.entries[self.count] = .{
            .push_id = push_id,
            .request_stream_id = request_stream_id,
            .stream_id = stream_id,
            .status = response.status,
        };
        self.count += 1;
    }
};

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP/3 incremental response reader bounds informational heads" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);

    try http3.writeResponseSequence(
        &bytes,
        allocator,
        &.{
            .{ .status = 103 },
            .{ .status = 102 },
            .{ .status = 103 },
        },
        .{ .status = 204 },
    );
    var reader = runtime.StreamingMessageReader
        .initResponseWithInformationalLimit(allocator, 0, 512, .{}, 2);
    defer reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = bytes.items,
        .fin = true,
    });
    for ([_]u16{ 103, 102 }) |expected| {
        var event = (try reader.next(table)) orelse
            return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        try std.testing.expect(event == .head);
        try std.testing.expectEqual(expected, event.head.response.status);
    }
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        reader.next(table),
    );
}

test "HTTP/3 protected client observes and bounds informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x81} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |scenario| {
                var request = try self.server.receiveRequest();
                defer request.deinit(self.server.quic_server.endpoint.allocator);
                const informational = if (scenario == 0)
                    &[_]http3.InformationalResponse{
                        .{
                            .status = 103,
                            .headers = &.{.{
                                .name = "link",
                                .value = "</runtime.css>",
                            }},
                        },
                        .{
                            .status = 102,
                            .headers = &.{.{
                                .name = "x-progress",
                                .value = "half",
                            }},
                        },
                    }
                else
                    &[_]http3.InformationalResponse{
                        .{ .status = 103 },
                        .{ .status = 102 },
                        .{ .status = 103 },
                    };
                try self.server.sendResponseWithInformational(
                    request.from,
                    request.stream_id,
                    informational,
                    .{ .status = 200, .body = "final" },
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_informational_responses = 2,
        },
    );
    defer client.deinit();

    const next_stream_id = client.next_stream_id;
    // Deadline validation must precede stream allocation and request
    // lifecycle mutation. Both an incompatible clock and an already-expired
    // awake deadline are rejected without sending a request.
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndDeadline(
            .{
                .method = "GET",
                .path = "/wrong-clock",
                .authority = "localhost",
            },
            null,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndDeadline(
            .{
                .method = "GET",
                .path = "/expired",
                .authority = "localhost",
            },
            null,
            .{ .clock = .awake, .raw = .zero },
        ),
    );
    try std.testing.expectEqual(next_stream_id, client.next_stream_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );

    var observation: Observation = .{};
    var response = try client.requestWithInformationalAndTimeout(.{
        .method = "GET",
        .path = "/informational",
        .authority = "localhost",
    }, .{
        .context = &observation,
        .on_response = Observation.observe,
    }, .fromSeconds(1));
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        observation.statuses[0..observation.count],
    );
    try std.testing.expect(observation.headers_valid);
    try std.testing.expect(!observation.saw_automatic_date);
    try std.testing.expectEqualStrings("final", response.response.body);
    const date = findHeader(response.response.headers, "date") orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 29), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);

    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .method = "GET",
            .path = "/informational-over-limit",
            .authority = "localhost",
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 authenticated informational deadline variants validate and deliver" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x65} ** 32,
            .x25519_secret_key = [_]u8{0x66} ** 32,
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
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponseWithInformational(
                request.stream_id,
                &.{.{ .status = 103 }},
                .{ .status = 200, .body = "late" },
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x67} ** 32,
            .x25519_secret_key = [_]u8{0x68} ** 32,
        } },
    );
    defer client.deinit();

    // These validation paths run before sending or selecting a stream, so a
    // bogus clock cannot mutate request lifecycle state.
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndDeadline(
            .{ .method = "GET", .path = "/wrong-clock", .authority = "localhost" },
            null,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        client.requestWithInformationalAndTimeout(
            .{ .method = "GET", .path = "/zero", .authority = "localhost" },
            null,
            .zero,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );

    var observation: Observation = .{};
    var response = try client.requestWithInformationalAndTimeout(
        .{ .method = "GET", .path = "/observed", .authority = "localhost" },
        .{
            .context = &observation,
            .on_response = Observation.observe,
        },
        .fromSeconds(1),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observation.count);
    try std.testing.expectEqual(@as(u16, 103), observation.statuses[0]);
    try std.testing.expect(!observation.saw_automatic_date);
    try std.testing.expectEqualStrings("late", response.response.body);
    try std.testing.expect(
        findHeader(response.response.headers, "date") != null,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 protected receive-next correlates informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    var first_request = try server.receiveRequest();
    defer first_request.deinit(allocator);
    var second_request = try server.receiveRequest();
    defer second_request.deinit(allocator);
    try std.testing.expectEqual(first_id, first_request.stream_id);
    try std.testing.expectEqual(second_id, second_request.stream_id);

    // Finish stream 4 first to prove callbacks follow readiness rather than
    // request creation order, while preserving order within each response.
    try server.sendResponseWithInformational(
        second_request.from,
        second_id,
        &.{ .{ .status = 103 }, .{ .status = 102 } },
        .{ .status = 200, .body = "second" },
    );
    try server.sendResponseWithInformational(
        first_request.from,
        first_id,
        &.{ .{ .status = 103 }, .{ .status = 102 } },
        .{ .status = 200, .body = "first" },
    );

    var observation: MultiplexedObservation = .{};
    const observer: runtime.MultiplexedInformationalObserver = .{
        .context = &observation,
        .on_response = MultiplexedObservation.observe,
    };
    var second_response =
        try client.receiveNextResponseWithInformational(observer);
    defer second_response.deinit(allocator);
    try std.testing.expectEqual(second_id, second_response.response.stream_id);
    try std.testing.expectEqualStrings(
        "second",
        second_response.response.value.response.body,
    );
    var first_response =
        try client.receiveNextResponseWithInformational(observer);
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(first_id, first_response.response.stream_id);
    try std.testing.expectEqualStrings(
        "first",
        first_response.response.value.response.body,
    );
    try std.testing.expectEqual(@as(usize, 4), observation.count);
    for (observation.entries, 0..) |entry, index| {
        try std.testing.expectEqual(
            if (index < 2) second_id else first_id,
            entry.stream_id,
        );
        try std.testing.expectEqual(
            if (index % 2 == 0) @as(u16, 103) else 102,
            entry.status,
        );
    }
}

test "HTTP/3 protected aggregate push correlates informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x31} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x41} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(7);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    const push_stream_id = try server.sendResponseWithPush(
        request.from,
        request.stream_id,
        .{ .status = 204 },
        .{
            .push_id = 7,
            .request = .{
                .method = "GET",
                .path = "/asset.css",
                .authority = "localhost",
            },
            .informational = &.{
                .{ .status = 103 },
                .{ .status = 102 },
            },
            .response = .{ .status = 200, .body = "asset" },
        },
    );
    var parent = try client.receiveResponse(request_stream_id);
    defer parent.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), parent.response.status);

    var observation: PushObservation = .{};
    var pushed = try client.receivePushWithInformational(.{
        .context = &observation,
        .on_response = PushObservation.observe,
    });
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(push_stream_id, pushed.stream_id);
    try std.testing.expectEqualStrings("asset", pushed.response.body);
    try std.testing.expectEqual(@as(usize, 2), observation.count);
    for (observation.entries, 0..) |entry, index| {
        try std.testing.expectEqual(@as(u64, 7), entry.push_id);
        try std.testing.expectEqual(request_stream_id, entry.request_stream_id);
        try std.testing.expectEqual(push_stream_id, entry.stream_id);
        try std.testing.expectEqual(
            if (index == 0) @as(u16, 103) else 102,
            entry.status,
        );
    }
}

test "HTTP/3 protected push 1xx overflow stops only the push stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x41} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x51} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_informational_responses = 1,
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/push-limit",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    const push_stream_id = try server.sendResponseWithPush(
        request.from,
        request.stream_id,
        .{ .status = 204 },
        .{
            .push_id = 0,
            .request = .{
                .method = "GET",
                .path = "/too-many-hints.css",
                .authority = "localhost",
            },
            .informational = &.{
                .{ .status = 103 },
                .{ .status = 102 },
            },
            .response = .{ .status = 200, .body = "unused" },
        },
    );
    var parent = try client.receiveResponse(request_stream_id);
    defer parent.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), parent.response.status);

    var first = try client.receivePushEvent();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 103), first.value.head.response.status);
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.receivePushEvent(),
    );

    var saw_stop = false;
    var saw_close = false;
    while (!saw_stop) {
        var packet = try quic.one_rtt.receive(
            &server.quic_server.endpoint,
            client_keys,
            server_cid.len,
            server.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        server.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| switch (frame) {
            .stop_sending => |stop| if (stop.stream_id == push_stream_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.excessive_load),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            .application_close => saw_close = true,
            else => {},
        };
    }
    try std.testing.expect(!saw_close);
    try std.testing.expectEqual(@as(usize, 0), client.push_streams.entryCount());
}
