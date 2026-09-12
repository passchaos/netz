const std = @import("std");
const http3 = @import("../../../../mod.zig");
const runtime = @import("../../../../runtime.zig");
const quic = @import("../../../../../quic/mod.zig");
const control_receive = @import("../../../control/receive.zig");

const ProtectedServer = runtime.ProtectedServer;
const ProtectedClient = runtime.ProtectedClient;
const server_qpack_encoder_stream_id: u62 = 7;
const client_qpack_decoder_stream_id: u62 = 10;
const first_server_push_stream_id: u62 = 15;

const FailOnCall = struct {
    delegate: std.Io,
    fail_on_call: usize,
    calls: usize = 0,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *FailOnCall = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        if (self.calls == self.fail_on_call) {
            return .{ error.NetworkDown, 0 };
        }
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

const DeadlineAfterSendIo = struct {
    delegate: std.Io,
    now_ns: i96,
    send_calls: usize = 0,

    fn now(
        userdata: ?*anyopaque,
        _: std.Io.Clock,
    ) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        return .fromNanoseconds(self.now_ns);
    }

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        self.send_calls += 1;
        const result = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
        if (result[1] != 0) self.now_ns += std.time.ns_per_s;
        return result;
    }
};

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: std.Io.net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: anytype,
) !void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

test "HTTP/3 protected client streams owned push promise events" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xca, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(3);
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/index",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqual(stream_id, request.stream_id);

    var response_block: std.ArrayList(u8) = .empty;
    defer response_block.deinit(allocator);
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    try http3.Qpack.encodeDynamicBlock(
        &response_block,
        allocator,
        &.{.{ .name = ":status", .value = "200" }},
        table,
    );
    var promise_block: std.ArrayList(u8) = .empty;
    defer promise_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&promise_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &response_bytes,
        allocator,
        3,
        promise_block.items,
    );
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = response_block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);

    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-promise-kind",
            .value = "dynamic-asset",
        } },
    );
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = server_qpack_encoder_stream_id,
            .data = encoder_bytes.items,
        } },
        .{ .stream = .{
            .stream_id = stream_id,
            .data = response_bytes.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    var promise = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);
    try std.testing.expectEqualStrings(
        "/asset.css",
        promise.push_promise.request.path,
    );
    try std.testing.expectEqualStrings(
        "example.test",
        promise.push_promise.request.authority.?,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        promise.push_promise.request.qpack_section_acknowledgments,
    );
    try std.testing.expectEqualStrings(
        "dynamic-asset",
        promise.push_promise.request.headers[4].value,
    );

    // The event path must flush both feedback instructions generated by this
    // packet: the insert-count increment and the promise's section ack.
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(allocator);
    var instruction_count: usize = 0;
    var feedback_offset: usize = 0;
    while (instruction_count < 2) {
        var feedback_packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer feedback_packet.deinit(allocator);
        for (feedback_packet.frames) |frame| {
            if (frame != .stream or
                frame.stream.stream_id != client_qpack_decoder_stream_id)
            {
                continue;
            }
            try feedback_bytes.appendSlice(allocator, frame.stream.data);
        }
        while (feedback_offset < feedback_bytes.items.len) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                feedback_bytes.items[feedback_offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return err,
            };
            switch (instruction_count) {
                0 => try std.testing.expectEqual(
                    @as(u64, 1),
                    decoded.instruction.insert_count_increment,
                ),
                1 => try std.testing.expectEqual(
                    stream_id,
                    decoded.instruction.section_acknowledgment,
                ),
                else => unreachable,
            }
            feedback_offset += decoded.consumed;
            instruction_count += 1;
        }
    }

    var head = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    var finished = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
}

test "HTTP/3 protected client retains pending push cancellation on send failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xcd, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xce, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcf} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd0} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    try client.push_streams.registerPromise(0, 0);
    try client.qpack_decode.table.setCapacity(256);
    _ = try client.qpack_decode.table.insert("x-cancelled-push", "dynamic");
    var push_block: std.ArrayList(u8) = .empty;
    defer push_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &push_block,
        allocator,
        &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "x-cancelled-push", .value = "dynamic" },
        },
        client.qpack_decode.table,
    );
    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 0);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = push_block.items,
        .consumed = 0,
    }).write(&push_bytes, allocator);
    try std.testing.expect(try client.push_streams.insert(
        server.address(),
        .{
            .stream_id = first_server_push_stream_id,
            .data = push_bytes.items,
            .fin = true,
        },
        client.control,
    ));

    var failed_send = FailOnCall{
        .delegate = client.quic_client.endpoint.io,
        .fail_on_call = 2,
    };
    var failed_vtable = client.quic_client.endpoint.io.vtable.*;
    failed_vtable.netSend = FailOnCall.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &failed_send,
        .vtable = &failed_vtable,
    };
    try std.testing.expectError(error.NetworkDown, client.cancelPush(0));
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.cancelledStreamCount());
    try std.testing.expectEqual(
        @as(?u62, first_server_push_stream_id),
        client.push_streams.firstCancelledStream(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_decode.pendingDecoderInstructions().len,
    );

    client.quic_client.endpoint.io = failed_send.delegate;
    try std.testing.expect((try client.pollPushEvent()) == null);
    try std.testing.expectEqual(@as(usize, 0), client.push_streams.cancelledStreamCount());

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    var saw_stop = false;
    var saw_qpack_cancel = false;
    while (!saw_stop or !saw_qpack_cancel) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .stop_sending => |stop| if (stop.stream_id == first_server_push_stream_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_cancelled),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            .stream => |stream| if (stream.stream_id ==
                client_qpack_decoder_stream_id)
            {
                try feedback.appendSlice(allocator, stream.data);
            },
            else => {},
        };
        var offset: usize = @intFromBool(
            feedback.items.len != 0 and
                feedback.items[0] ==
                    @intFromEnum(http3.StreamType.qpack_decoder),
        );
        while (offset < feedback.items.len) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                feedback.items[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return err,
            };
            if (decoded.instruction == .stream_cancellation and
                decoded.instruction.stream_cancellation ==
                    first_server_push_stream_id)
            {
                saw_qpack_cancel = true;
            }
            offset += decoded.consumed;
        }
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_decode.pendingDecoderInstructions().len,
    );
}

test "HTTP/3 protected client resumes pending push cancellation after deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xd5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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

    try client.sendMaxPushIdWithTimeout(0, .fromSeconds(1));
    try client.push_streams.registerPromise(0, 0);
    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 0);
    try (http3.Response{ .status = 204 }).write(&push_bytes, allocator);
    try std.testing.expect(try client.push_streams.insert(
        server.address(),
        .{
            .stream_id = first_server_push_stream_id,
            .data = push_bytes.items,
            .fin = true,
        },
        client.control,
    ));

    var timed_io = DeadlineAfterSendIo{
        .delegate = client.quic_client.endpoint.io,
        .now_ns = 1_000_000,
    };
    var timed_vtable = client.quic_client.endpoint.io.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.quic_client.endpoint.io = .{
        .userdata = &timed_io,
        .vtable = &timed_vtable,
    };
    defer client.quic_client.endpoint.io = timed_io.delegate;

    const cancel_offset = client.control_send.next_offset;
    try std.testing.expectError(
        error.Timeout,
        client.cancelPushWithDeadline(0, .{
            .clock = .awake,
            .raw = .fromNanoseconds(timed_io.now_ns + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), timed_io.send_calls);
    try std.testing.expect(client.control_send.next_offset > cancel_offset);
    try std.testing.expectEqual(@as(usize, 0), client.push_streams.promiseCount());
    try std.testing.expectEqual(@as(usize, 1), client.push_streams.cancelledStreamCount());

    const committed_offset = client.control_send.next_offset;
    client.quic_client.endpoint.io = timed_io.delegate;
    try client.cancelPushWithTimeout(0, .fromSeconds(1));
    try std.testing.expectEqual(committed_offset, client.control_send.next_offset);
    try std.testing.expectEqual(@as(usize, 0), client.push_streams.cancelledStreamCount());

    var saw_cancel = false;
    var saw_stop = false;
    while (!saw_cancel or !saw_stop) {
        var packet = try server.receive_packets.takeWithDeadline(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .stream => |stream| {
                _ = try control_receive.applyControlStreamFrameForRoleWithPushes(
                    &server.control,
                    allocator,
                    stream,
                    .server,
                    .{ .slice = &.{0} },
                    null,
                    null,
                );
                saw_cancel = saw_cancel or server.control.pushCancelled(0);
            },
            .stop_sending => |stop| if (stop.stream_id == first_server_push_stream_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_cancelled),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            else => {},
        };
    }
}

test "HTTP/3 protected client streams promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xd1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
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
    var client = try ProtectedClient.connect(
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
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(3);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/index",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var promise_fields: std.ArrayList(u8) = .empty;
    defer promise_fields.deinit(allocator);
    var literal_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer literal_table.deinit();
    try http3.Qpack.encodeDynamicBlock(
        &promise_fields,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/asset.css" },
            .{ .name = ":authority", .value = "example.test" },
        },
        literal_table,
    );
    var request_response: std.ArrayList(u8) = .empty;
    defer request_response.deinit(allocator);
    try http3.writePushPromiseFrame(
        &request_response,
        allocator,
        3,
        promise_fields.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &request_response,
        allocator,
    );

    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 3);
    try (http3.Response{
        .status = 200,
        .body = "asset",
    }).write(&push_bytes, allocator);

    // Deliver the push stream first to exercise cross-stream reordering. It is
    // retained but cannot surface until PUSH_PROMISE is decoded below.
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 15,
            .data = push_bytes.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = request_stream_id,
            .data = request_response.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);

    client.qpack_decode.decoder_instructions.deinit(allocator);
    client.qpack_decode.decoder_instructions = .empty;
    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    client.qpack_decode.allocator = failed_alloc.allocator();
    try std.testing.expectError(error.OutOfMemory, client.pollPushEvent());
    client.qpack_decode.allocator = allocator;
    try std.testing.expect(failed_alloc.has_induced_failure);
    const retained = client.push_streams.findByPushId(3) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(retained.reader.?.awaitingInitialHead());

    var push_head = (try client.pollPushEvent()) orelse
        return error.TestUnexpectedResult;
    defer push_head.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), push_head.push_id);
    try std.testing.expectEqual(
        request_stream_id,
        push_head.request_stream_id,
    );
    try std.testing.expectEqual(@as(u62, 15), push_head.stream_id);
    try std.testing.expect(push_head.value == .head);
    try std.testing.expectEqual(
        @as(u16, 200),
        push_head.value.head.response.status,
    );
    var data = try client.receivePushEvent();
    defer data.deinit(allocator);
    try std.testing.expect(data.value == .data_available);
    try std.testing.expectEqual(
        @as(usize, 5),
        try client.skipPushData(3),
    );
    var finished = try client.receivePushEvent();
    defer finished.deinit(allocator);
    try std.testing.expect(finished.value == .finished);
    try std.testing.expect(client.push_streams.findByPushId(3) == null);
}
