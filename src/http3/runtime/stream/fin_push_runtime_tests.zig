const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");

const Operation = enum { read, read_once, skip, skip_once };
const push_id = 3;
const push_stream_id: u62 = 19;
const decoder_stream_id: u62 = 10;

test "HTTP/3 push late FIN short content retires push and preserves parent and sibling" {
    inline for (.{ Operation.read, Operation.read_once, Operation.skip, Operation.skip_once }) |operation| try exercise(operation, false);
}

test "HTTP/3 push late FIN truncated DATA closes connection before delivery" {
    inline for (.{ Operation.read, Operation.read_once, Operation.skip, Operation.skip_once }) |operation| try exercise(operation, true);
}

fn exercise(comptime operation: Operation, truncated: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const client_cid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c };
    const server_cid = [_]u8{ 0x2d, 0x2e, 0x2f, 0x30 };
    var server = try runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .handshake = .{ .local_connection_id = &server_cid, .random = [_]u8{0x31} ** 32, .x25519_secret_key = [_]u8{0x32} ** 32 },
    });
    defer server.deinit();

    const Peer = struct {
        server: *runtime.HandshakeServer,
        truncated: bool,
        prefix_read: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var parent_request = try session.receiveRequest();
            defer parent_request.deinit(allocator);
            var sibling_request = try session.receiveRequest();
            defer sibling_request.deinit(allocator);
            try session.sendOrigins(&.{});
            // Deliberately leave the first reserved uni stream unused so neither
            // the push ID nor the first uni stream is a valid error target.
            try std.testing.expectEqual(@as(u62, 15), try session.reserveServerUnidirectionalStreamId());
            try std.testing.expectEqual(push_stream_id, try session.reserveServerUnidirectionalStreamId());

            var table = http3.Qpack.DynamicTable.init(allocator, 256);
            defer table.deinit();
            try table.setCapacity(256);
            _ = try table.insert("x-push-kind", "late-fin");
            var encoder: std.ArrayList(u8) = .empty;
            defer encoder.deinit(allocator);
            try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
            try http3.Qpack.writeEncoderInstruction(&encoder, allocator, .{ .set_capacity = 256 });
            try http3.Qpack.writeEncoderInstruction(&encoder, allocator, .{ .insert_literal = .{ .name = "x-push-kind", .value = "late-fin" } });

            var parent: std.ArrayList(u8) = .empty;
            defer parent.deinit(allocator);
            var promise: std.ArrayList(u8) = .empty;
            defer promise.deinit(allocator);
            try http3.Qpack.encodeLiteralBlock(&promise, allocator, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "https" },
                .{ .name = ":path", .value = "/pushed" },
                .{ .name = ":authority", .value = "localhost" },
            });
            try http3.writePushPromiseFrame(&parent, allocator, push_id, promise.items);
            try (http3.Response{ .status = 204 }).write(&parent, allocator);

            var pushed: std.ArrayList(u8) = .empty;
            defer pushed.deinit(allocator);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "3" },
                .{ .name = "x-push-kind", .value = "late-fin" },
            }, table);
            try quic.varint.encode(&pushed, allocator, @intFromEnum(http3.StreamType.push));
            try quic.varint.encode(&pushed, allocator, push_id);
            try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&pushed, allocator);
            try quic.varint.encode(&pushed, allocator, http3.FrameType.data);
            try quic.varint.encode(&pushed, allocator, if (self.truncated) 3 else 2);
            try pushed.append(allocator, 'a');
            try session.established.connection.send(&.{
                .{ .stream = .{ .stream_id = 7, .data = encoder.items } },
                .{ .stream = .{ .stream_id = parent_request.stream_id, .data = parent.items } },
                .{ .stream = .{ .stream_id = push_stream_id, .data = pushed.items } },
            });
            try self.prefix_read.wait(self.server.quic_server.endpoint.io);

            var sibling: std.ArrayList(u8) = .empty;
            defer sibling.deinit(allocator);
            try (http3.Response{ .status = 204 }).write(&sibling, allocator);
            try session.established.connection.send(&.{
                .{ .stream = .{ .stream_id = push_stream_id, .offset = pushed.items.len, .data = "b", .fin = true } },
                .{ .stream = .{ .stream_id = sibling_request.stream_id, .data = sibling.items } },
            });

            // Initial request reception already consumed the real decoder
            // stream prefix. Continue that receive cursor when inspecting
            // subsequent feedback directly from authenticated TLS packets.
            try std.testing.expect(session.qpack_encode.decoder_stream_type_received);
            const decoder = &session.qpack_encode.decoder_stream.?;
            var saw_stop = false;
            var saw_section_ack = false;
            var saw_cancellation = false;
            while (true) {
                var packet = try session.established.connection.receivePacketTimeout(.{
                    .duration = .{ .clock = .awake, .raw = .fromSeconds(2) },
                });
                defer packet.deinit(allocator);
                for (packet.frames) |frame| switch (frame) {
                    .application_close => |close| {
                        try std.testing.expect(self.truncated);
                        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.frame_error), close.error_code);
                        return;
                    },
                    .connection_close, .reset_stream => return error.TestUnexpectedResult,
                    .stop_sending => |stop| {
                        try std.testing.expect(!self.truncated);
                        try std.testing.expectEqual(push_stream_id, stop.stream_id);
                        try std.testing.expectEqual(@as(u64, http3.ApplicationErrorCode.message_error), stop.application_error_code);
                        saw_stop = true;
                    },
                    .stream => |stream| if (stream.stream_id == decoder_stream_id) {
                        try decoder.insert(stream);
                        while (decoder.available().len != 0) {
                            const decoded = http3.Qpack.decodeDecoderInstruction(decoder.available()) catch |err| switch (err) {
                                error.BufferTooShort => break,
                                else => return err,
                            };
                            switch (decoded.instruction) {
                                .section_acknowledgment => |stream_id| {
                                    try std.testing.expectEqual(push_stream_id, stream_id);
                                    saw_section_ack = true;
                                },
                                .stream_cancellation => |stream_id| {
                                    try std.testing.expect(!self.truncated);
                                    try std.testing.expectEqual(push_stream_id, stream_id);
                                    saw_cancellation = true;
                                },
                                .insert_count_increment => |count| try std.testing.expectEqual(@as(u64, 1), count),
                            }
                            try decoder.consume(decoded.consumed);
                        }
                    },
                    else => {},
                };
                if (saw_stop and saw_section_ack and saw_cancellation) break;
            }
            try std.testing.expect(!session.established.connection.closing());
            // Finish both ordinary responses only after the failed push's
            // STOP_SENDING and QPACK cancellation have reached the peer.
            try session.established.connection.send(&.{
                .{ .stream = .{ .stream_id = parent_request.stream_id, .offset = parent.items.len, .data = "", .fin = true } },
                .{ .stream = .{ .stream_id = sibling_request.stream_id, .offset = sibling.items.len, .data = "", .fin = true } },
            });
        }
    };

    var peer = Peer{ .server = &server, .truncated = truncated };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.prefix_read.set(io);
        thread.join();
    };
    var client = try runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{}, .{
        .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid, .server_name = "localhost", .random = [_]u8{0x33} ** 32, .x25519_secret_key = [_]u8{0x34} ** 32 },
        .session = .{ .local_settings = .{ .qpack_max_table_capacity = 256 } },
    });
    defer client.deinit();
    try client.sendMaxPushId(push_id);
    const parent_id = try client.sendRequest(.{ .method = "GET", .path = "/parent", .authority = "localhost" });
    const sibling_id = try client.sendRequest(.{ .method = "GET", .path = "/sibling", .authority = "localhost" });
    var promise_event = try nextResponseEvent(&client, parent_id);
    defer promise_event.deinit(allocator);
    try std.testing.expect(promise_event == .push_promise);
    try std.testing.expectEqual(@as(u64, push_id), promise_event.push_promise.push_id);
    try std.testing.expectEqualStrings("/pushed", promise_event.push_promise.request.path);

    var push_head = try client.receivePushEventWithTimeout(.fromSeconds(2));
    defer push_head.deinit(allocator);
    try std.testing.expectEqual(@as(u64, push_id), push_head.push_id);
    try std.testing.expectEqual(parent_id, push_head.request_stream_id);
    try std.testing.expectEqual(push_stream_id, push_head.stream_id);
    try std.testing.expect(push_head.value == .head);
    try std.testing.expectEqual(@as(usize, 1), push_head.value.head.response.qpack_section_acknowledgments);
    // Capture the actual association before any error can remove the entry.
    const actual_push_stream_id = push_head.stream_id;
    var push_data = try client.receivePushEventWithTimeout(.fromSeconds(2));
    defer push_data.deinit(allocator);
    try std.testing.expectEqual(actual_push_stream_id, push_data.stream_id);
    try std.testing.expect(push_data.value == .data_available);
    var prefix: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try client.readPushData(push_id, &prefix));
    try std.testing.expectEqualStrings("a", &prefix);
    try std.testing.expectEqual(@as(?u64, null), client.push_streams.readerForStream(actual_push_stream_id).?.receive.final_size);
    peer.prefix_read.set(io);

    // Pump only the sibling response to route the push FIN without polling
    // the push reader and installing the error policy through its event API.
    var sibling_head = try nextResponseEvent(&client, sibling_id);
    defer sibling_head.deinit(allocator);
    try std.testing.expect(sibling_head == .head);
    const reader = client.push_streams.readerForStream(actual_push_stream_id).?;
    try std.testing.expect(reader.receive.final_size != null);
    try std.testing.expectEqual(reader.receive.final_size.?, reader.receive.contiguous_end);
    try std.testing.expectEqual(@as(usize, 1), reader.body_read);
    try std.testing.expect(reader.hasPendingFrame());
    try std.testing.expectEqual(@as(?u62, null), client.push_streams.lastErrorStreamId());
    const expected = if (truncated) error.BufferTooShort else error.InvalidContentLength;
    var out = [_]u8{0xaa} ** 4;
    switch (operation) {
        .read => try std.testing.expectError(expected, client.readPushData(push_id, &out)),
        .read_once => try std.testing.expectError(expected, client.readPushDataOnce(push_id, &out)),
        .skip => try std.testing.expectError(expected, client.skipPushData(push_id)),
        .skip_once => try std.testing.expectError(expected, client.skipPushDataOnce(push_id)),
    }
    try std.testing.expectEqual([4]u8{ 0xaa, 0xaa, 0xaa, 0xaa }, out);
    if (truncated) {
        try std.testing.expect(client.established.connection.closing());
        try std.testing.expectEqual(@as(usize, 1), client.push_streams.readerForStream(actual_push_stream_id).?.body_read);
    } else {
        try std.testing.expect(!client.established.connection.closing());
        try std.testing.expect(client.push_streams.isIdle());
        try std.testing.expect(!client.push_streams.containsStream(actual_push_stream_id));
        try std.testing.expectEqual(@as(usize, 0), client.push_streams.promiseCount());
        try std.testing.expect(client.push_streams.hasPromise(push_id));
        try std.testing.expectEqual(@as(usize, 1), client.push_streams.completedPromiseRangeCount());
        try std.testing.expect(client.request_lifecycle.contains(parent_id));
        try std.testing.expect(client.request_lifecycle.contains(sibling_id));
        var parent_head = try nextResponseEvent(&client, parent_id);
        defer parent_head.deinit(allocator);
        try std.testing.expect(parent_head == .head);
        try std.testing.expectEqual(@as(u16, 204), parent_head.head.response.status);
        inline for (.{ parent_id, sibling_id }) |request_id| {
            var finished = try nextResponseEvent(&client, request_id);
            defer finished.deinit(allocator);
            try std.testing.expect(finished == .finished);
            try std.testing.expect(!client.request_lifecycle.contains(request_id));
        }
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn nextResponseEvent(client: *runtime.HandshakeClient, stream_id: u62) !@import("reader.zig").Event {
    const deadline = std.Io.Clock.Timestamp.fromNow(
        client.established.connection.endpoint.io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    );
    while (true) {
        if (try client.receiveResponseEventWithDeadline(stream_id, deadline)) |event| return event;
    }
}
