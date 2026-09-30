const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const body_sender = @import("../../send/body.zig");

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

test "HTTP/3 protected response scheduler honors request priority" {
    const allocator = std.testing.allocator;
    const low_body = "low-" ** 18;
    const high_body = "high" ** 18;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xc6, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xc7, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
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
            .max_frames_per_packet = 1,
            .max_stream_frame_data = 129,
            .response_scheduler_max_batch_packets = 2,
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
            .max_frames_per_packet = 1,
        },
    );
    defer client.deinit();

    const low_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/low",
        .authority = "localhost",
        .headers = &.{.{ .name = "priority", .value = "u=6" }},
    });
    const high_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/high",
        .authority = "localhost",
        .headers = &.{.{ .name = "priority", .value = "u=1" }},
    });
    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try server.startResponse(
        first.from,
        low_id,
        .{ .status = 200 },
        low_body.len,
    );
    try server.startResponse(
        first.from,
        high_id,
        .{ .status = 200 },
        high_body.len,
    );
    const responses = [_]runtime.ResponseBody{
        .{ .stream_id = low_id, .data = low_body },
        .{ .stream_id = high_id, .data = high_body },
    };
    const low_before = server.outbound_bodies.find(low_id).?.*;
    const high_before = server.outbound_bodies.find(high_id).?.*;
    const packet_number = server.next_packet_number;
    var committed = [_]usize{99} ** responses.len;
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodiesPacedWithTimeout(
            first.from,
            &responses,
            &committed,
            .zero,
        ),
    );
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, 0 },
        &committed,
    );
    try std.testing.expectEqual(packet_number, server.next_packet_number);
    try std.testing.expectEqual(
        low_before.written,
        server.outbound_bodies.find(low_id).?.written,
    );
    try std.testing.expectEqual(
        high_before.written,
        server.outbound_bodies.find(high_id).?.written,
    );

    @memset(&committed, 99);
    try std.testing.expectError(
        error.InvalidContentLength,
        server.sendResponseBodiesPacedWithDeadline(
            first.from,
            &.{
                responses[0],
                .{ .stream_id = high_id, .data = high_body ++ "x" },
            },
            &committed,
            .fromNow(
                server.quic_server.endpoint.io,
                .{ .raw = .fromSeconds(1), .clock = .awake },
            ),
        ),
    );
    try std.testing.expectEqualSlices(usize, &.{ 0, 0 }, &committed);
    try std.testing.expectEqual(packet_number, server.next_packet_number);
    try std.testing.expectEqual(
        low_before.send.next_offset,
        server.outbound_bodies.find(low_id).?.send.next_offset,
    );
    try std.testing.expectEqual(
        high_before.send.next_offset,
        server.outbound_bodies.find(high_id).?.send.next_offset,
    );

    var timed = DeadlineAfterSendIo{
        .delegate = server.quic_server.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            server.quic_server.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    server.quic_server.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    defer server.quic_server.endpoint.io = timed.delegate;
    const first_chunk = body_sender.pacedProtectedBodyChunkLimit(
        server.config,
    );
    try std.testing.expectError(
        error.Timeout,
        server.sendResponseBodiesPacedWithDeadline(
            first.from,
            &responses,
            &committed,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 0, first_chunk },
        &committed,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.outbound_bodies.find(low_id).?.written,
    );
    try std.testing.expectEqual(
        first_chunk,
        server.outbound_bodies.find(high_id).?.written,
    );

    server.quic_server.endpoint.io = timed.delegate;
    const suffixes = [_]runtime.ResponseBody{
        responses[0],
        .{
            .stream_id = high_id,
            .data = responses[1].data[first_chunk..],
        },
    };
    try server.sendResponseBodiesPacedWithTimeout(
        first.from,
        &suffixes,
        &committed,
        .fromSeconds(1),
    );
    try std.testing.expectEqualSlices(
        usize,
        &.{ low_body.len, high_body.len - first_chunk },
        &committed,
    );

    var high = try client.receiveNextResponse();
    defer high.deinit(allocator);
    try std.testing.expect(high == .response);
    try std.testing.expectEqual(high_id, high.response.stream_id);
    try std.testing.expectEqualStrings(
        high_body,
        high.response.value.response.body,
    );
    var low = try client.receiveNextResponse();
    defer low.deinit(allocator);
    try std.testing.expect(low == .response);
    try std.testing.expectEqual(low_id, low.response.stream_id);
    try std.testing.expectEqualStrings(
        low_body,
        low.response.value.response.body,
    );
}
