const std = @import("std");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");
const NativeSendIo = @import("../../../internal/testing/deadline_send_io.zig").Native;
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Pair = @import("../receive/test_support/request_pair.zig").Pair;

fn admit(pair: *Pair, id: u62) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Request{ .method = "GET", .path = "/response", .authority = "localhost" }).write(&bytes, std.testing.allocator);
    try pair.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes.items, .fin = true } }});
    var request = try pair.server.receiveRequestWithTimeout(.fromSeconds(1));
    defer request.deinit(std.testing.allocator);
    try std.testing.expectEqual(id, request.stream_id);
}

test "HTTP/3 complete response crosses fixed windows with informational fields and trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (0..3) |mode| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try admit(&pair, 0);
        const connection = &pair.server.established.connection;
        connection.send_flow.limit = connection.send_flow.used + 8192;
        connection.config.initial_send_max_stream_data_bidi_local = 2048;
        pair.client.recv_flow = try .init(8192, 8192);
        pair.client.config.initial_receive_max_stream_data_bidi_local = 2048;
        pair.client.config.stream_receive_window = 2048;
        pair.client.config.max_stream_receive_window = 2048;
        const Shared = struct {
            pair: *Pair,
            err: ?anyerror = null,
            expects_early: bool,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                    self.pair.client.closeApplication(http3.ApplicationErrorCode.internal_error, "test-peer-failed") catch {};
                };
            }

            fn runFallible(self: *@This()) !void {
                var bytes: std.ArrayList(u8) = .empty;
                defer bytes.deinit(allocator);
                var buffer: [113]u8 = undefined;
                const until = std.Io.Clock.Timestamp.fromNow(self.pair.client_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
                while (true) {
                    const event = try self.pair.client.receiveStreamIdWithDeadline(0, &buffer, until);
                    if (event != .data) return error.TestUnexpectedResult;
                    try bytes.appendSlice(allocator, buffer[0..event.data.bytes]);
                    if (event.data.fin) break;
                }
                const Early = struct {
                    count: usize = 0,
                    valid: bool = true,
                    fn observe(context: *anyopaque, head: http3.InformationalResponseHead) void {
                        const observer: *@This() = @ptrCast(@alignCast(context));
                        observer.count += 1;
                        var matched = false;
                        for (head.headers) |field| if (std.mem.eql(u8, field.name, "x-early")) {
                            matched = std.mem.eql(u8, field.value, "e" ** 5000);
                        };
                        observer.valid = observer.valid and head.status == 103 and matched;
                    }
                };
                var early: Early = .{};
                var response = try http3.decodeResponseWithOptions(allocator, bytes.items, .{ .informational = .{ .context = &early, .on_response = Early.observe } });
                try std.testing.expect(early.valid);
                try std.testing.expectEqual(@as(usize, if (self.expects_early) 1 else 0), early.count);
                defer response.deinit(allocator);
                try std.testing.expectEqual(@as(u16, 200), response.status);
                try std.testing.expectEqualStrings("response body " ** 2048, response.body);
                var saw_head = false;
                for (response.headers) |field| if (std.mem.eql(u8, field.name, "x-head")) {
                    saw_head = true;
                    try std.testing.expectEqualStrings("h" ** 5000, field.value);
                };
                try std.testing.expect(saw_head);
                try std.testing.expectEqualStrings("t" ** 5000, response.trailers[0].value);
            }
        };
        var shared = Shared{ .pair = &pair, .expects_early = mode == 2 };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();
        const response = http3.Response{ .status = 200, .body = "response body " ** 2048, .headers = &.{.{ .name = "x-head", .value = "h" ** 5000 }}, .trailers = &.{.{ .name = "x-trailer", .value = "t" ** 5000 }} };
        switch (mode) {
            0 => try pair.server.sendResponseWithTimeout(0, response, .fromSeconds(3)),
            1 => try pair.server.sendResponsePaced(0, response),
            else => try pair.server.sendResponseWithInformationalAndTimeout(0, &.{.{ .status = 103, .headers = &.{.{ .name = "x-early", .value = "e" ** 5000 }} }}, response, .fromSeconds(3)),
        }
        thread.join();
        joined = true;
        if (shared.err) |err| return err;
        try std.testing.expect(!connection.closed());
        try std.testing.expect(pair.server.outbound_bodies.find(0) == null);
        try std.testing.expect(!pair.server.request_lifecycle.contains(0));
        try admit(&pair, 4);
        try pair.server.sendResponse(4, .{ .status = 204 });
    }
}

test "HTTP/3 complete response validates every field before output and retains zero-byte owner" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admit(&pair, 0);
    const packet = pair.server.established.connection.next_packet_number;
    try std.testing.expectError(error.InvalidHeader, pair.server.sendResponse(0, .{ .status = 200, .body = "abc", .trailers = &.{.{ .name = "content-length", .value = "3" }} }));
    try std.testing.expectError(error.InvalidContentLength, pair.server.sendResponse(0, .{ .status = 200, .body = "abc", .headers = &.{.{ .name = "content-length", .value = "4" }} }));
    try std.testing.expectError(error.InvalidStatus, pair.server.sendResponseWithInformational(0, &.{.{ .status = 200 }}, .{ .status = 200 }));
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
    try std.testing.expectEqual(packet, pair.server.established.connection.next_packet_number);
    try pair.server.sendResponse(0, .{ .status = 204 });
}

test "HTTP/3 complete response queues refused cancellation and retries before a sibling" {
    try native_protocol_io.run(queuedResponseCancellation);
}

fn queuedResponseCancellation(io: std.Io) !void {
    for ([_]bool{ false, true }) |packet_progress| {
        var pair: Pair = undefined;
        try pair.init(io);
        defer pair.deinit();
        try admit(&pair, 0);
        try admit(&pair, 4);
        const FailAfterFirst = struct {
            fn send(context: ?*anyopaque, handle: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
                const sender: *NativeSendIo = @ptrCast(@alignCast(context.?));
                if (sender.send_calls.load(.acquire) >= 2) return .{ error.NetworkDown, 0 };
                const base = sender.baseIo();
                return base.vtable.netSend(base.userdata, handle, messages, flags);
            }
        };
        const connection = &pair.server.established.connection;
        const fixed_delegate_io = connection.endpoint.io;
        var fixed: NativeSendIo = .{
            .backend = .init(std.testing.allocator, .{ .async_limit = .nothing }),
            .delegate_io = fixed_delegate_io,
            .now_ns = .init(1_000_000),
            .advance_after_send_ns = std.time.ns_per_s,
            .send_override = FailAfterFirst.send,
        };
        fixed.send_context = &fixed;
        defer fixed.backend.deinit();
        connection.endpoint.io = fixed.io();
        defer connection.endpoint.io = fixed_delegate_io;
        try std.testing.expectError(error.Timeout, pair.server.sendResponsePacedWithDeadline(0, .{ .status = 200, .body = "response" }, .{ .clock = .awake, .raw = .fromNanoseconds(fixed.now_ns.load(.acquire) + 100) }));
        try std.testing.expectEqual(@as(usize, 2), fixed.send_calls.load(.acquire));
        try std.testing.expectEqual(@as(usize, 1), pair.server.pending_response_cancellations.items.len);
        try std.testing.expect(!pair.server.request_lifecycle.contains(0));
        try std.testing.expect(pair.server.request_lifecycle.contains(4));
        try std.testing.expect(!connection.closed());
        connection.endpoint.io = fixed_delegate_io;
        if (packet_progress) {
            try pair.send(&.{.ping});
            try std.testing.expectEqual(@as(usize, 0), pair.server.pending_response_cancellations.items.len);
        }
        try pair.server.sendResponse(4, .{ .status = 200, .body = "sibling" });
        try std.testing.expectEqual(@as(usize, 0), pair.server.pending_response_cancellations.items.len);
        try std.testing.expectEqual(http3.ApplicationErrorCode.internal_error, connection.sendStreamStats(0).?.reset.?.application_error_code);
        try std.testing.expect(!connection.closed());
    }
}

test "HTTP/3 complete response timeout retires its stream and preserves siblings" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]http3.Response{
        .{ .status = 200, .body = "response body " ** 2048 },
        .{ .status = 200, .body = "small", .headers = &.{.{ .name = "x-head", .value = "h" ** 5000 }} },
        .{ .status = 200, .body = "small", .trailers = &.{.{ .name = "x-trailer", .value = "t" ** 5000 }} },
    }) |response| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try admit(&pair, 0);
        try admit(&pair, 4);
        const connection = &pair.server.established.connection;
        connection.config.initial_send_max_stream_data_bidi_local = 2048;
        try std.testing.expectError(error.Timeout, pair.server.sendResponsePacedWithTimeout(0, response, .fromMilliseconds(30)));
        try std.testing.expect(!connection.closed());
        try std.testing.expect(!connection.closing());
        try std.testing.expect(!pair.server.request_lifecycle.contains(0));
        try std.testing.expect(pair.server.outbound_bodies.find(0) == null);
        try std.testing.expect(pair.server.request_lifecycle.contains(4));
        try std.testing.expectEqual(http3.ApplicationErrorCode.internal_error, connection.sendStreamStats(0).?.reset.?.application_error_code);
        try pair.server.sendResponseWithTimeout(4, .{ .status = 200, .body = "sibling survives" }, .fromSeconds(1));
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        var buffer: [113]u8 = undefined;
        const until = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            const event = try pair.client.receiveStreamIdWithDeadline(4, &buffer, until);
            if (event != .data) return error.TestUnexpectedResult;
            try bytes.appendSlice(std.testing.allocator, buffer[0..event.data.bytes]);
            if (event.data.fin) break;
        }
        var received = try http3.decodeResponse(std.testing.allocator, bytes.items);
        defer received.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("sibling survives", received.body);
    }
}

test "HTTP/3 complete response retains cancellation until an incomplete upload terminates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    _ = try (http3.Request{ .method = "POST", .path = "/unfinished", .authority = "localhost" }).writeStreamingHead(&encoded, allocator, .{}, 10);
    try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = encoded.items } }});
    var request = try pair.server.receiveRequestEventWithTimeout(.fromSeconds(1));
    defer request.deinit(allocator);
    try std.testing.expect(request == .message and request.message.value == .head);
    const connection = &pair.server.established.connection;
    connection.config.initial_send_max_stream_data_bidi_local = 2048;
    try std.testing.expectError(error.Timeout, pair.server.sendResponsePacedWithTimeout(0, .{ .status = 200, .body = "response body " ** 2048 }, .fromMilliseconds(30)));
    try std.testing.expect(!connection.closed());
    try std.testing.expectEqual(@as(usize, 1), pair.server.pending_response_cancellations.items.len);
    try std.testing.expect(!pair.server.pending_response_cancellations.items[0].needs_cancel);
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    try pair.send(&.{.{ .reset_stream = .{ .stream_id = 0, .application_error_code = http3.ApplicationErrorCode.request_cancelled, .final_size = encoded.items.len } }});
    try std.testing.expectEqual(@as(usize, 0), pair.server.pending_response_cancellations.items.len);
    try std.testing.expect(connection.peerStreamClosed(0) or quic.one_rtt.testing.peerStreamReleaseRequested(connection, 0));
    try admit(&pair, 4);
    try pair.server.sendResponse(4, .{ .status = 204 });
}

test "HTTP/3 response cancellation survives acknowledged reset reclamation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    try admit(&pair, 0);
    try pair.send(&.{.{ .stop_sending = .{ .stream_id = 0, .application_error_code = http3.ApplicationErrorCode.request_cancelled } }});
    const until = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    var saw_reset = false;
    while (!saw_reset) {
        var packet = try pair.client.receivePacketServicingTimersDeadline(until);
        defer packet.deinit(allocator);
        for (packet.frames) |frame| if (frame == .reset_stream and frame.reset_stream.stream_id == 0) {
            saw_reset = true;
        };
    }
    try pair.client.sendAck(0);
    const connection = &pair.server.established.connection;
    while (!connection.peerStreamClosed(0)) {
        var packet = try connection.receivePacketServicingTimersDeadline(until);
        defer packet.deinit(allocator);
        try pair.server.processRequestPacket(&packet);
    }
    try std.testing.expect(connection.sendStreamStats(0) == null);
    try std.testing.expect(pair.server.request_lifecycle.contains(0));
    const canceled = try pair.server.receivePeerResponseCancellationWithTimeout(0, .fromMilliseconds(20));
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, canceled.application_error_code);
    try std.testing.expect(!pair.server.request_lifecycle.contains(0));
    try std.testing.expectEqual(@as(usize, 0), pair.server.request_lifecycle.peer_response_cancellations);
    try admit(&pair, 4);
    try pair.server.sendResponse(4, .{ .status = 204 });
}
