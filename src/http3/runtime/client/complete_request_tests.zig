const std = @import("std");
const http3 = @import("../../mod.zig");
const Pair = @import("../receive/test_support/response_pair.zig").Pair;

test "HTTP/3 complete request preflight rejects body and trailers before admission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const client = &pair.client;
    const packet_number = client.established.connection.next_packet_number;
    const count = client.request_lifecycle.count();
    const id = client.next_stream_id;
    const errors = [_]anyerror{ error.InvalidContentLength, error.InvalidHeader, error.InvalidContentLength };
    for ([_]http3.Request{
        .{ .method = "POST", .path = "/invalid", .authority = "localhost", .body = "abc", .headers = &.{.{ .name = "content-length", .value = "2" }} },
        .{ .method = "POST", .path = "/invalid", .authority = "localhost", .body = "abc", .trailers = &.{.{ .name = "content-length", .value = "3" }} },
        .{ .method = "CONNECT", .path = "", .authority = "localhost:443", .body = "abc" },
    }, errors) |request, expected| {
        try std.testing.expectError(expected, client.sendRequest(request));
        try std.testing.expectEqual(id, client.next_stream_id);
        try std.testing.expectEqual(@as(u64, id), client.established.connection.nextLocalBidirectionalStreamId());
        try std.testing.expectEqual(count, client.request_lifecycle.count());
        try std.testing.expectEqual(packet_number, client.established.connection.next_packet_number);
    }
}

test "HTTP/3 complete request crosses fixed windows with exact head body trailers and reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ true, false }) |bounded| {
        var pair: Pair = undefined;
        try pair.init(io);
        defer pair.deinit();
        const client = &pair.client;
        const id = client.next_stream_id;
        client.established.connection.send_flow.limit = client.established.connection.send_flow.used + 8192;
        client.established.connection.config.initial_send_max_stream_data_bidi_remote = 2048;
        pair.server.recv_flow.limit = pair.server.recv_flow.highest_received + 8192;
        pair.server.recv_flow.window = 8192;
        pair.server.recv_flow.max_window = 8192;
        pair.server.config.initial_receive_max_stream_data_bidi_remote = 2048;
        pair.server.config.stream_receive_window = 2048;
        pair.server.config.max_stream_receive_window = 2048;
        const Shared = struct {
            pair: *Pair,
            id: u62,
            io: std.Io,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                    self.pair.server.closeApplication(http3.ApplicationErrorCode.internal_error, "test-peer-failed") catch {};
                };
            }

            fn runFallible(self: *@This()) !void {
                var bytes: std.ArrayList(u8) = .empty;
                defer bytes.deinit(allocator);
                var buffer: [113]u8 = undefined;
                const until = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
                while (true) {
                    const event = try self.pair.server.receiveStreamIdWithDeadline(self.id, &buffer, until);
                    if (event != .data) return error.TestUnexpectedResult;
                    try bytes.appendSlice(allocator, buffer[0..event.data.bytes]);
                    if (event.data.fin) break;
                }
                var request = try http3.decodeRequest(allocator, bytes.items);
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings("/complete", request.path);
                try std.testing.expectEqualStrings("complete body " ** 2048, request.body);
                var saw_head = false;
                for (request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-head")) {
                        try std.testing.expectEqualStrings("h" ** 5000, header.value);
                        saw_head = true;
                    }
                }
                try std.testing.expect(saw_head);
                try std.testing.expectEqualStrings("t" ** 5000, request.trailers[0].value);
                var response: std.ArrayList(u8) = .empty;
                defer response.deinit(allocator);
                try (http3.Response{ .status = 200, .body = "complete" }).write(&response, allocator);
                try self.pair.server.send(&.{.{ .stream = .{ .stream_id = self.id, .data = response.items, .fin = true } }});
            }
        };
        var shared = Shared{ .pair = &pair, .id = id, .io = io };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();
        const request = http3.Request{
            .method = "POST",
            .path = "/complete",
            .authority = "localhost",
            .body = "complete body " ** 2048,
            .headers = &.{.{ .name = "x-head", .value = "h" ** 5000 }},
            .trailers = &.{.{ .name = "x-trailer", .value = "t" ** 5000 }},
        };
        var response = if (bounded)
            try client.requestWithTimeout(request, .fromSeconds(3))
        else
            try client.request(request);
        defer response.deinit(allocator);
        thread.join();
        joined = true;
        if (shared.err) |err| return err;
        try std.testing.expectEqualStrings("complete", response.response.body);
        try std.testing.expect(client.stream_send_scratch.encoded.items.len < request.body.len);
        try std.testing.expect(!client.established.connection.closing());
        try std.testing.expect(client.outbound_bodies.find(id) == null);
        _ = try client.sendRequest(.{ .method = "GET", .path = "/reuse", .authority = "localhost" });
    }
}

test "HTTP/3 complete request timeout retires partial upload and preserves siblings" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]http3.Request{
        .{ .method = "POST", .authority = "localhost", .path = "/blocked-body", .body = "request payload " ** 1024 },
        .{ .method = "POST", .authority = "localhost", .path = "/blocked-head", .body = "small", .headers = &.{.{ .name = "x-head", .value = "h" ** 5000 }} },
        .{ .method = "POST", .authority = "localhost", .path = "/blocked-trailer", .body = "small", .trailers = &.{.{ .name = "x-trailer", .value = "t" ** 5000 }} },
    }) |request| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const client = &pair.client;
        const connection = &client.established.connection;
        // No peer reader grants additional connection credit. HEADERS and a
        // definite DATA prefix fit; the complete request cannot fit this budget.
        connection.send_flow.limit = connection.send_flow.used + 2048;
        const request_id = client.next_stream_id;
        try std.testing.expectError(error.Timeout, client.sendRequestWithTimeout(request, .fromMilliseconds(30)));
        try std.testing.expect(!connection.closed());
        try std.testing.expect(!connection.closing());
        try std.testing.expect(!client.request_lifecycle.contains(request_id));
        try std.testing.expect(client.outbound_bodies.find(request_id) == null);
        try std.testing.expect(client.request_lifecycle.contains(0));
        try std.testing.expect(client.request_lifecycle.contains(4));
        const stats = connection.sendStreamStats(request_id).?;
        try std.testing.expect(stats.highest_sent_offset > 0);
        try std.testing.expect(stats.highest_sent_offset <= 2048);
        try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, stats.reset.?.application_error_code);
        try std.testing.expectEqual(request_id + 4, client.next_stream_id);
        // A sibling still completes through the same transport after the reset.
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(std.testing.allocator);
        try (http3.Response{ .status = 200, .body = "sibling survives" }).write(&encoded, std.testing.allocator);
        try pair.send(&.{.{ .stream = .{ .stream_id = 0, .data = encoded.items, .fin = true } }});
        var response = try client.receiveResponseWithTimeout(0, .fromSeconds(1));
        defer response.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("sibling survives", response.response.body);
    }
}

test "HTTP/3 complete request empty body trailers retains a finite send cursor" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.client.sendRequest(.{
        .method = "POST",
        .authority = "localhost",
        .path = "/empty",
        .trailers = &.{.{ .name = "x-complete", .value = "yes" }},
    });
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (pair.server.recvStreamStats(id)) |stats| stats.final_size else null) == null) {
        var packet = try pair.server.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    var request = try http3.decodeRequest(std.testing.allocator, pair.server.availableReceivedStream(id).?);
    defer request.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), request.body.len);
    try std.testing.expectEqualStrings("yes", request.trailers[0].value);
    try std.testing.expect(pair.client.outbound_bodies.find(id) == null);
}
