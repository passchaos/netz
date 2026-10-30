const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const tls = @import("../../../tls/testing.zig");
const capsule = @import("../capsule.zig");
const endpoint = @import("../endpoint_client.zig");
const runtime = @import("../runtime.zig");
const allocator = std.testing.allocator;

const credit: http2.WebTransportSettings = .{
    .enabled = true,
    .max_data = 8192,
    .max_stream_data_uni = 2048,
    .max_stream_data_bidi_local = 2048,
    .max_stream_data_bidi_remote = 2048,
    .max_streams_uni = 8,
    .max_streams_bidi = 8,
};

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake });
}

fn start(stream: *http2.runtime.ServerDuplexStream, status: u16, headers: []const http2.Hpack.HeaderField, before: std.Io.Clock.Timestamp) !void {
    try std.testing.expectEqualStrings("CONNECT", stream.method);
    try std.testing.expectEqualStrings("webtransport", stream.protocol.?);
    try stream.startResponseWithDeadline(.{
        .status = status,
        .headers = headers,
        .request_method = "CONNECT",
        .extended_connect = true,
    }, before);
}

fn readDatagram(stream: *http2.runtime.ServerDuplexStream, expected: []const u8, before: std.Io.Clock.Timestamp) !void {
    while (true) {
        var event = try stream.readRequestEventWithDeadline(before);
        defer event.deinit(allocator);
        switch (event) {
            .data => |data| {
                const parsed = try capsule.Capsule.parse(data.data);
                try std.testing.expectEqual(data.data.len, parsed.consumed);
                try std.testing.expectEqualStrings(expected, parsed.capsule.datagram);
                return;
            },
            .finished, .trailers, .reset => return error.TestUnexpectedResult,
        }
    }
}

fn readClose(stream: *http2.runtime.ServerDuplexStream, expected_code: u32, before: std.Io.Clock.Timestamp) !void {
    while (true) {
        var event = try stream.readRequestEventWithDeadline(before);
        defer event.deinit(allocator);
        switch (event) {
            .data => |data| {
                const parsed = try capsule.Capsule.parse(data.data);
                try std.testing.expectEqual(data.data.len, parsed.consumed);
                try std.testing.expectEqual(expected_code, parsed.capsule.close_session.code);
                return;
            },
            .finished, .trailers, .reset => return error.TestUnexpectedResult,
        }
    }
}

fn readStream(stream: *http2.runtime.ServerDuplexStream, expected_id: u62, expected: []const u8, before: std.Io.Clock.Timestamp) !void {
    while (true) {
        var event = try stream.readRequestEventWithDeadline(before);
        defer event.deinit(allocator);
        switch (event) {
            .data => |data| {
                const parsed = try capsule.Capsule.parse(data.data);
                try std.testing.expectEqual(data.data.len, parsed.consumed);
                try std.testing.expectEqual(expected_id, parsed.capsule.stream.id);
                try std.testing.expectEqualStrings(expected, parsed.capsule.stream.data);
                try std.testing.expect(parsed.capsule.stream.fin);
                return;
            },
            .finished, .trailers, .reset => return error.TestUnexpectedResult,
        }
    }
}

fn writeCapsule(stream: *http2.runtime.ServerDuplexStream, value: capsule.Capsule, before: std.Io.Clock.Timestamp) !void {
    var storage: [256]u8 = undefined;
    const bytes = try value.writeInto(&storage);
    const result = try stream.writeResponseWithDeadline(bytes, before);
    try std.testing.expectEqual(bytes.len, result.written);
}

test "WebTransport HTTP2 EndpointClient owns multiplexed Sessions and stable handles" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
    });
    defer server.deinit();
    var release_server: std.Io.Event = .unset;
    var blocked_seen: std.Io.Event = .unset;
    var release_blocked: std.Io.Event = .unset;
    const Peer = struct {
        server: *http2.runtime.TlsServer,
        release: *std.Io.Event,
        blocked_seen: *std.Io.Event,
        release_blocked: *std.Io.Event,

        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();

            var rejected = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer rejected.deinit();
            try std.testing.expectEqualStrings("/reject", rejected.path);
            try start(&rejected, 429, &.{
                .{ .name = "content-length", .value = "5" },
                .{ .name = "retry-after", .value = "11" },
            }, deadline(connection.io));
            _ = try rejected.writeResponseWithDeadline("later", deadline(connection.io));
            try rejected.finishResponseTrailersWithDeadline(&.{.{ .name = "x-rejected", .value = "owned" }}, deadline(connection.io));
            try std.testing.expect((try rejected.drainRequestAfterResponseWithDeadline(deadline(connection.io))) == .finished);

            var streams: [2]http2.runtime.ServerDuplexStream = undefined;
            var initialized: usize = 0;
            defer for (streams[0..initialized]) |*stream| stream.deinit();
            for (&streams) |*stream| {
                stream.* = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
                initialized += 1;
                try start(stream, 200, &.{.{ .name = "x-session", .value = stream.path }}, deadline(connection.io));
            }
            const a_index: usize = if (std.mem.eql(u8, streams[0].path, "/a")) 0 else 1;
            const b_index: usize = 1 - a_index;
            try std.testing.expectEqualStrings("/b", streams[b_index].path);

            try readStream(&streams[a_index], 0, "hello", deadline(connection.io));
            try readDatagram(&streams[a_index], "to-a", deadline(connection.io));
            try readDatagram(&streams[b_index], "to-b", deadline(connection.io));
            try writeCapsule(&streams[b_index], .{ .datagram = "from-b" }, deadline(connection.io));
            try writeCapsule(&streams[a_index], .{ .stream = .{ .id = 0, .data = "reply", .fin = true } }, deadline(connection.io));
            try writeCapsule(&streams[a_index], .{ .datagram = "from-a" }, deadline(connection.io));

            try readClose(&streams[a_index], 1, deadline(connection.io));
            try std.testing.expect((try streams[a_index].readRequestEventWithDeadline(deadline(connection.io))) == .finished);
            _ = try streams[a_index].finishResponseWithDeadline(deadline(connection.io));
            try readClose(&streams[b_index], 2, deadline(connection.io));
            try std.testing.expect((try streams[b_index].readRequestEventWithDeadline(deadline(connection.io))) == .finished);
            _ = try streams[b_index].finishResponseWithDeadline(deadline(connection.io));

            var reused = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer reused.deinit();
            try std.testing.expectEqualStrings("/reused", reused.path);
            try start(&reused, 200, &.{.{ .name = "x-session", .value = "reused" }}, deadline(connection.io));

            var dropped = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer dropped.deinit();
            try std.testing.expectEqualStrings("/dropped", dropped.path);
            try start(&dropped, 200, &.{.{ .name = "x-session", .value = "dropped" }}, deadline(connection.io));

            var blocked = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer blocked.deinit();
            try std.testing.expectEqualStrings("/blocked", blocked.path);
            self.blocked_seen.set(connection.io);
            try self.release_blocked.wait(connection.io);
            try start(&blocked, 429, &.{.{ .name = "content-length", .value = "0" }}, deadline(connection.io));
            _ = try blocked.finishResponseWithDeadline(deadline(connection.io));
            try std.testing.expect((try blocked.drainRequestAfterResponseWithDeadline(deadline(connection.io))) == .finished);
            try self.release.wait(connection.io);
        }
    };
    var peer = Peer{ .server = &server, .release = &release_server, .blocked_seen = &blocked_seen, .release_blocked = &release_blocked };
    var peer_task = io.async(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var client = try endpoint.EndpointClient.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .{ .max_sessions = 2 }, .fromSeconds(3));
    try std.testing.expectError(error.InvalidEndpointOptions, (endpoint.Options{ .max_sessions = 0 }).validate());
    var client_owned = true;
    defer if (client_owned) client.deinit();

    var rejected = try client.connectAttemptWithTimeout(.{ .path = "/reject", .authority = "localhost" }, .fromSeconds(3));
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 429), rejected.status());
    try std.testing.expectEqualStrings("11", rejected.responseHeader("retry-after").?);
    try std.testing.expectEqualStrings("later", rejected.body());
    try std.testing.expectEqualStrings("owned", rejected.trailers()[0].value);

    const Open = struct {
        fn run(value: endpoint.EndpointClient, path: []const u8) !endpoint.Handle {
            return value.connectWithTimeout(.{ .path = path, .authority = "localhost" }, .fromSeconds(3));
        }
    };
    var a_task = io.async(Open.run, .{ client, "/a" });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Open.run, .{ client, "/b" });
    defer _ = b_task.cancel(io) catch {};
    const a = try a_task.await(io);
    const b = try b_task.await(io);
    try std.testing.expect(a.index != b.index);
    try std.testing.expectError(error.EndpointCapacity, client.connectWithTimeout(.{ .path = "/overflow", .authority = "localhost" }, .fromSeconds(3)));
    var key_a = try client.exportKeyingMaterialWithTimeout(a, "demo", "context", 32, .fromSeconds(3));
    defer key_a.deinit();
    var key_a_again = try client.exportKeyingMaterialWithTimeout(a, "demo", "context", 32, .fromSeconds(3));
    defer key_a_again.deinit();
    var key_b = try client.exportKeyingMaterialWithTimeout(b, "demo", "context", 32, .fromSeconds(3));
    defer key_b.deinit();
    try std.testing.expectEqualSlices(u8, key_a.value, key_a_again.value);
    try std.testing.expect(!std.mem.eql(u8, key_a.value, key_b.value));

    const Send = struct {
        fn run(value: endpoint.EndpointClient, handle: endpoint.Handle, data: []const u8) !void {
            try value.sendDatagramWithTimeout(handle, data, .fromSeconds(3));
        }
    };
    var send_b = io.async(Send.run, .{ client, b, "to-b" });
    defer _ = send_b.cancel(io) catch {};
    const a_stream = try client.openStreamWithTimeout(a, .bidirectional, .fromSeconds(3));
    try std.testing.expectEqual(@as(u62, 0), a_stream);
    try client.sendStreamWithTimeout(a, a_stream, "hello", true, .fromSeconds(3));
    var send_a = io.async(Send.run, .{ client, a, "to-a" });
    defer _ = send_a.cancel(io) catch {};
    try send_b.await(io);
    try send_a.await(io);

    var event_a = try client.receiveWithTimeout(a, .fromSeconds(3));
    defer event_a.deinit();
    try std.testing.expectEqualStrings("reply", event_a.value.stream.data);
    try std.testing.expect(event_a.value.stream.fin);
    try client.consumeWithTimeout(a, a_stream, 5, .fromSeconds(3));
    try client.retireStreamWithTimeout(a, a_stream, .fromSeconds(3));
    var datagram_a = try client.receiveWithTimeout(a, .fromSeconds(3));
    defer datagram_a.deinit();
    try std.testing.expectEqualStrings("from-a", datagram_a.value.datagram);
    var event_b = try client.receiveWithTimeout(b, .fromSeconds(3));
    defer event_b.deinit();
    try std.testing.expectEqualStrings("from-b", event_b.value.datagram);
    try client.closeWithTimeout(a, 1, "a", .fromSeconds(3));
    try client.closeWithTimeout(b, 2, "b", .fromSeconds(3));
    var closed_a = try client.receiveWithTimeout(a, .fromSeconds(3));
    defer closed_a.deinit();
    try std.testing.expectEqual(@as(u32, 0), closed_a.value.closed.code);
    var closed_b = try client.receiveWithTimeout(b, .fromSeconds(3));
    defer closed_b.deinit();
    try std.testing.expectEqual(@as(u32, 0), closed_b.value.closed.code);
    try std.testing.expect(try client.removeWithTimeout(a, .fromSeconds(3)));
    try std.testing.expectError(error.StaleSession, client.sendDatagramWithTimeout(a, "stale", .fromSeconds(3)));
    try std.testing.expect(try client.removeWithTimeout(b, .fromSeconds(3)));

    var reused_attempt = try client.connectAttemptWithTimeout(.{ .path = "/reused", .authority = "localhost" }, .fromSeconds(3));
    var reused_attempt_owned = true;
    defer if (reused_attempt_owned) reused_attempt.deinit();
    try std.testing.expect(reused_attempt.accepted());
    try std.testing.expectEqual(@as(u16, 200), reused_attempt.status());
    try std.testing.expectEqualStrings("reused", reused_attempt.responseHeader("x-session").?);
    var reused_accepted = try reused_attempt.requireAccepted();
    reused_attempt_owned = false;
    defer reused_accepted.deinit();
    const reused = reused_accepted.handle;
    const previous = if (reused.index == a.index) a else b;
    try std.testing.expectEqual(previous.index, reused.index);
    try std.testing.expect(previous.generation != reused.generation);

    var dropped_attempt = try client.connectAttemptWithTimeout(.{ .path = "/dropped", .authority = "localhost" }, .fromSeconds(3));
    try std.testing.expect(dropped_attempt.accepted());
    dropped_attempt.deinit();

    const OpenAttempt = struct {
        fn run(value: endpoint.EndpointClient) !endpoint.ConnectAttempt {
            return value.connectAttemptWithTimeout(.{ .path = "/blocked", .authority = "localhost" }, .fromSeconds(3));
        }
    };
    var blocked_task = io.async(OpenAttempt.run, .{client});
    defer _ = blocked_task.cancel(io) catch {};
    try blocked_seen.wait(io);
    try std.testing.expectError(error.Timeout, client.sendDatagramWithTimeout(reused, "abandoned", .fromMilliseconds(20)));
    release_blocked.set(io);
    var blocked_attempt = try blocked_task.await(io);
    defer blocked_attempt.deinit();
    try std.testing.expect(!blocked_attempt.accepted());
    try std.testing.expectEqual(@as(u16, 429), blocked_attempt.status());
    release_server.set(io);
    client.deinit();
    client_owned = false;
    try peer_task.await(io);
}
