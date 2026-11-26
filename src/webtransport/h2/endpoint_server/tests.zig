const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const tls = @import("../../../tls/testing.zig");
const tls_stream = @import("../../../tls/mod.zig").stream;
const h2 = @import("../mod.zig");
const endpoint = @import("../endpoint_server.zig");
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

fn next(session: *h2.Session) !h2.state.Event {
    while (true) {
        const event = try session.receiveWithTimeout(.fromSeconds(3));
        if (event != .progress) return event;
    }
}

test "WebTransport HTTP2 EndpointServer owns admission Sessions and capacity" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var listener = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
    });
    defer listener.deinit();
    const Peer = struct {
        listener: *http2.runtime.TlsServer,
        stage: []const u8 = "TLS accept",

        fn acceptRequest(server: endpoint.EndpointServer, expected: []const u8) !endpoint.PendingRequest {
            var request = try server.receiveRequestWithTimeout(.fromSeconds(3));
            errdefer request.deinit();
            try std.testing.expectEqualStrings(expected, request.path());
            try std.testing.expectEqualStrings("localhost", request.authority().?);
            return request;
        }

        fn run(self: *@This()) !void {
            return self.runPeer() catch |err| {
                std.debug.print("WebTransport H2 server fixture peer failed: stage={s} err={s}\n", .{ self.stage, @errorName(err) });
                return err;
            };
        }

        fn runPeer(self: *@This()) !void {
            try std.testing.expectError(error.InvalidEndpointOptions, (endpoint.Options{ .max_sessions = 0 }).validate());
            var faults = @import("../endpoint_client/testing/drop_faults.zig").Faults{ .caller = std.Thread.getCurrentId(), .base = self.listener.io };
            var server = try endpoint.EndpointServer.acceptTlsConnectionWithTimeout(faults.allocator(), self.listener, .{ .max_sessions = 2, .max_pending_sessions = 2 }, .fromSeconds(3));
            defer server.deinit();
            try std.testing.expectEqual(
                tls_stream.Protocol.tls13,
                server.negotiatedTlsProtocol().?,
            );
            try std.testing.expect(server.wasTlsSessionResumed() != null);
            try std.testing.expect(server.remoteAddress().?.getPort() != 0);
            try std.testing.expectEqual(@as(u64, 0), server.localKeyUpdateCount());
            try std.testing.expectEqual(@as(u64, 0), server.peerKeyUpdateCount());
            self.stage = "KeyUpdate";
            try server.initiateKeyUpdate();
            try std.testing.expectEqual(@as(u64, 1), server.localKeyUpdateCount());
            try std.testing.expectEqual(@as(u64, 0), server.peerKeyUpdateCount());

            self.stage = "rejected CONNECT";
            var rejected = try acceptRequest(server, "/reject");
            var rejected_owned = true;
            defer if (rejected_owned) rejected.deinit();
            try rejected.rejectWithTimeout(.{
                .status = 429,
                .headers = &.{.{ .name = "retry-after", .value = "13" }},
                .body = "later",
                .trailers = &.{.{ .name = "x-rejected", .value = "server" }},
            }, .fromSeconds(3));
            rejected_owned = false;

            self.stage = "dropped CONNECT";
            var dropped = try acceptRequest(server, "/dropped");
            const dropped_handle = dropped.data.handle;
            {
                server.state.mutex.lockUncancelable(self.listener.io);
                defer server.state.mutex.unlock(self.listener.io);
                faults.tracking.store(true, .release);
                faults.deny.store(true, .release);
                defer faults.tracking.store(false, .release);
                const queued = server.state.queued;
                dropped.deinit();
                try std.testing.expectEqual(@as(usize, 0), faults.attempts.load(.acquire));
                try std.testing.expectEqual(queued, server.state.queued);
                try std.testing.expectEqual(dropped_handle.generation, server.state.pending[dropped_handle.index].cleanup.pending.load(.acquire));
            }

            self.stage = "accepted CONNECT a";
            var a_request = try acceptRequest(server, "/a");
            var a_owned = true;
            defer if (a_owned) a_request.deinit();
            var a_accepted = try a_request.acceptWithTimeout(.{ .headers = &.{.{ .name = "x-session", .value = "/a" }} }, .fromSeconds(3));
            a_owned = false;
            defer a_accepted.deinit();
            self.stage = "accepted CONNECT b";
            var b_request = try acceptRequest(server, "/b");
            var b_owned = true;
            defer if (b_owned) b_request.deinit();
            var b_accepted = try b_request.acceptWithTimeout(.{ .headers = &.{.{ .name = "x-session", .value = "/b" }} }, .fromSeconds(3));
            b_owned = false;
            defer b_accepted.deinit();
            const a = a_accepted.handle;
            const b = b_accepted.handle;
            var key_a = try server.exportKeyingMaterialWithTimeout(a, "server", "context", 32, .fromSeconds(3));
            defer key_a.deinit();
            var key_b = try server.exportKeyingMaterialWithTimeout(b, "server", "context", 32, .fromSeconds(3));
            defer key_b.deinit();
            try std.testing.expect(!std.mem.eql(u8, key_a.value, key_b.value));

            self.stage = "capacity overflow CONNECT";
            var overflow = try acceptRequest(server, "/overflow");
            defer overflow.deinit();
            try std.testing.expectError(error.EndpointCapacity, overflow.acceptWithTimeout(.{}, .fromSeconds(3)));

            self.stage = "STREAM input and reply";
            var stream_event = try server.receiveWithTimeout(a, .fromSeconds(3));
            defer stream_event.deinit();
            try std.testing.expectEqualStrings("hello", stream_event.value.stream.data);
            const stream_id = stream_event.value.stream.id;
            try server.consumeWithDeadline(a, stream_id, 5, deadline(server.state.io));
            try server.sendStreamSlicesWithTimeout(a, stream_id, &.{ "rep", "ly" }, true, .fromSeconds(3));
            try server.retireStreamWithDeadline(a, stream_id, deadline(server.state.io));
            self.stage = "DATAGRAM input and reply";
            var datagram = try server.receiveWithTimeout(b, .fromSeconds(3));
            defer datagram.deinit();
            try std.testing.expectEqualStrings("ping", datagram.value.datagram);
            try server.sendDatagramWithTimeout(b, "pong", .fromSeconds(3));

            self.stage = "CLOSE input";
            var close_a = try server.receiveWithTimeout(a, .fromSeconds(3));
            defer close_a.deinit();
            try std.testing.expectEqual(@as(u32, 1), close_a.value.closed.code);
            var close_b = try server.receiveWithTimeout(b, .fromSeconds(3));
            defer close_b.deinit();
            try std.testing.expectEqual(@as(u32, 2), close_b.value.closed.code);
            try std.testing.expect(try server.removeWithTimeout(a, .fromSeconds(3)));
            try std.testing.expect(try server.removeWithTimeout(b, .fromSeconds(3)));

            self.stage = "reused CONNECT";
            var reused_request = try acceptRequest(server, "/reused");
            var reused_owned = true;
            defer if (reused_owned) reused_request.deinit();
            var reused = try reused_request.acceptWithTimeout(.{}, .fromSeconds(3));
            reused_owned = false;
            defer reused.deinit();
            const previous = if (reused.handle.index == a.index) a else b;
            try std.testing.expectEqual(previous.index, reused.handle.index);
            try std.testing.expect(previous.generation != reused.handle.generation);
            // EndpointServer deinit aborts this still-live Session and closes
            // the connection after its worker has joined.
        }
    };
    var peer = Peer{ .listener = &listener };
    var peer_task = io.async(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, listener.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(3));
    defer connection.close();

    var rejected = try h2.runtime.connectDuplexAttemptWithTimeout(allocator, &connection, .{ .path = "/reject", .authority = "localhost" }, .fromSeconds(3));
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 429), rejected.status());
    try std.testing.expectEqualStrings("later", rejected.body());
    try std.testing.expectEqualStrings("server", rejected.trailers()[0].value);
    try std.testing.expectError(error.StreamReset, h2.runtime.connectDuplexAttemptWithTimeout(allocator, &connection, .{ .path = "/dropped", .authority = "localhost" }, .fromSeconds(3)));

    var a = try h2.runtime.connectDuplexWithTimeout(allocator, &connection, .{ .path = "/a", .authority = "localhost" }, .fromSeconds(3));
    defer a.deinit();
    var b = try h2.runtime.connectDuplexWithTimeout(allocator, &connection, .{ .path = "/b", .authority = "localhost" }, .fromSeconds(3));
    defer b.deinit();
    try std.testing.expectEqualStrings("/a", a.responseHeader("x-session").?);
    try std.testing.expectEqualStrings("/b", b.responseHeader("x-session").?);

    var overflow = try h2.runtime.connectDuplexAttemptWithTimeout(allocator, &connection, .{ .path = "/overflow", .authority = "localhost" }, .fromSeconds(3));
    defer overflow.deinit();
    try std.testing.expect(!overflow.accepted());
    try std.testing.expectEqual(@as(u16, 429), overflow.status());

    const stream_id = try a.openStream(.bidirectional);
    try a.sendStreamWithTimeout(stream_id, "hello", true, .fromSeconds(3));
    try b.sendDatagramWithTimeout("ping", .fromSeconds(3));
    const reply = (try next(&a)).stream;
    try std.testing.expectEqualStrings("reply", reply.data);
    try a.consume(stream_id, 5);
    try a.retireStream(stream_id);
    try std.testing.expectEqualStrings("pong", (try next(&b)).datagram);
    try a.closeWithTimeout(1, "a", .fromSeconds(3));
    try b.closeWithTimeout(2, "b", .fromSeconds(3));
    try std.testing.expect((try next(&a)) == .closed);
    try std.testing.expect((try next(&b)) == .closed);

    var reused = try h2.runtime.connectDuplexWithTimeout(allocator, &connection, .{ .path = "/reused", .authority = "localhost" }, .fromSeconds(3));
    defer reused.deinit();
    try peer_task.await(io);
}
