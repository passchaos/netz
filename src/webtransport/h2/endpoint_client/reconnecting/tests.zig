const std = @import("std");
const http2 = @import("../../../../http2/mod.zig");
const tls = @import("../../../../tls/testing.zig");
const h2 = @import("../../mod.zig");
const endpoint_server = @import("../../endpoint_server.zig");
const reconnecting = @import("../reconnecting.zig");

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

test "WebTransport HTTP2 ReconnectingEndpointClient reconnects only future Sessions" {
    // The peer and both CONNECTs must run independently even when
    // opportunistic async execution would fall back to the caller.
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls.certificate_base64,
    );
    const key = try tls.serverKeyPair();
    var listener = try http2.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
            .protocol_policy = .tls13_only,
            .limits = .{
                .enable_connect_protocol = true,
                .webtransport = credit,
            },
        },
    );
    defer listener.deinit();
    var drop_first: std.Io.Event = .unset;
    const Peer = struct {
        listener: *http2.runtime.TlsServer,
        drop_first: *std.Io.Event,

        fn run(self: *@This()) !void {
            var first = try endpoint_server.EndpointServer.acceptTlsConnectionWithTimeout(
                allocator,
                self.listener,
                .{ .max_sessions = 2, .max_pending_sessions = 2 },
                .fromSeconds(3),
            );
            var first_live = true;
            defer if (first_live) first.deinit();
            try std.testing.expectEqualStrings("h2", first.negotiatedAlpn().?);
            try std.testing.expect(first.negotiatedTranscriptHash() != null);
            // The reconnecting client verifies the server but presents no
            // client certificate.
            try std.testing.expect(first.peerCertificates() == null);
            var rejected = try first.receiveRequestWithTimeout(.fromSeconds(3));
            var rejected_live = true;
            defer if (rejected_live) rejected.deinit();
            try std.testing.expectEqualStrings("/reject", rejected.path());
            try rejected.rejectWithTimeout(
                .{ .status = 429, .body = "later" },
                .fromSeconds(3),
            );
            rejected_live = false;
            var handles: [2]endpoint_server.Handle = undefined;
            for (&handles) |*handle| {
                var request = try first.receiveRequestWithTimeout(.fromSeconds(3));
                var request_live = true;
                defer if (request_live) request.deinit();
                var accepted = try request.acceptWithTimeout(
                    .{ .headers = &.{.{ .name = "x-generation", .value = "one" }} },
                    .fromSeconds(3),
                );
                request_live = false;
                handle.* = accepted.handle;
                accepted.deinit();
            }
            for (handles) |handle| {
                var event = try first.receiveWithTimeout(handle, .fromSeconds(3));
                defer event.deinit();
                try first.sendDatagramWithTimeout(
                    handle,
                    if (std.mem.eql(u8, event.value.datagram, "a")) "ack-a" else "ack-b",
                    .fromSeconds(3),
                );
            }
            try self.drop_first.wait(self.listener.io);
            first.deinit();
            first_live = false;

            var second = try endpoint_server.EndpointServer.acceptTlsConnectionWithTimeout(
                allocator,
                self.listener,
                .{ .max_sessions = 1, .max_pending_sessions = 1 },
                .fromSeconds(3),
            );
            defer second.deinit();
            var request = try second.receiveRequestWithTimeout(.fromSeconds(3));
            var request_live = true;
            defer if (request_live) request.deinit();
            var accepted = try request.acceptWithTimeout(
                .{ .headers = &.{.{ .name = "x-generation", .value = "two" }} },
                .fromSeconds(3),
            );
            request_live = false;
            defer accepted.deinit();
            var event = try second.receiveWithTimeout(
                accepted.handle,
                .fromSeconds(3),
            );
            defer event.deinit();
            try std.testing.expectEqualStrings("c", event.value.datagram);
            try second.sendDatagramWithTimeout(
                accepted.handle,
                "ack-c",
                .fromSeconds(3),
            );
        }
    };
    var peer = Peer{ .listener = &listener, .drop_first = &drop_first };
    var peer_task = try io.concurrent(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var client = try reconnecting.ReconnectingEndpointClient.init(
        allocator,
        io,
        .{ .tls_address = .{
            .address = listener.address(),
            .tls_host = "localhost",
            .authority = "localhost",
            .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
            .tls = .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
                },
                .protocol_policy = .tls13_only,
            },
        } },
        .{ .endpoint = .{ .max_sessions = 2 }, .backoff = testBackoff() },
    );
    defer client.deinit();
    var rejected = try client.connectAttemptWithTimeout(
        .{ .path = "/reject", .authority = "localhost" },
        .fromSeconds(3),
    );
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 429), rejected.status());
    try std.testing.expectEqualStrings("later", rejected.body());
    const Open = struct {
        fn run(value: reconnecting.ReconnectingEndpointClient, path: []const u8) !reconnecting.Handle {
            return value.connectWithTimeout(
                .{ .path = path, .authority = "localhost" },
                .fromSeconds(3),
            );
        }
    };
    var a_task = try io.concurrent(Open.run, .{ client, "/a" });
    defer _ = a_task.cancel(io) catch {};
    var b_task = try io.concurrent(Open.run, .{ client, "/b" });
    defer _ = b_task.cancel(io) catch {};
    const a = try a_task.await(io);
    const b = try b_task.await(io);
    try std.testing.expectEqual(a.connection_generation, b.connection_generation);
    try std.testing.expect(a.session.index != b.session.index);
    try client.sendDatagramWithTimeout(a, "a", .fromSeconds(3));
    try client.sendDatagramWithTimeout(b, "b", .fromSeconds(3));
    var ack_a = try client.receiveWithTimeout(a, .fromSeconds(3));
    defer ack_a.deinit();
    var ack_b = try client.receiveWithTimeout(b, .fromSeconds(3));
    defer ack_b.deinit();
    const first_ack = ack_a.value.datagram;
    const second_ack = ack_b.value.datagram;
    try std.testing.expect(
        std.mem.eql(u8, first_ack, "ack-a") or
            std.mem.eql(u8, first_ack, "ack-b"),
    );
    try std.testing.expect(
        !std.mem.eql(u8, first_ack, second_ack),
    );

    drop_first.set(io);
    var unexpected = client.receiveWithTimeout(a, .fromSeconds(3)) catch |err| blk: {
        try std.testing.expect(err != error.Timeout);
        break :blk null;
    };
    if (unexpected) |*event| {
        event.deinit();
        return error.TestUnexpectedResult;
    }
    _ = removeAfterDrop(client, a) catch |err| return err;
    _ = removeAfterDrop(client, b) catch |err| return err;
    const c = try client.connectWithTimeout(
        .{ .path = "/c", .authority = "localhost" },
        .fromSeconds(3),
    );
    try std.testing.expect(c.connection_generation != a.connection_generation);
    try std.testing.expectError(
        error.StaleConnection,
        client.sendDatagramWithTimeout(a, "old", .fromSeconds(3)),
    );
    try client.sendDatagramWithTimeout(c, "c", .fromSeconds(3));
    var ack_c = try client.receiveWithTimeout(c, .fromSeconds(3));
    defer ack_c.deinit();
    try std.testing.expectEqualStrings("ack-c", ack_c.value.datagram);
    try peer_task.await(io);
}

test "WebTransport HTTP2 ReconnectingEndpointClient initialization is transactional" {
    try std.testing.expectError(
        error.InvalidReconnectOptions,
        (reconnecting.Options{ .backoff = .{ .initial = .zero } }).validate(),
    );
    const Connector = struct {
        fn connect(
            _: ?*anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.Clock.Timestamp,
        ) http2.runtime.Error!http2.runtime.Connection {
            unreachable;
        }
    };
    const Harness = struct {
        fn run(failing: std.mem.Allocator) !void {
            var client = try reconnecting.ReconnectingEndpointClient.init(
                failing,
                undefined,
                .{ .custom = .{
                    .context = null,
                    .connect_fn = Connector.connect,
                } },
                .{},
            );
            client.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        allocator,
        Harness.run,
        .{},
    );
}

test "WebTransport HTTP2 ReconnectingEndpointClient bounds retryable connect failure" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Connector = struct {
        attempts: usize = 0,
        fn connect(
            context: ?*anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.Clock.Timestamp,
        ) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.attempts += 1;
            return error.ConnectionRefused;
        }
        fn retryable(_: ?*anyopaque, err: anyerror) bool {
            return err == error.ConnectionRefused;
        }
    };
    var connector: Connector = .{};
    var client = try reconnecting.ReconnectingEndpointClient.init(
        allocator,
        io,
        .{ .custom = .{
            .context = &connector,
            .connect_fn = Connector.connect,
            .retryable_fn = Connector.retryable,
        } },
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    try std.testing.expectError(
        error.Timeout,
        client.connectWithTimeout(
            .{ .path = "/retry", .authority = "localhost" },
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(connector.attempts >= 2);
    try std.testing.expect(connector.attempts < 20);
}

fn testBackoff() reconnecting.Backoff {
    return .{
        .initial = .fromMilliseconds(1),
        .maximum = .fromMilliseconds(1),
        .multiplier = 1,
        .jitter = 0,
        .min_connect_timeout = .fromSeconds(3),
    };
}

fn removeAfterDrop(
    client: reconnecting.ReconnectingEndpointClient,
    handle: reconnecting.Handle,
) !bool {
    return client.removeWithTimeout(handle, .fromSeconds(3)) catch |err| switch (err) {
        error.StaleConnection,
        error.EndpointClosed,
        error.ConnectionClosed,
        error.SocketUnconnected,
        => false,
        else => return err,
    };
}
