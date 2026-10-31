const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const tls = @import("../../../tls/testing.zig");
const h2 = @import("../mod.zig");
const listener_mod = @import("../endpoint_listener.zig");

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

test "WebTransport HTTP2 EndpointListener owns multiple TLS connections" {
    try exercise();
}

test "WebTransport HTTP2 EndpointListener preserves the h2c encryption boundary" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const raw = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true, .webtransport = credit },
    );
    var listener = try listener_mod.EndpointListener.initServer(
        allocator,
        raw,
        .{ .max_connections = 1, .max_pending_requests = 1, .accept_workers = 1 },
    );
    defer listener.deinit();
    var connection = try http2.runtime.Client.connectWithTimeout(
        allocator,
        io,
        listener.address(),
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .fromSeconds(3),
    );
    defer connection.close();
    try std.testing.expectError(
        error.EncryptionRequired,
        h2.runtime.connectDuplexWithTimeout(
            allocator,
            &connection,
            .{ .path = "/secure", .authority = "localhost" },
            .fromSeconds(3),
        ),
    );
}

test "WebTransport HTTP2 EndpointListener isolates a slow TLS handshake" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls.certificate_base64,
    );
    const key = try tls.serverKeyPair();
    const raw = try http2.runtime.TlsServer.listen(
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
    var listener = try listener_mod.EndpointListener.initTlsServer(
        allocator,
        raw,
        .{
            .max_connections = 2,
            .max_pending_requests = 1,
            .accept_workers = 2,
        },
    );
    defer listener.deinit();
    const address = listener.address();
    const until = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(3), .clock = .awake },
    );
    while (true) {
        const snapshot = listener_mod.EndpointListener.testing.snapshot(listener);
        if (snapshot.reserved == 2 and snapshot.connected == 0) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const stalled = try address.connect(io, .{ .mode = .stream });
    defer stalled.close(io);
    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(
        allocator,
        io,
        address,
        "localhost",
        "localhost",
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(3),
    );
    defer connection.close();
    const Connect = struct {
        fn run(value: *http2.runtime.Connection) !h2.Session {
            return h2.runtime.connectDuplexWithTimeout(
                allocator,
                value,
                .{ .path = "/healthy", .authority = "localhost" },
                .fromSeconds(3),
            );
        }
    };
    var task = try io.concurrent(Connect.run, .{&connection});
    defer _ = task.cancel(io) catch {};
    var request = try listener.receiveRequestWithTimeout(.fromSeconds(3));
    var request_owned = true;
    defer if (request_owned) request.deinit();
    try std.testing.expectEqualStrings("/healthy", request.path());
    var accepted = try request.acceptWithTimeout(.{}, .fromSeconds(3));
    request_owned = false;
    defer accepted.deinit();
    var session = try task.await(io);
    defer session.deinit();
    const snapshot = listener_mod.EndpointListener.testing.snapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), snapshot.reserved);
    try std.testing.expectEqual(@as(usize, 1), snapshot.connected);
}

test "WebTransport HTTP2 EndpointListener initialization is transactional" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.InvalidListenerOptions,
        (listener_mod.Options{ .max_connections = 0 }).validate(),
    );
    try std.testing.expectError(
        error.InvalidListenerOptions,
        (listener_mod.Options{ .accept_failure_backoff = .zero }).validate(),
    );
    const Harness = struct {
        fn run(failing: std.mem.Allocator, base: std.Io) !void {
            const raw = try http2.runtime.Server.listen(
                failing,
                base,
                .{ .ip4 = .loopback(0) },
                .{
                    .enable_connect_protocol = true,
                    .webtransport = credit,
                },
            );
            var listener = try listener_mod.EndpointListener.initServer(
                failing,
                raw,
                .{
                    .max_connections = 2,
                    .max_pending_requests = 2,
                    .accept_workers = 2,
                },
            );
            listener.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        allocator,
        Harness.run,
        .{io},
    );
}

fn exercise() !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls.certificate_base64,
    );
    const key = try tls.serverKeyPair();
    const raw = try http2.runtime.TlsServer.listen(
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
    var listener = try listener_mod.EndpointListener.initTlsServer(
        allocator,
        raw,
        .{
            .max_connections = 2,
            .max_pending_requests = 2,
            .accept_workers = 2,
            .endpoint = .{
                .max_sessions = 2,
                .max_pending_sessions = 2,
            },
        },
    );
    var listener_live = true;
    defer if (listener_live) listener.deinit();
    const address = listener.address();
    var a_connection = try http2.runtime.Client.connectTlsAddressWithTimeout(
        allocator,
        io,
        address,
        "localhost",
        "localhost",
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(3),
    );
    var a_connection_live = true;
    defer if (a_connection_live) a_connection.close();
    var b_connection = try http2.runtime.Client.connectTlsAddressWithTimeout(
        allocator,
        io,
        address,
        "localhost",
        "localhost",
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(3),
    );
    defer b_connection.close();

    const Connect = struct {
        fn run(
            connection: *http2.runtime.Connection,
            path: []const u8,
            started: *std.Io.Event,
        ) !h2.Session {
            started.set(connection.io);
            return h2.runtime.connectDuplexWithTimeout(
                allocator,
                connection,
                .{ .path = path, .authority = "localhost" },
                .fromSeconds(3),
            );
        }
    };
    var a_started: std.Io.Event = .unset;
    var b_started: std.Io.Event = .unset;
    var a_task = try io.concurrent(
        Connect.run,
        .{ &a_connection, "/a", &a_started },
    );
    defer _ = a_task.cancel(io) catch {};
    var b_task = try io.concurrent(
        Connect.run,
        .{ &b_connection, "/b", &b_started },
    );
    defer _ = b_task.cancel(io) catch {};
    try a_started.wait(io);
    try b_started.wait(io);

    var a_accepted: ?listener_mod.Accepted = null;
    defer if (a_accepted) |*value| value.deinit();
    var b_accepted: ?listener_mod.Accepted = null;
    defer if (b_accepted) |*value| value.deinit();
    for (0..2) |_| {
        var request = try listener.receiveRequestWithTimeout(.fromSeconds(3));
        var request_owned = true;
        defer if (request_owned) request.deinit();
        const is_a = std.mem.eql(u8, request.path(), "/a");
        const is_b = std.mem.eql(u8, request.path(), "/b");
        const accepted = try request.acceptWithTimeout(
            .{ .headers = &.{.{
                .name = "x-connection",
                .value = request.path(),
            }} },
            .fromSeconds(3),
        );
        request_owned = false;
        if (is_a) {
            a_accepted = accepted;
        } else if (is_b) {
            b_accepted = accepted;
        } else return error.TestUnexpectedResult;
    }
    try std.testing.expect(a_accepted != null and b_accepted != null);
    try std.testing.expect(
        a_accepted.?.handle.connection.index !=
            b_accepted.?.handle.connection.index,
    );

    var a_session = try a_task.await(io);
    var a_session_live = true;
    defer if (a_session_live) a_session.deinit();
    var b_session = try b_task.await(io);
    defer b_session.deinit();
    try std.testing.expectEqualStrings(
        "/a",
        a_session.responseHeader("x-connection").?,
    );
    try std.testing.expectEqualStrings(
        "/b",
        b_session.responseHeader("x-connection").?,
    );

    try a_session.sendDatagramWithTimeout("from-a", .fromSeconds(3));
    try b_session.sendDatagramWithTimeout("from-b", .fromSeconds(3));
    var a_event = try listener.receiveWithTimeout(
        a_accepted.?.handle,
        .fromSeconds(3),
    );
    defer a_event.deinit();
    var b_event = try listener.receiveWithTimeout(
        b_accepted.?.handle,
        .fromSeconds(3),
    );
    defer b_event.deinit();
    try std.testing.expectEqualStrings("from-a", a_event.value.datagram);
    try std.testing.expectEqualStrings("from-b", b_event.value.datagram);
    try listener.sendDatagramWithTimeout(
        a_accepted.?.handle,
        "to-a",
        .fromSeconds(3),
    );
    try listener.sendDatagramWithTimeout(
        b_accepted.?.handle,
        "to-b",
        .fromSeconds(3),
    );
    try std.testing.expectEqualStrings(
        "to-a",
        (try next(&a_session)).datagram,
    );
    try std.testing.expectEqualStrings(
        "to-b",
        (try next(&b_session)).datagram,
    );

    a_session.deinit();
    a_session_live = false;
    a_connection.close();
    a_connection_live = false;
    try b_session.sendDatagramWithTimeout("still-b", .fromSeconds(3));
    var surviving = try listener.receiveWithTimeout(
        b_accepted.?.handle,
        .fromSeconds(3),
    );
    defer surviving.deinit();
    try std.testing.expectEqualStrings("still-b", surviving.value.datagram);
    try listener.sendDatagramWithTimeout(
        b_accepted.?.handle,
        "alive",
        .fromSeconds(3),
    );
    try std.testing.expectEqualStrings(
        "alive",
        (try next(&b_session)).datagram,
    );

    var c_connection = try http2.runtime.Client.connectTlsAddressWithTimeout(
        allocator,
        io,
        address,
        "localhost",
        "localhost",
        .{ .enable_connect_protocol = true, .webtransport = credit },
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(3),
    );
    defer c_connection.close();
    var c_started: std.Io.Event = .unset;
    var c_task = try io.concurrent(
        Connect.run,
        .{ &c_connection, "/c", &c_started },
    );
    defer _ = c_task.cancel(io) catch {};
    try c_started.wait(io);
    var c_request = try listener.receiveRequestWithTimeout(.fromSeconds(3));
    var c_request_owned = true;
    defer if (c_request_owned) c_request.deinit();
    var c_accepted = try c_request.acceptWithTimeout(
        .{ .headers = &.{.{ .name = "x-connection", .value = "/c" }} },
        .fromSeconds(3),
    );
    c_request_owned = false;
    defer c_accepted.deinit();
    try std.testing.expectEqual(
        a_accepted.?.handle.connection.index,
        c_accepted.handle.connection.index,
    );
    try std.testing.expect(
        a_accepted.?.handle.connection.generation !=
            c_accepted.handle.connection.generation,
    );
    var c_session = try c_task.await(io);
    defer c_session.deinit();
    try std.testing.expectEqualStrings(
        "/c",
        c_session.responseHeader("x-connection").?,
    );
    try c_session.sendDatagramWithTimeout("from-c", .fromSeconds(3));
    var c_event = try listener.receiveWithTimeout(
        c_accepted.handle,
        .fromSeconds(3),
    );
    defer c_event.deinit();
    try std.testing.expectEqualStrings("from-c", c_event.value.datagram);

    var pending_started: std.Io.Event = .unset;
    var pending_task = try io.concurrent(
        Connect.run,
        .{ &b_connection, "/pending", &pending_started },
    );
    defer _ = pending_task.cancel(io) catch {};
    try pending_started.wait(io);
    var pending = try listener.receiveRequestWithTimeout(.fromSeconds(3));
    defer pending.deinit();
    listener.deinit();
    listener_live = false;
    try std.testing.expectError(
        error.EndpointClosed,
        pending.acceptWithTimeout(.{}, .fromSeconds(3)),
    );
}

fn next(session: *h2.Session) !h2.state.Event {
    while (true) {
        const event = try session.receiveWithTimeout(.fromSeconds(3));
        if (event != .progress) return event;
    }
}
