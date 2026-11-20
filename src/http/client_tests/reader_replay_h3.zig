//! A rejected H3 upload must not fall back with an exhausted Reader.
const std = @import("std");
const http = @import("../mod.zig");
const h1 = @import("../../http1/runtime.zig");
const h3 = @import("../../http3/runtime.zig");
const protocol = @import("../../http3/mod.zig");
const tls_testing = @import("../../tls/testing.zig");
const allocator = std.testing.allocator;
const payload = "reader-replay-across-transports";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

fn exercise(comptime replayable: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const identity: @FieldType(h1.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
    };
    var tcp = try h1.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = identity,
        .alpn_protocols = &.{"http/1.1"},
    });
    defer tcp.deinit();
    var quic = try h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer quic.deinit();
    const advertisement = try std.fmt.allocPrint(allocator, "h3=\":{d}\"; ma=60", .{quic.address().getPort()});
    defer allocator.free(advertisement);
    var release: std.Io.Event = .unset;
    const TcpWorker = struct {
        fn run(listener: *h1.TlsServer, alt_svc: []const u8, finished: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var discovery = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
            defer discovery.deinit(allocator);
            try connection.writeResponse(.{
                .headers = &.{.{ .name = "alt-svc", .value = alt_svc }},
                .body = "discovered",
                .request_method = discovery.request.method,
            });
            if (replayable) {
                var upload = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
                defer upload.deinit(allocator);
                try std.testing.expectEqualStrings(payload, upload.request.body);
                try connection.writeResponse(.{ .body = "tcp-replay", .request_method = upload.request.method });
                try finished.wait(listener.io);
            } else {
                try finished.wait(listener.io);
                try std.testing.expectError(error.Timeout, connection.readRequestWithTimeout(.{}, .fromMilliseconds(100)));
            }
        }
    };
    const QuicWorker = struct {
        fn run(listener: *h3.HandshakeServer, finished: *std.Io.Event) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var upload = try session.receiveRequestWithDeadline(deadline(listener.quic_server.endpoint.io));
            defer upload.deinit(allocator);
            try std.testing.expectEqualStrings(payload, upload.request.body);
            try session.cancelRequestWithTimeout(upload.stream_id, protocol.ApplicationErrorCode.request_cancelled, .fromSeconds(5));
            try finished.wait(listener.quic_server.endpoint.io);
        }
    };
    var tcp_task = try io.concurrent(TcpWorker.run, .{ &tcp, advertisement, &release });
    defer _ = tcp_task.cancel(io) catch {};
    var quic_task = try io.concurrent(QuicWorker.run, .{ &quic, &release });
    defer _ = quic_task.cancel(io) catch {};
    defer release.set(io);
    var pool = try http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } } },
        .http3 = .{ .handshake = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key },
        } } },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://localhost:{d}/upload", .{tcp.address().getPort()});
    defer allocator.free(uri);
    var discovery = try pool.requestUriWithDeadline(uri, .{}, deadline(io));
    defer discovery.deinit();
    const Reset = struct {
        calls: usize = 0,
        fn rewind(context: ?*anyopaque, reader: *std.Io.Reader) std.Io.Reader.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            reader.* = .fixed(payload);
        }
    };
    var reset = Reset{};
    var reader = std.Io.Reader.fixed(payload);
    const result = pool.requestUriWithDeadline(uri, .{
        .method = "PUT",
        .body_source = .{ .reader = .{
            .reader = &reader,
            .length = payload.len,
            .replay = if (replayable) .{ .context = &reset, .rewind = Reset.rewind } else null,
        } },
    }, deadline(io));
    if (replayable) {
        var response = try result;
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http1, response.protocol());
        try std.testing.expectEqualStrings("tcp-replay", response.body());
        try std.testing.expectEqual(@as(usize, 1), reset.calls);
    } else {
        try std.testing.expectError(error.RequestCancelled, result);
        try std.testing.expectEqual(@as(usize, 0), reset.calls);
    }
    release.set(io);
    try tcp_task.await(io);
    try quic_task.await(io);
}

test "unified HTTP replayable Reader rewinds after an H3 upload rejection" {
    try exercise(true);
}

test "unified HTTP single-pass Reader does not fall back after an H3 upload rejection" {
    try exercise(false);
}

/// A connection-level H3 failure happens before the Reader is touched, so a
/// single-pass source can still fall back to TCP.
fn exerciseConnectionFailure() !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const identity: @FieldType(h1.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
    };
    var tcp = try h1.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = identity,
        .alpn_protocols = &.{"http/1.1"},
    });
    defer tcp.deinit();
    // Reserve a UDP port, then close it so the advertised H3 route refuses
    // connections before any request byte is written.
    var reserved = try h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .handshake = .{ .local_connection_id = &.{ 9, 9, 9, 9, 9, 9, 9, 9 }, .identity = identity },
    });
    const dead_port = reserved.address().getPort();
    reserved.deinit();
    const advertisement = try std.fmt.allocPrint(allocator, "h3=\":{d}\"; ma=60", .{dead_port});
    defer allocator.free(advertisement);
    var release: std.Io.Event = .unset;
    const TcpWorker = struct {
        fn run(listener: *h1.TlsServer, alt_svc: []const u8, finished: *std.Io.Event) !void {
            var discovery_done = false;
            while (true) {
                var connection = try listener.acceptWithTimeout(.fromSeconds(5));
                var closed = false;
                defer if (!closed) connection.close();
                while (true) {
                    var request = connection.readRequestWithTimeout(.{}, .fromMilliseconds(500)) catch break;
                    defer request.deinit(allocator);
                    if (!discovery_done) {
                        discovery_done = true;
                        try connection.writeResponse(.{
                            .headers = &.{.{ .name = "alt-svc", .value = alt_svc }},
                            .body = "discovered",
                            .request_method = request.request.method,
                        });
                        continue;
                    }
                    try std.testing.expectEqualStrings(payload, request.request.body);
                    try connection.writeResponse(.{ .body = "tcp-fallback", .request_method = request.request.method });
                    try finished.wait(listener.io);
                    return;
                }
                connection.close();
                closed = true;
            }
        }
    };
    var tcp_task = try io.concurrent(TcpWorker.run, .{ &tcp, advertisement, &release });
    defer _ = tcp_task.cancel(io) catch {};
    defer release.set(io);
    var pool = try http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } } },
        .http3 = .{
            .handshake = .{
                .connect_timeout = .fromMilliseconds(150),
                .handshake = .{
                    .original_destination_connection_id = &.{},
                    .local_connection_id = &.{},
                    .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key },
                },
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://localhost:{d}/upload", .{tcp.address().getPort()});
    defer allocator.free(uri);
    var discovery = try pool.requestUriWithDeadline(uri, .{}, deadline(io));
    defer discovery.deinit();
    var reader = std.Io.Reader.fixed(payload);
    var response = try pool.requestUriWithDeadline(uri, .{
        .method = "PUT",
        .body_source = .{ .reader = .{ .reader = &reader, .length = payload.len } },
    }, deadline(io));
    defer response.deinit();
    try std.testing.expectEqual(http.Protocol.http1, response.protocol());
    try std.testing.expectEqualStrings("tcp-fallback", response.body());
    try std.testing.expectEqual(payload.len, reader.seek);
    release.set(io);
    try tcp_task.await(io);
}

test "unified HTTP single-pass Reader falls back after an H3 connection failure" {
    try exerciseConnectionFailure();
}
