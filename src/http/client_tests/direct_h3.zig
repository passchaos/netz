//! Explicit unified H3 Client/Connection ownership and API parity.
const std = @import("std");
const http = @import("../mod.zig");
const h3 = @import("../../http3/runtime.zig");
const socks = @import("../../proxy/socks/server.zig");
const tls_testing = @import("../../tls/testing.zig");
const backend_mod = @import("../../runtime.zig");
const binding_checks = @import("../../internal/network_interface_test_support.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const Sink = struct {
    body: std.ArrayList(u8) = .empty,
    interims: usize = 0,
    fn responseSink(self: *Sink) http.ResponseSink {
        return .{ .context = self, .begin = begin, .data = data, .end = end, .informational = interim };
    }
    fn begin(_: *anyopaque, head: http.ResponseHead) !void {
        try std.testing.expectEqual(http.Protocol.http3, head.protocol);
        try std.testing.expectEqual(@as(u16, 201), head.status);
    }
    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *Sink = @ptrCast(@alignCast(context));
        try self.body.appendSlice(allocator, bytes);
    }
    fn end(_: *anyopaque, fields: []const http.Header) !void {
        try std.testing.expectEqualStrings("done", fields[0].value);
        try std.testing.expect(fields[0].never_indexed);
    }
    fn interim(context: *anyopaque, head: http.ResponseHead) void {
        const self: *Sink = @ptrCast(@alignCast(context));
        std.debug.assert(head.status == 103);
        self.interims += 1;
    }
};

fn exercise(io: std.Io, comptime ipv6: bool, comptime policy: http.ProtocolPolicy, comptime bind_interface: bool) !void {
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const pin = key.public_key.toUncompressedSec1();
    const limits: h3.Limits = .{ .quic = .{ .max_datagram_size = 4096, .network_interface = if (bind_interface) binding_checks.loopback() else null } };
    var server = try h3.HandshakeServer.bind(allocator, io, if (ipv6) .{ .ip6 = .loopback(0) } else .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *h3.HandshakeServer, task_io: std.Io, done: *std.Io.Event) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            for (0..6) |index| {
                var request = try session.receiveRequestWithDeadline(deadline(task_io));
                defer request.deinit(allocator);
                const expected = switch (index) {
                    0 => "slice-source",
                    1 => "reader-source",
                    2 => "manual-source",
                    5 => "reader-deadline",
                    else => "",
                };
                try std.testing.expectEqualStrings(expected, request.request.body);
                try std.testing.expectEqualStrings("done", request.request.trailers[0].value);
                try std.testing.expect(request.request.trailers[0].never_indexed);
                try session.sendInformationalResponse(request.stream_id, .{ .status = 103 });
                try session.sendResponse(request.stream_id, .{ .status = 201, .body = "result", .headers = &.{.{ .name = "x-header", .value = "v", .never_indexed = true }}, .trailers = &.{.{ .name = "x-end", .value = "done", .never_indexed = true }} });
            }
            try done.wait(task_io);
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io, &release });
    defer _ = peer.cancel(io) catch {};
    defer release.set(io);
    const uri = try std.fmt.allocPrint(allocator, "https://{s}:{d}/direct", .{ if (ipv6) "[::1]" else if (policy == .prefer_http3) "localhost" else "127.0.0.1", server.address().getPort() });
    defer allocator.free(uri);
    var client_limits = limits;
    if (bind_interface) client_limits.quic.network_interface = .{ .name = "netz_missing" };
    var client = try http.Client.init(allocator, io, .{ .protocol_policy = policy, .network_interface = if (bind_interface) binding_checks.loopback() else null, .local_address = if (bind_interface) (if (ipv6) .{ .ip6 = .loopback(0) } else .{ .ip4 = .loopback(0) }) else null, .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = pin } }, .http3 = .{ .limits = client_limits, .local_address = if (bind_interface) (if (ipv6) .{ .ip4 = .unspecified(0) } else .{ .ip6 = .unspecified(0) }) else null } });
    defer client.deinit();
    var connection = try client.connectUriWithDeadline(uri, deadline(io));
    defer connection.close();
    try std.testing.expectEqual(http.Protocol.http3, connection.protocol());
    if (bind_interface) try binding_checks.expectBound(io, connection.value.http3.client.endpoint.socket);
    try std.testing.expectEqualStrings("h3", connection.negotiatedAlpn().?);
    try std.testing.expect(connection.peerAddress().?.eql(&server.address()));
    try std.testing.expectEqual(@as(?@import("../../tls/mod.zig").stream.Protocol, .tls13), connection.negotiatedTlsProtocol());
    try std.testing.expectEqual(@as(?bool, false), connection.wasTlsSessionResumed());
    try std.testing.expectEqual(.not_offered, connection.earlyDataStatus().?);
    try std.testing.expect(connection.peerCertificates() != null);
    try std.testing.expect(connection.negotiatedCipherSuite() != null);
    try std.testing.expect(connection.negotiatedTranscriptHash() != null);
    var exported: [32]u8 = undefined;
    try connection.exportKeyingMaterial(
        "EXPORTER-netz-direct-h3",
        "connection-metadata",
        &exported,
    );
    try std.testing.expect(connection.takeTls12SessionTicket() == null);
    try std.testing.expect((try connection.takeTls13SessionTicket()) == null);
    try std.testing.expectEqual(
        @as(u64, 0),
        connection.keyUpdateCounts().?.sent,
    );
    try connection.initiateKeyUpdate();
    try std.testing.expectEqual(
        @as(u64, 1),
        connection.keyUpdateCounts().?.sent,
    );
    try std.testing.expect(!connection.keyUpdateCounts().?.awaiting_peer_response);
    const trailers: []const http.Header = &.{.{ .name = "x-end", .value = "done", .never_indexed = true }};
    var first = try connection.requestWithDeadline("/slice", .{ .method = "POST", .body = "ignored", .body_source = .{ .slice = "slice-source" }, .trailers = trailers }, deadline(io));
    defer first.deinit();
    try std.testing.expectEqual(http.Protocol.http3, first.protocol());
    try std.testing.expectEqualStrings("result", first.body());
    try std.testing.expectEqualStrings("done", first.trailer("x-end").?);
    try std.testing.expect(connection.isReusable());
    var reader = std.Io.Reader.fixed("reader-source");
    var second = try connection.requestWithDeadline("/reader", .{ .method = "POST", .body_source = .{ .reader = .{ .reader = &reader } }, .trailers = trailers }, deadline(io));
    defer second.deinit();
    try std.testing.expectEqualStrings("result", second.body());
    try std.testing.expect(connection.isReusable());
    {
        var handle = try connection.startRequestWithDeadline("/manual", .{ .method = "POST", .body_length = .unknown }, deadline(io));
        defer handle.deinit();
        var progress: http.UploadProgress = .{};
        try handle.writeBodyWithDeadline("manual-source", &progress, deadline(io));
        try std.testing.expectEqual(@as(usize, 13), progress.accepted_bytes);
        try handle.finishTrailersWithDeadline(trailers, &progress, deadline(io));
        var sink: Sink = .{};
        defer sink.body.deinit(allocator);
        _ = try handle.readResponseWithDeadline(sink.responseSink(), deadline(io));
        try std.testing.expectEqualStrings("result", sink.body.items);
        try std.testing.expectEqual(@as(usize, 1), sink.interims);
    }
    try std.testing.expect(connection.isReusable());
    var empty_slice = try connection.requestWithDeadline("/empty-slice", .{ .method = "POST", .trailers = trailers }, deadline(io));
    defer empty_slice.deinit();
    try std.testing.expectEqualStrings("result", empty_slice.body());
    var empty_reader = std.Io.Reader.fixed(&.{});
    var empty_source = try connection.requestWithDeadline("/empty-reader", .{ .method = "POST", .body_source = .{ .reader = .{ .reader = &empty_reader, .length = 0 } }, .trailers = trailers }, deadline(io));
    defer empty_source.deinit();
    try std.testing.expectEqualStrings("done", empty_source.trailer("x-end").?);
    try std.testing.expect(connection.isReusable());
    {
        var handle = try connection.startRequestWithDeadline("/reader-deadline", .{ .method = "POST", .body_length = .unknown }, deadline(io));
        defer handle.deinit();
        var source = @import("reader_gate.zig").Gate{ .io = io, .bytes = "reader-deadline", .prefix_len = 3 };
        var progress: http.UploadProgress = .{};
        try std.testing.expectError(error.Timeout, handle.writeBodyFromReaderWithTimeout(&source.reader, &progress, .fromMilliseconds(30)));
        try std.testing.expect(source.canceled);
        try std.testing.expect(source.finished);
        try std.testing.expectEqual(source.prefix_len, progress.accepted_bytes);
        source.release.set(io);
        try handle.writeBodyFromReaderWithDeadline(&source.reader, &progress, deadline(io));
        try std.testing.expectEqual(source.bytes.len - source.prefix_len, progress.accepted_bytes);
        try handle.finishTrailersWithDeadline(trailers, &progress, deadline(io));
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        const head = try handle.readResponseWithTimeout(http.ResponseSink.toWriter(&output.writer), .fromSeconds(5));
        try std.testing.expectEqual(@as(u16, 201), head.status);
        try std.testing.expectEqualStrings("result", output.written());
        _ = try handle.readResponse(http.ResponseSink.discard());
    }
    try std.testing.expect(connection.isReusable());
    release.set(io);
    try peer.await(io);
}

test "unified HTTP direct H3 Client Connection request sources streaming metadata and reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try exercise(threaded.io(), false, .http3_only, false);
    try exercise(threaded.io(), true, .http3_only, false);
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    try exercise(backend.io(), false, .http3_only, false);
    try exercise(backend.io(), true, .http3_only, false);
}

test "unified HTTP protocol policy prefers H3 on both address families and I/O backends" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try exercise(threaded.io(), false, .prefer_http3, false);
    try exercise(threaded.io(), true, .prefer_http3, false);
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    try exercise(backend.io(), false, .prefer_http3, false);
    try exercise(backend.io(), true, .prefer_http3, false);
}

test "unified HTTP direct H3 routes through SOCKS5 UDP ASSOCIATE" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls_testing.certificate_base64,
    );
    const key = try tls_testing.serverKeyPair();
    const pin = key.public_key.toUncompressedSec1();
    const limits: h3.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var server = try h3.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &.{ 9, 8, 7, 6, 5, 4, 3, 2 },
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
        } },
    );
    defer server.deinit();

    const Peer = struct {
        fn run(
            listener: *h3.HandshakeServer,
            task_io: std.Io,
        ) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var request = try session.receiveRequestWithDeadline(
                deadline(task_io),
            );
            defer request.deinit(allocator);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "socks-h3",
            });
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io });
    defer _ = peer.cancel(io) catch {};

    var proxy = try socks.Server.init(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .auth = .{ .allow_anonymous = true },
            .acl = .{ .default_action = .allow },
            .allow_udp = true,
        },
    );
    defer proxy.deinit();
    const Serve = struct {
        fn run(proxy_server: *socks.Server) !void {
            try proxy_server.serve();
        }
    };
    var proxy_loop = try io.concurrent(Serve.run, .{&proxy});
    defer _ = proxy_loop.cancel(io) catch {};

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/socks",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var client = try http.Client.init(allocator, io, .{
        .protocol_policy = .http3_only,
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = pin,
        } },
        .socks5_proxy = .{
            .host = "127.0.0.1",
            .port = proxy.listener.socket.address.ip4.port,
        },
        .http3 = .{ .limits = limits },
    });
    defer client.deinit();
    var response = try client.requestUriWithDeadline(uri, .{}, deadline(io));
    defer response.deinit();
    try std.testing.expectEqual(http.Protocol.http3, response.protocol());
    try std.testing.expectEqualStrings("socks-h3", response.body());
    try peer.await(io);
}

test "unified HTTP direct H3 rejects unsupported proxy cleartext and expired setup" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, io, .{ .protocol_policy = .http3_only, .http_proxy = .{ .uri = "http://127.0.0.1:1" } }));
    // SOCKS5 UDP ASSOCIATE can carry H3, so the strict policy accepts it.
    var socks_client = try http.Client.init(allocator, io, .{ .protocol_policy = .http3_only, .socks5_proxy = .{ .host = "localhost" } });
    socks_client.deinit();
    var h3_pool = try http.Pool.init(allocator, io, .{ .client = .{ .protocol_policy = .http3_only } });
    h3_pool.deinit();
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, io, .{ .protocol_policy = .http3_only, .http3 = .{ .handshake = .{ .connect_timeout = .zero, .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{} } } } }));
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, io, .{ .protocol_policy = .http3_only, .http3 = .{ .handshake = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{}, .alpn_protocols = &.{"h2"} } } } }));
    var oversized: http.ClientOptions = .{ .protocol_policy = .http3_only };
    oversized.http3.handshake.handshake.initial_one_rtt_config.max_datagram_size =
        oversized.http3.limits.quic.max_datagram_size + 1;
    try std.testing.expectError(error.InvalidClientOptions, http.Client.init(allocator, io, oversized));
    var client = try http.Client.init(allocator, io, .{ .protocol_policy = .http3_only });
    defer client.deinit();
    try std.testing.expectError(error.UnsupportedScheme, client.connectUriWithDeadline("http://127.0.0.1:1/", deadline(io)));
    try std.testing.expectError(error.Timeout, client.connectUriWithDeadline("https://127.0.0.1:1/", .{ .clock = .awake, .raw = .zero }));
}

fn redirectAndOneShot(comptime identity: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const pin = key.public_key.toUncompressedSec1();
    const credentials = @as(@import("../../quic/mod.zig").tls.client_auth.ClientIdentity, .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } });
    const limits: h3.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var server = try h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits, .{ .handshake = .{ .local_connection_id = &.{ 11, 12, 13, 14, 15, 16, 17, 18 }, .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } } } });
    defer server.deinit();
    const location = try std.fmt.allocPrint(allocator, "https://localhost:{d}/final", .{server.address().getPort()});
    defer allocator.free(location);
    const Peer = struct {
        fn run(listener: *h3.HandshakeServer, task_io: std.Io, target: []const u8) !void {
            for (0..if (identity) @as(usize, 1) else 3) |index| {
                var session = try listener.acceptWithTimeout(.fromSeconds(5));
                defer session.deinit();
                var request = try session.receiveRequestWithDeadline(deadline(task_io));
                defer request.deinit(allocator);
                if (index < 2) {
                    try std.testing.expectEqualStrings("payload", request.request.body);
                    var authorization: ?[]const u8 = null;
                    for (request.request.headers) |field| if (std.ascii.eqlIgnoreCase(field.name, "authorization")) {
                        authorization = field.value;
                    };
                    if (index == 0) try std.testing.expectEqualStrings("Bearer test", authorization.?) else try std.testing.expect(authorization == null);
                }
                if (index == 0) try session.sendResponse(request.stream_id, .{ .status = 307, .headers = &.{.{ .name = "location", .value = target }} }) else try session.sendResponse(request.stream_id, .{ .status = 200, .body = "owned-after-close", .headers = &.{.{ .name = "x-owned", .value = "yes", .never_indexed = true }} });
            }
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io, location });
    defer _ = peer.cancel(io) catch {};
    var client = try http.Client.init(allocator, io, .{
        .protocol_policy = .http3_only,
        .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = pin } },
        .http3 = .{ .limits = limits, .handshake = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{}, .client_identity = if (identity) credentials else null } } },
    });
    defer client.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/redirect", .{server.address().getPort()});
    defer allocator.free(uri);
    const Replay = struct {
        resets: usize = 0,
        fn rewind(context: ?*anyopaque, reader: *std.Io.Reader) std.Io.Reader.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.resets += 1;
            reader.* = .fixed("payload");
        }
    };
    var replay: Replay = .{};
    var reader = std.Io.Reader.fixed("payload");
    const result = client.requestUriFollowingRedirectsDetailedWithDeadline(uri, .{ .method = "POST", .headers = &.{.{ .name = "authorization", .value = "Bearer test", .never_indexed = true }}, .body_source = .{ .reader = .{ .reader = &reader, .length = 7, .replay = .{ .context = &replay, .rewind = Replay.rewind } } } }, .{}, deadline(io));
    if (identity) {
        try std.testing.expectError(error.CrossOriginIdentityRestricted, result);
        try std.testing.expectEqual(@as(usize, 0), replay.resets);
    } else {
        var redirected = try result;
        defer redirected.deinit();
        try std.testing.expectEqual(@as(usize, 1), redirected.redirect_count);
        try std.testing.expectEqualStrings(location, redirected.final_uri);
        try std.testing.expectEqualStrings("owned-after-close", redirected.response.body());
        try std.testing.expectEqualStrings("yes", redirected.response.header("x-owned").?);
        try std.testing.expectEqual(@as(usize, 1), replay.resets);
        var response = try client.requestUriWithDeadline(uri, .{}, deadline(io));
        defer response.deinit();
        try std.testing.expectEqual(http.Protocol.http3, response.protocol());
        try std.testing.expectEqualStrings("owned-after-close", response.body());
    }
    try peer.await(io);
}

test "unified HTTP direct H3 URI requests redirects Reader replay and credential policy" {
    try redirectAndOneShot(false);
    try redirectAndOneShot(true);
}

const CloseMode = enum { close, deadline, timeout, zero_timeout };

fn closeObservation(comptime mode: CloseMode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const pin = key.public_key.toUncompressedSec1();
    const limits: h3.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var server = try h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 31, 32, 33, 34, 35, 36, 37, 38 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *h3.HandshakeServer, task_io: std.Io, done: *std.Io.Event) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var request = try session.receiveRequestWithDeadline(deadline(task_io));
            defer request.deinit(allocator);
            try session.sendResponse(request.stream_id, .{ .status = 200, .body = "ok" });
            // The facade's close() must deliver CONNECTION_CLOSE, not just
            // drop the local QUIC owner. A zero-budget close retires locally
            // without output, so the peer observes no terminal frame.
            if (mode == .zero_timeout) {
                try std.testing.expectError(
                    error.Timeout,
                    session.receiveRequestWithDeadline(.fromNow(task_io, .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(300),
                    })),
                );
            } else {
                try std.testing.expectError(
                    error.ConnectionClosed,
                    session.receiveRequestWithDeadline(deadline(task_io)),
                );
            }
            try done.wait(task_io);
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, io, &release });
    defer _ = peer.cancel(io) catch {};
    defer release.set(io);
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/close", .{server.address().getPort()});
    defer allocator.free(uri);
    var client = try http.Client.init(allocator, io, .{ .protocol_policy = .http3_only, .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = pin } }, .http3 = .{ .limits = limits } });
    defer client.deinit();
    var connection = try client.connectUriWithDeadline(uri, deadline(io));
    var response = try connection.requestWithDeadline("/close", .{}, deadline(io));
    defer response.deinit();
    try std.testing.expectEqualStrings("ok", response.body());
    switch (mode) {
        .close => connection.close(),
        .deadline => try connection.closeWithDeadline(deadline(io)),
        .timeout => try connection.closeWithTimeout(.fromSeconds(5)),
        .zero_timeout => try std.testing.expectError(
            error.Timeout,
            connection.closeWithTimeout(.zero),
        ),
    }
    release.set(io);
    try peer.await(io);
}

test "unified HTTP direct H3 close sends CONNECTION_CLOSE" {
    try closeObservation(.close);
}

test "unified HTTP direct H3 deadline close sends CONNECTION_CLOSE" {
    try closeObservation(.deadline);
}

test "unified HTTP direct H3 timeout close sends CONNECTION_CLOSE" {
    try closeObservation(.timeout);
}

test "unified HTTP direct H3 zero-budget close retires without CONNECTION_CLOSE" {
    try closeObservation(.zero_timeout);
}

test "unified HTTP network interface direct H3 and preferred H3 retain source and device constraints" {
    if (@import("builtin").os.tag != .macos and @import("builtin").os.tag != .linux and @import("builtin").os.tag != .windows) return error.SkipZigTest;
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    try exercise(backend.io(), false, .http3_only, true);
    try exercise(backend.io(), true, .http3_only, true);
    try exercise(backend.io(), false, .prefer_http3, true);
    try exercise(backend.io(), true, .prefer_http3, true);
}
