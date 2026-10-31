const std = @import("std");
const http1 = @import("../../../../http1/mod.zig");
const http1_runtime = @import("../../../../http1/runtime.zig");
const http2 = @import("../../../../http2/mod.zig");
const stream_io = @import("../../../../internal/stream_io.zig");
const tls = @import("../../../../tls/testing.zig");
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

const ProxyKind = enum {
    http_connect,
    socks5,
};

test "WebTransport HTTP2 reconnects through HTTP CONNECT proxy" {
    try exercise(.http_connect);
}

test "WebTransport HTTP2 reconnects through SOCKS5 remote DNS proxy" {
    try exercise(.socks5);
}

fn exercise(kind: ProxyKind) !void {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls.certificate_base64,
    );
    const key = try tls.serverKeyPair();
    var origin = try http2.runtime.TlsServer.listen(
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
    defer origin.deinit();
    var authority_buffer: [64]u8 = undefined;
    const authority = try std.fmt.bufPrint(
        &authority_buffer,
        "localhost:{d}",
        .{origin.address().getPort()},
    );

    const Peer = struct {
        io: std.Io,
        proxy: *std.Io.net.Server,
        origin: *http2.runtime.TlsServer,
        authority: []const u8,
        kind: ProxyKind,

        fn run(self: *@This()) !void {
            for (0..2) |index| try self.serve(index);
        }

        fn serve(self: *@This(), index: usize) !void {
            const paths = [_][]const u8{ "/proxy-one", "/proxy-two" };
            const datagrams = [_][]const u8{ "through-one", "through-two" };
            const acknowledgements = [_][]const u8{
                "proxy-ack-one",
                "proxy-ack-two",
            };
            const stream = try self.proxy.accept(self.io);
            var stream_owned = true;
            defer if (stream_owned) stream.close(self.io);
            switch (self.kind) {
                .http_connect => try acceptHttpConnect(
                    self.io,
                    stream,
                    self.authority,
                ),
                .socks5 => try acceptSocks5(
                    self.io,
                    stream,
                    "localhost",
                    self.origin.address().getPort(),
                ),
            }
            const connection = try self.origin.acceptStreamWithTimeout(
                stream,
                .fromSeconds(3),
            );
            stream_owned = false;
            var server = try endpoint_server.EndpointServer.init(
                allocator,
                connection,
                .{ .max_sessions = 1, .max_pending_sessions = 1 },
            );
            defer server.deinit();
            var pending = try server.receiveRequestWithTimeout(
                .fromSeconds(3),
            );
            var pending_live = true;
            defer if (pending_live) pending.deinit();
            try std.testing.expectEqualStrings(paths[index], pending.path());
            try std.testing.expectEqualStrings(
                self.authority,
                pending.authority().?,
            );
            try std.testing.expect(
                pending.header("proxy-authorization") == null,
            );
            var accepted = try pending.acceptWithTimeout(
                .{},
                .fromSeconds(3),
            );
            pending_live = false;
            defer accepted.deinit();
            var event = try server.receiveWithTimeout(
                accepted.handle,
                .fromSeconds(3),
            );
            defer event.deinit();
            try std.testing.expectEqualStrings(
                datagrams[index],
                event.value.datagram,
            );
            try server.sendDatagramWithTimeout(
                accepted.handle,
                acknowledgements[index],
                .fromSeconds(3),
            );
        }
    };
    var peer = Peer{
        .io = io,
        .proxy = &proxy,
        .origin = &origin,
        .authority = authority,
        .kind = kind,
    };
    var peer_task = io.async(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{proxy.socket.address.getPort()},
    );
    const proxy_headers = [_]http1.Header{.{
        .name = "Proxy-Authorization",
        .value = "Bearer proxy-only",
    }};
    const target: reconnecting.Target = switch (kind) {
        .http_connect => .{ .tls_http_proxy = .{
            .host = "localhost",
            .port = origin.address().getPort(),
            .proxy = .{
                .uri = proxy_uri,
                .options = .{ .headers = &proxy_headers },
            },
            .limits = endpointLimits(),
            .tls = tlsOptions(key),
        } },
        .socks5 => .{ .tls_socks5_proxy = .{
            .proxy = .{
                .host = "127.0.0.1",
                .port = proxy.socket.address.getPort(),
            },
            .host = "localhost",
            .port = origin.address().getPort(),
            .limits = endpointLimits(),
            .tls = tlsOptions(key),
        } },
    };
    var client = try reconnecting.ReconnectingEndpointClient.init(
        allocator,
        io,
        target,
        .{ .endpoint = .{ .max_sessions = 1 }, .backoff = testBackoff() },
    );
    defer client.deinit();
    const first = try client.connectWithTimeout(
        .{ .path = "/proxy-one", .authority = authority },
        .fromSeconds(3),
    );
    try client.sendDatagramWithTimeout(
        first,
        "through-one",
        .fromSeconds(3),
    );
    var first_ack = try client.receiveWithTimeout(first, .fromSeconds(3));
    defer first_ack.deinit();
    try std.testing.expectEqualStrings(
        "proxy-ack-one",
        first_ack.value.datagram,
    );
    var unexpected = client.receiveWithTimeout(first, .fromSeconds(3)) catch |err| blk: {
        try std.testing.expect(err != error.Timeout);
        break :blk null;
    };
    if (unexpected) |*event| {
        event.deinit();
        return error.TestUnexpectedResult;
    }
    _ = try removeAfterDrop(client, first);
    const second = try client.connectWithTimeout(
        .{ .path = "/proxy-two", .authority = authority },
        .fromSeconds(3),
    );
    try std.testing.expect(
        second.connection_generation != first.connection_generation,
    );
    try client.sendDatagramWithTimeout(
        second,
        "through-two",
        .fromSeconds(3),
    );
    var second_ack = try client.receiveWithTimeout(second, .fromSeconds(3));
    defer second_ack.deinit();
    try std.testing.expectEqualStrings(
        "proxy-ack-two",
        second_ack.value.datagram,
    );
    try peer_task.await(io);
}

fn endpointLimits() http2.runtime.Limits {
    return .{
        .enable_connect_protocol = true,
        .webtransport = credit,
    };
}

fn tlsOptions(key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair) http2.runtime.TlsConnectOptions {
    return .{
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
        },
        .protocol_policy = .tls13_only,
    };
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

fn acceptHttpConnect(
    io: std.Io,
    stream: std.Io.net.Stream,
    authority: []const u8,
) !void {
    var connect = try http1_runtime.readRequestFromStream(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
    );
    defer connect.deinit(allocator);
    try std.testing.expect(connect.request.method == .CONNECT);
    try std.testing.expectEqualStrings(authority, connect.request.target);
    try std.testing.expectEqualStrings(
        "Bearer proxy-only",
        connect.request.header("proxy-authorization").?,
    );
    try http1_runtime.writeResponseToStream(
        allocator,
        io,
        stream,
        .{ .status = 200, .request_method = .CONNECT },
    );
}

fn acceptSocks5(
    io: std.Io,
    stream: std.Io.net.Stream,
    expected_host: []const u8,
    expected_port: u16,
) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(3), .clock = .awake },
    );
    var greeting_head: [2]u8 = undefined;
    try readExact(io, stream, &greeting_head, deadline);
    try std.testing.expectEqual(@as(u8, 5), greeting_head[0]);
    var methods: [255]u8 = undefined;
    try readExact(
        io,
        stream,
        methods[0..greeting_head[1]],
        deadline,
    );
    try std.testing.expect(std.mem.indexOfScalar(
        u8,
        methods[0..greeting_head[1]],
        0,
    ) != null);
    try writeExact(io, stream, &.{ 5, 0 }, deadline);

    var request_head: [5]u8 = undefined;
    try readExact(io, stream, &request_head, deadline);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 5, 1, 0, 3 },
        request_head[0..4],
    );
    const host_len = request_head[4];
    var host: [255]u8 = undefined;
    try readExact(io, stream, host[0..host_len], deadline);
    var port_bytes: [2]u8 = undefined;
    try readExact(io, stream, &port_bytes, deadline);
    try std.testing.expectEqualStrings(expected_host, host[0..host_len]);
    try std.testing.expectEqual(
        expected_port,
        std.mem.readInt(u16, &port_bytes, .big),
    );
    try writeExact(
        io,
        stream,
        &.{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 },
        deadline,
    );
}

fn readExact(
    io: std.Io,
    stream: std.Io.net.Stream,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const count = try stream_io.readSomeWithDeadline(
            io,
            stream,
            out[offset..],
            deadline,
        );
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

fn writeExact(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var committed: usize = 0;
    try stream_io.writeAllTrackedWithDeadline(
        io,
        stream,
        bytes,
        &committed,
        deadline,
    );
}
