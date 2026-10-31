const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const shared = @import("shared.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const allocator = std.testing.allocator;

test "gRPC Channels map environment proxy and isolate HTTP proxy credentials" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy_listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) })
        .listen(io, .{ .reuse_address = true });
    defer proxy_listener.deinit(io);
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls_testing.certificate_base64,
    );
    const key = try tls_testing.serverKeyPair();
    var origin = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
            .protocol_policy = .tls13_only,
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        } },
    );
    defer origin.deinit();
    var authority_buffer: [64]u8 = undefined;
    const authority = try std.fmt.bufPrint(
        &authority_buffer,
        "localhost:{d}",
        .{origin.address().getPort()},
    );
    var peer = ProxyPeer{
        .io = io,
        .listener = &proxy_listener,
        .origin = &origin,
        .authority = authority,
    };
    var peer_task = io.async(ProxyPeer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};
    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://grpc%2Dproxy@127.0.0.1:{d}",
        .{proxy_listener.socket.address.getPort()},
    );
    var target = try grpc.ChannelTlsHostProxyTarget.init(
        allocator,
        .{
            .grpc_proxy = proxy_uri,
            .https_proxy = "http://unused-https-proxy.invalid:8080",
            .http_proxy = "http://unused-http-proxy.invalid:8080",
            .no_grpc_proxy = "direct-only.invalid",
            .no_proxy = "localhost",
        },
        .{},
        .{
            .host = "localhost",
            .port = origin.address().getPort(),
            .tls = .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
                },
                .protocol_policy = .tls13_only,
            },
        },
    );
    defer target.deinit();
    try std.testing.expect(target.decision.? == .proxy);
    try std.testing.expectEqual(
        grpc.ChannelProxySource.grpc_proxy,
        target.decision.?.proxy.source,
    );
    try std.testing.expect(std.mem.find(
        u8,
        target.decision.?.proxy.uri,
        "grpc%2Dproxy",
    ) == null);

    var ordinary = try channel.Channel.init(
        allocator,
        io,
        target.target,
        .{},
    );
    defer ordinary.deinit();
    var first = try ordinary.unary(request("ordinary"));
    defer first.deinit();
    try std.testing.expectEqualStrings("origin-ordinary", first.message.?.payload);

    var background = try shared.SharedChannel.init(
        allocator,
        io,
        target.target,
        .{},
    );
    defer background.deinit();
    var sender = background.sender();
    defer sender.deinit();
    var second = try sender.unary(request("shared"));
    defer second.deinit();
    try std.testing.expectEqualStrings("origin-shared", second.message.?.payload);
    try peer_task.await(io);
    try std.testing.expectEqual(@as(usize, 2), peer.accepts);
}

test "explicit gRPC endpoint proxy overrides automatic proxy policy" {
    var target = try grpc.ChannelTlsHostProxyTarget.init(
        allocator,
        .{ .grpc_proxy = "https://unsupported-environment-proxy.invalid" },
        .{ .explicit_uri = "https://unsupported-policy-proxy.invalid" },
        .{
            .host = "origin.example",
            .port = 443,
            .proxy = .{ .uri = "http://explicit-endpoint.proxy:8080" },
        },
    );
    defer target.deinit();
    try std.testing.expectEqual(@as(?grpc.ChannelProxyDecision, null), target.decision);
    try std.testing.expectEqualStrings(
        "http://explicit-endpoint.proxy:8080",
        target.target.tls_host.proxy.?.uri,
    );

    var process_target = try grpc.ChannelTlsHostProxyTarget.initEnviron(
        allocator,
        std.testing.environ,
        .{ .enabled = false },
        .{ .host = "origin.example", .port = 443 },
    );
    defer process_target.deinit();
    try std.testing.expectEqual(
        grpc.ChannelProxyDirectReason.disabled,
        process_target.decision.?.direct.reason,
    );
}

fn request(message: []const u8) grpc.UnaryCallOptions {
    return .{
        .path = "/demo.Proxy/Unary",
        .authority = null,
        .message = message,
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(3, .second) catch unreachable,
    };
}

const ProxyPeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    origin: *grpc.runtime.TlsServer,
    authority: []const u8,
    accepts: usize = 0,

    fn run(self: *ProxyPeer) !void {
        for ([_][]const u8{ "ordinary", "shared" }) |expected| {
            const stream = try self.listener.accept(self.io);
            var stream_owned = true;
            defer if (stream_owned) stream.close(self.io);
            var connect = try http1_runtime.readRequestFromStream(
                allocator,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
                .{},
            );
            defer connect.deinit(allocator);
            try std.testing.expect(connect.request.method == .CONNECT);
            try std.testing.expectEqualStrings(
                self.authority,
                connect.request.target,
            );
            try std.testing.expectEqualStrings(
                "Basic Z3JwYy1wcm94eQ==",
                connect.request.header("proxy-authorization").?,
            );
            try http1_runtime.writeResponseToStream(
                allocator,
                self.io,
                stream,
                .{ .status = 200, .request_method = .CONNECT },
            );
            const transport = try self.origin.transport.acceptStreamWithTimeout(
                stream,
                .fromSeconds(3),
            );
            stream_owned = false;
            var connection = grpc.runtime.ServerConnection{
                .connection = transport,
                .max_message_size = self.origin.max_message_size,
            };
            defer connection.deinit();
            var accepted = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer accepted.deinit();
            try std.testing.expectEqualStrings(
                self.authority,
                accepted.transport.authority.?,
            );
            try std.testing.expectEqualStrings(expected, accepted.request.message.payload);
            try std.testing.expect(
                headerValue(
                    accepted.transport.headers,
                    "proxy-authorization",
                ) == null,
            );
            var response_buffer: [64]u8 = undefined;
            const response = try std.fmt.bufPrint(
                &response_buffer,
                "origin-{s}",
                .{expected},
            );
            try connection.writeUnary(accepted.request.stream_id, .{
                .message = response,
            });
            self.accepts += 1;
        }
    }
};

fn headerValue(
    fields: []const @import("../../http2/mod.zig").Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}
