const std = @import("std");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const allocator = std.testing.allocator;

test "HTTP/2 TLS proxy validates timeout and allocation before proxy I/O" {
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsHostViaProxyWithTimeout(
            allocator,
            undefined,
            "localhost",
            443,
            .{ .uri = "http://proxy.invalid" },
            .{},
            .{},
            .zero,
        ),
    );
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        runtime.Client.connectTlsHostViaProxy(
            failing.allocator(),
            undefined,
            "localhost",
            443,
            .{ .uri = "http://proxy.invalid" },
            .{},
            .{},
        ),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(
        failing.allocated_bytes,
        failing.freed_bytes,
    );
}

test "HTTP/2 TLS client preserves origin identity through HTTP CONNECT proxy" {
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

    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls_testing.certificate_base64,
    );
    const key = try tls_testing.serverKeyPair();
    const limits = runtime.Limits{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var origin = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
            .protocol_policy = .tls13_only,
            .limits = limits,
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
        origin: *runtime.TlsServer,
        authority: []const u8,

        fn run(self: *@This()) !void {
            const stream = try self.proxy.accept(self.io);
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
                "Basic cHJveHk=",
                connect.request.header("proxy-authorization").?,
            );
            try http1_runtime.writeResponseToStream(
                allocator,
                self.io,
                stream,
                .{ .status = 200, .request_method = .CONNECT },
            );

            var connection = try self.origin.acceptStreamWithTimeout(
                stream,
                .fromSeconds(3),
            );
            stream_owned = false;
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings("/through-proxy", request.path);
            try std.testing.expectEqualStrings("https", request.scheme);
            try std.testing.expectEqualStrings(
                self.authority,
                request.authority.?,
            );
            try std.testing.expect(
                headerValue(request.headers, "proxy-authorization") == null,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "origin-response",
                .request_method = request.method,
            });
        }
    };
    var peer = Peer{
        .io = io,
        .proxy = &proxy,
        .origin = &origin,
        .authority = authority,
    };
    var peer_task = io.async(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{proxy.socket.address.getPort()},
    );
    var client = try runtime.Client.connectTlsHostViaProxyWithTimeout(
        allocator,
        io,
        "localhost",
        origin.address().getPort(),
        .{
            .uri = proxy_uri,
            .options = .{ .headers = &.{.{
                .name = "Proxy-Authorization",
                .value = "Basic cHJveHk=",
            }} },
        },
        limits,
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .fromSeconds(3),
    );
    defer client.close();
    var response = try client.request(.{ .path = "/through-proxy" });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("origin-response", response.body);
    try peer_task.await(io);
}

fn headerValue(
    fields: []const @import("../mod.zig").Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}
