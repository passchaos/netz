const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const stream_io = @import("../../internal/stream_io.zig");
const tcp_saturation = @import("../../internal/testing/tcp_saturation.zig");

const net = std.Io.net;

test "HTTP/1 bounded CONNECT and Upgrade retire silent peers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for (.{ false, true }) |upgrade| {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
            io,
            .{ .reuse_address = true },
        );
        defer listener.deinit(io);
        var client = try runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        );
        defer client.close();
        const peer = try listener.accept(io);
        defer peer.close(io);

        if (upgrade) {
            // The same absolute budget must survive an informational head;
            // receiving 103 cannot restart the wait for the final 101.
            try stream_io.writeAllSlices(io, peer, &.{
                "HTTP/1.1 103 Early Hints\r\n" ++
                    "Link: </style.css>; rel=preload\r\n\r\n",
            });
            try std.testing.expectError(
                error.Timeout,
                client.openUpgradeWithTimeout(
                    "/upgrade",
                    "example.com",
                    "netz-timeout",
                    &.{},
                    .fromMilliseconds(20),
                ),
            );
        } else {
            try std.testing.expectError(
                error.Timeout,
                client.openConnectTunnelWithTimeout(
                    "example.com:443",
                    &.{},
                    .fromMilliseconds(20),
                ),
            );
        }
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(
            error.ConnectionUnusable,
            client.request(.{
                .method = .GET,
                .target = "/after-timeout",
                .host = "example.com",
            }),
        );
    }
}

test "HTTP/1 TLS stream adoption owns invalid timeout cleanup" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.adoptTlsStreamWithTimeout(
            allocator,
            io,
            client,
            "origin.internal",
            "origin.internal:443",
            .{},
            .{ .verify_host = false },
            .zero,
        ),
    );
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(
            io.userdata,
            peer.socket.handle,
            &buffers,
        ),
    );
}

test "HTTP/1 bounded CONNECT write fails closed under backpressure" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const peer = try listener.accept(io);
    defer peer.close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        client.stream.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const filler = [_]u8{0xa5} ** 4096;
    tcp_saturation.saturateSendBuffer(client.stream, &filler) catch |err| switch (err) {
        error.BufferNotSaturated => return error.SkipZigTest,
        else => return err,
    };

    try std.testing.expectError(
        error.Timeout,
        client.openConnectTunnelWithTimeout(
            "example.com:443",
            &.{},
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.openConnectTunnelWithTimeout(
            "example.com:443",
            &.{},
            .fromSeconds(1),
        ),
    );
}
