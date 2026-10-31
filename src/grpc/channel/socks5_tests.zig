const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const shared = @import("shared.zig");
const stream_io = @import("../../internal/stream_io.zig");
const tls_testing = @import("../../tls/testing.zig");

const allocator = std.testing.allocator;

test "gRPC Channels use authenticated SOCKS5 remote DNS without credential leakage" {
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
    var peer = Peer{
        .io = io,
        .proxy = &proxy,
        .origin = &origin,
        .authority = authority,
    };
    var peer_task = io.async(Peer.run, .{&peer});
    defer _ = peer_task.cancel(io) catch {};

    var resolver_calls: std.atomic.Value(usize) = .init(0);
    const resolver: channel.AddressResolver = .{
        .context = &resolver_calls,
        .resolve = failLocalResolution,
    };
    const endpoint: channel.Target = .{ .tls_host = .{
        .host = "localhost",
        .port = origin.address().getPort(),
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
            },
            .protocol_policy = .tls13_only,
        },
        .socks5_proxy = .{
            .host = "127.0.0.1",
            .port = proxy.socket.address.getPort(),
            .options = .{
                .credentials = .{
                    .username = "grpc-user",
                    .password = "grpc-pass:word",
                },
                .allow_no_authentication = false,
            },
        },
    } };

    var ordinary = try channel.Channel.init(
        allocator,
        io,
        endpoint,
        .{
            .address_resolver = resolver,
            .backoff = .{
                .initial_backoff = .fromMilliseconds(5),
                .max_backoff = .fromMilliseconds(5),
                .multiplier = 1,
                .jitter = 0,
                .min_connect_timeout = .fromMilliseconds(50),
            },
        },
    );
    defer ordinary.deinit();
    var first = try ordinary.unary(request("ordinary"));
    defer first.deinit();
    try std.testing.expectEqualStrings(
        "origin-ordinary",
        first.message.?.payload,
    );

    var background = try shared.SharedChannel.init(
        allocator,
        io,
        endpoint,
        .{ .channel = .{ .address_resolver = resolver } },
    );
    defer background.deinit();
    var sender = background.sender();
    defer sender.deinit();
    var second = try sender.unary(request("shared"));
    defer second.deinit();
    try std.testing.expectEqualStrings(
        "origin-shared",
        second.message.?.payload,
    );

    try peer_task.await(io);
    try std.testing.expectEqual(@as(usize, 2), peer.accepts);
    try std.testing.expectEqual(@as(usize, 3), peer.connections);
    try std.testing.expectEqual(
        @as(usize, 0),
        resolver_calls.load(.acquire),
    );
}

test "gRPC channel rejects conflicting or malformed SOCKS5 proxy options" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const valid: grpc.ChannelSocks5Proxy = .{
        .host = "proxy.example",
    };
    try std.testing.expectError(
        error.InvalidChannelOptions,
        channel.Channel.init(allocator, io, .{ .tls_host = .{
            .host = "origin.example",
            .port = 443,
            .proxy = .{ .uri = "http://proxy.example" },
            .socks5_proxy = valid,
        } }, .{}),
    );
    for ([_]grpc.ChannelSocks5Proxy{
        .{ .host = "", .port = 1080 },
        .{ .host = "proxy.example", .port = 0 },
        .{ .host = "proxy.example", .options = .{
            .allow_no_authentication = false,
        } },
        .{ .host = "proxy.example", .options = .{ .credentials = .{
            .username = "",
            .password = "secret",
        } } },
    }) |proxy| {
        try std.testing.expectError(
            error.InvalidChannelOptions,
            channel.Channel.init(allocator, io, .{ .tls_host = .{
                .host = "origin.example",
                .port = 443,
                .socks5_proxy = proxy,
            } }, .{}),
        );
    }
    try std.testing.expectError(
        error.InvalidChannelOptions,
        channel.Channel.init(allocator, io, .{ .tls_host = .{
            .host = "origin.example",
            .port = 0,
            .socks5_proxy = valid,
        } }, .{}),
    );
    try std.testing.expectError(
        error.InvalidChannelOptions,
        shared.SharedChannel.init(allocator, io, .{ .tls_host = .{
            .host = "origin.example",
            .port = 443,
            .socks5_proxy = .{ .host = "" },
        } }, .{}),
    );
}

fn failLocalResolution(
    context: *anyopaque,
    _: std.mem.Allocator,
    _: std.Io,
    _: []const u8,
    _: u16,
    _: ?std.Io.Clock.Timestamp,
) channel.AddressResolver.ResolveError![]std.Io.net.IpAddress {
    const calls: *std.atomic.Value(usize) = @ptrCast(@alignCast(context));
    _ = calls.fetchAdd(1, .acq_rel);
    return error.UnknownHostName;
}

fn request(message: []const u8) grpc.UnaryCallOptions {
    return .{
        .path = "/demo.Socks5/Unary",
        .authority = null,
        .message = message,
        .wait_for_ready = true,
        .timeout = grpc.Timeout.init(3, .second) catch unreachable,
    };
}

const Peer = struct {
    io: std.Io,
    proxy: *std.Io.net.Server,
    origin: *grpc.runtime.TlsServer,
    authority: []const u8,
    accepts: usize = 0,
    connections: usize = 0,

    fn run(self: *Peer) !void {
        {
            const stream = try self.proxy.accept(self.io);
            defer stream.close(self.io);
            self.connections += 1;
            try acceptAuthenticatedSocks5(
                self.io,
                stream,
                "localhost",
                self.origin.address().getPort(),
                false,
            );
        }
        for ([_][]const u8{ "ordinary", "shared" }) |expected| {
            const stream = try self.proxy.accept(self.io);
            var stream_owned = true;
            defer if (stream_owned) stream.close(self.io);
            self.connections += 1;
            try acceptAuthenticatedSocks5(
                self.io,
                stream,
                "localhost",
                self.origin.address().getPort(),
                true,
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
            try std.testing.expectEqualStrings(
                expected,
                accepted.request.message.payload,
            );
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

fn acceptAuthenticatedSocks5(
    io: std.Io,
    stream: std.Io.net.Stream,
    expected_host: []const u8,
    expected_port: u16,
    succeed: bool,
) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(3), .clock = .awake },
    );
    var greeting: [2]u8 = undefined;
    try readExact(io, stream, &greeting, deadline);
    try std.testing.expectEqualSlices(u8, &.{ 5, 1 }, &greeting);
    var method: [1]u8 = undefined;
    try readExact(io, stream, &method, deadline);
    try std.testing.expectEqual(@as(u8, 2), method[0]);
    try writeExact(io, stream, &.{ 5, 2 }, deadline);

    var auth_head: [2]u8 = undefined;
    try readExact(io, stream, &auth_head, deadline);
    try std.testing.expectEqualSlices(u8, &.{ 1, 9 }, &auth_head);
    var username: [9]u8 = undefined;
    try readExact(io, stream, &username, deadline);
    try std.testing.expectEqualStrings("grpc-user", &username);
    var password_len: [1]u8 = undefined;
    try readExact(io, stream, &password_len, deadline);
    try std.testing.expectEqual(@as(u8, 14), password_len[0]);
    var password: [14]u8 = undefined;
    try readExact(io, stream, &password, deadline);
    try std.testing.expectEqualStrings("grpc-pass:word", &password);
    try writeExact(io, stream, &.{ 1, 0 }, deadline);

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
        if (succeed)
            &.{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }
        else
            &.{ 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 },
        deadline,
    );
}

fn readExact(
    io: std.Io,
    stream: std.Io.net.Stream,
    output: []u8,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try stream_io.readSomeWithDeadline(
            io,
            stream,
            output[offset..],
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

fn headerValue(
    fields: []const @import("../../http2/mod.zig").Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}
