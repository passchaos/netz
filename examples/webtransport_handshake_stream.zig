const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const original_dcid =
        [_]u8{ 0x77, 0x74, 0x10, 0x01, 0x77, 0x74, 0x10, 0x02 };
    const client_cid = [_]u8{ 0x77, 0x74, 0x10, 0x03 };
    const server_cid = [_]u8{ 0x77, 0x74, 0x10, 0x04 };

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x63} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(
            server_ptr: *netz.webtransport.runtime.HandshakeServer,
        ) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var bidi = try session.receiveStream();
            defer bidi.deinit();
            if (bidi.direction != .bidirectional or
                !std.mem.eql(u8, bidi.payload, "hello bidi"))
            {
                return error.UnexpectedStream;
            }
            try session.sendStream(
                bidi.stream_id,
                "echo bidi",
                true,
            );

            var uni = try session.receiveStream();
            defer uni.deinit();
            if (uni.direction != .unidirectional or
                !std.mem.eql(u8, uni.payload, "hello uni"))
            {
                return error.UnexpectedStream;
            }

            const response_uni =
                try session.openUnidirectionalStream();
            try session.sendStream(
                response_uni,
                "server uni",
                true,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );

    var client =
        try netz.webtransport.runtime.HandshakeClientSession.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = "/wt-stream",
                .limits = .{
                    .http3 = .{
                        .quic = .{
                            .max_datagram_size = 4096,
                            .max_frames_per_datagram = 8,
                        },
                    },
                },
                .h3 = .{
                    .handshake = .{
                        .original_destination_connection_id = &original_dcid,
                        .local_connection_id = &client_cid,
                        .server_name = "localhost",
                        .random = [_]u8{0x61} ** 32,
                        .x25519_secret_key = [_]u8{0x62} ** 32,
                    },
                },
            },
        );
    defer client.deinit();

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, "hello bidi", true);
    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, "hello uni", true);

    var bidi_response = try client.receiveStream();
    defer bidi_response.deinit();
    if (bidi_response.stream_id != bidi or
        !std.mem.eql(u8, bidi_response.payload, "echo bidi"))
    {
        return error.UnexpectedStream;
    }

    var uni_response = try client.receiveStream();
    defer uni_response.deinit();
    if (uni_response.direction != .unidirectional or
        !std.mem.eql(u8, uni_response.payload, "server uni"))
    {
        return error.UnexpectedStream;
    }

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print(
        "WebTransport handshake streams ok: bidi={d}, uni={d}, " ++
            "server_uni={d}\n",
        .{ bidi, uni, uni_response.stream_id },
    );
}
