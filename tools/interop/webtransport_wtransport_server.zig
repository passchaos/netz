const std = @import("std");
const netz = @import("netz");

const client_datagram = "wtransport datagram";
const server_datagram = "netz datagram";
const client_bidi = "wtransport bidi";
const server_bidi = "netz bidi";
const client_uni = "wtransport uni";
const server_uni = "netz uni";
const close_ready = "close ready";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [
        netz.tls.testing.certificate_der_len
    ]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const server_cid = [_]u8{ 0x77, 0x74, 0x69, 0x6f, 0x70, 0x00, 0x00, 0x01 };

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 16,
            } },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .max_crypto_buffer = 64 * 1024,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz WebTransport interop server listening on {f}\n",
        .{server.address()},
    );

    var session = try server.accept();
    defer session.deinit();
    if (!std.mem.eql(u8, session.request.request.path, "/interop")) {
        return error.UnexpectedPath;
    }
    std.debug.print("netz WebTransport interop accepted CONNECT\n", .{});

    var datagram = try session.receiveDatagram();
    defer datagram.deinit(allocator);
    if (!std.mem.eql(u8, datagram.datagram.payload, client_datagram)) {
        return error.UnexpectedDatagram;
    }
    std.debug.print("netz WebTransport interop received DATAGRAM\n", .{});
    try session.sendDatagram(server_datagram);

    var bidi = try session.receiveStream();
    defer bidi.deinit();
    if (bidi.direction != .bidirectional or
        bidi.locally_initiated or
        !bidi.fin or
        !std.mem.eql(u8, bidi.payload, client_bidi))
    {
        return error.UnexpectedBidirectionalStream;
    }
    std.debug.print("netz WebTransport interop received bidi\n", .{});
    try session.sendStream(bidi.stream_id, server_bidi, true);

    var uni = try session.receiveStream();
    defer uni.deinit();
    if (uni.direction != .unidirectional or
        uni.locally_initiated or
        !uni.fin or
        !std.mem.eql(u8, uni.payload, client_uni))
    {
        return error.UnexpectedUnidirectionalStream;
    }
    std.debug.print("netz WebTransport interop received uni\n", .{});
    const response_uni = try session.openUnidirectionalStream();
    try session.sendStream(response_uni, server_uni, true);
    var ready = try session.receiveDatagram();
    defer ready.deinit(allocator);
    if (!std.mem.eql(u8, ready.datagram.payload, close_ready)) {
        return error.UnexpectedCloseReady;
    }
    try session.close(77, "netz done");
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    std.debug.print(
        "netz WebTransport server interop passed: CONNECT DATAGRAM bidi uni close\n",
        .{},
    );
}
