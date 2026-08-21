const std = @import("std");
const netz = @import("netz");

const client_datagram = "wtransport datagram";
const server_datagram = "netz datagram";
const client_bidi = "wtransport bidi";
const server_bidi = "netz bidi";
const client_uni = "wtransport uni";
const server_uni = "netz uni";
const client_reset = "wtransport reset";
const server_stop = "netz stop";
const reuse_request = "after cancel";
const reuse_response = "session reused";
const reset_ready = "reset ready";
const cancel_done = "cancel done";
const close_ready = "close ready";

fn receiveExpectedStream(
    session: anytype,
    buffer: []u8,
    expected_stream_id: ?u62,
    direction: netz.webtransport.StreamDirection,
    locally_initiated: bool,
    expected: []const u8,
    expect_fin: bool,
) !u62 {
    var stream_id = expected_stream_id;
    var received: usize = 0;
    while (true) {
        const event = try session.readStream(buffer);
        switch (event) {
            .data => |data| {
                if (stream_id) |id| {
                    if (data.stream_id != id) return error.UnexpectedStream;
                } else {
                    stream_id = data.stream_id;
                }
                if (data.direction != direction or
                    data.locally_initiated != locally_initiated or
                    data.bytes > expected.len - received or
                    !std.mem.eql(
                        u8,
                        buffer[0..data.bytes],
                        expected[received..][0..data.bytes],
                    ))
                {
                    return error.UnexpectedStream;
                }
                received += data.bytes;
                if (data.fin) {
                    if (!expect_fin or received != expected.len) {
                        return error.UnexpectedStream;
                    }
                    return stream_id.?;
                }
                if (!expect_fin and received == expected.len) {
                    return stream_id.?;
                }
            },
            .reset, .stopped => return error.UnexpectedStream,
        }
    }
}

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

    var read_buffer: [64]u8 = undefined;
    const bidi_stream_id = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .bidirectional,
        false,
        client_bidi,
        true,
    );
    std.debug.print("netz WebTransport interop received bidi\n", .{});
    try session.sendStream(bidi_stream_id, server_bidi, true);

    _ = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .unidirectional,
        false,
        client_uni,
        true,
    );
    std.debug.print("netz WebTransport interop received uni\n", .{});
    const response_uni = try session.openUnidirectionalStream();
    try session.sendStream(response_uni, server_uni, true);

    const reset_stream_id = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .unidirectional,
        false,
        client_reset,
        false,
    );
    try session.sendDatagram(reset_ready);
    while (true) {
        const event = try session.readStream(&read_buffer);
        switch (event) {
            .reset => |reset| {
                if (reset.stream_id != reset_stream_id or
                    reset.direction != .unidirectional or
                    reset.locally_initiated or
                    reset.error_info.application_code != 71)
                {
                    return error.UnexpectedResetStream;
                }
                break;
            },
            .data, .stopped => return error.UnexpectedResetStream,
        }
    }

    const stop_stream = try session.openUnidirectionalStream();
    try session.sendStream(stop_stream, server_stop, false);
    while (true) {
        const event = try session.readStream(&read_buffer);
        switch (event) {
            .stopped => |stopped| {
                if (stopped.stream_id != stop_stream or
                    stopped.direction != .unidirectional or
                    !stopped.locally_initiated or
                    stopped.error_info.application_code != 72)
                {
                    return error.UnexpectedStoppedStream;
                }
                break;
            },
            .data, .reset => return error.UnexpectedStoppedStream,
        }
    }
    try session.sendDatagram(cancel_done);

    const reused_stream_id = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .bidirectional,
        false,
        reuse_request,
        true,
    );
    try session.sendStream(reused_stream_id, reuse_response, true);

    var ready = try session.receiveDatagram();
    defer ready.deinit(allocator);
    if (!std.mem.eql(u8, ready.datagram.payload, close_ready)) {
        return error.UnexpectedCloseReady;
    }
    try session.close(77, "netz done");
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    std.debug.print(
        "netz WebTransport server interop passed: CONNECT DATAGRAM bidi uni reset=71 stop=72 reuse=true close\n",
        .{},
    );
}
