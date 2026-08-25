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
    // Browser certificate hashes impose a <=14-day validity window, so the
    // Chrome gate supplies a freshly generated DER leaf and raw P-256 scalar.
    // Native wtransport interop keeps using the stable built-in test identity.
    if (args.len != 2 and args.len != 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var built_in_certificate_der: [
        netz.tls.testing.certificate_der_len
    ]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &built_in_certificate_der,
        netz.tls.testing.certificate_base64,
    );
    var owned_certificate_der: ?[]u8 = null;
    defer if (owned_certificate_der) |bytes| allocator.free(bytes);
    var owned_private_scalar: ?[]u8 = null;
    defer if (owned_private_scalar) |bytes| allocator.free(bytes);
    const certificate_der: []const u8 = if (args.len == 4) blk: {
        owned_certificate_der = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[2],
            allocator,
            .limited(16 * 1024),
        );
        break :blk owned_certificate_der.?;
    } else &built_in_certificate_der;
    const key_pair = if (args.len == 4) blk: {
        owned_private_scalar = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[3],
            allocator,
            .limited(33),
        );
        if (owned_private_scalar.?.len != 32) return error.InvalidArgument;
        const secret = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey
            .fromBytes(owned_private_scalar.?[0..32].*);
        break :blk try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair
            .fromSecretKey(secret);
    } else try netz.tls.testing.serverKeyPair();
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
                    .certificate_chain = &.{certificate_der},
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

    var pending = try server.receiveSessionRequest();
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.path(), "/interop")) {
        return error.UnexpectedPath;
    }
    if (!std.mem.eql(
        u8,
        pending.userAgent() orelse return error.UnexpectedHeader,
        "netz-wtransport-gate",
    )) return error.UnexpectedHeader;
    const authorization = blk: {
        for (pending.headers()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
                break :blk header.value;
            }
        }
        return error.UnexpectedHeader;
    };
    if (!std.mem.eql(u8, authorization, "Bearer wtransport-interop")) {
        return error.UnexpectedHeader;
    }
    var session = try pending.acceptWithHeaders(&.{.{
        .name = "x-netz-admission",
        .value = "accepted",
    }});
    pending_owned = false;
    defer session.deinit();
    const max_datagram_size = session.maxDatagramSize();
    if (max_datagram_size == 0) return error.UnexpectedDatagramLimit;
    const oversized_datagram = try allocator.alloc(
        u8,
        max_datagram_size + 1,
    );
    defer allocator.free(oversized_datagram);
    @memset(oversized_datagram, 0xa5);
    try std.testing.expectError(
        error.DatagramTooLarge,
        session.sendDatagram(oversized_datagram),
    );
    std.debug.print(
        "netz WebTransport interop accepted CONNECT with admission metadata\n",
        .{},
    );

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
    var sibling_stream_id: ?u62 = null;
    var sibling_received: usize = 0;
    var sibling_finished = false;
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
            .data => |data| {
                if (data.direction != .bidirectional or
                    data.locally_initiated)
                {
                    return error.UnexpectedStoppedStream;
                }
                if (sibling_stream_id) |id| {
                    if (data.stream_id != id) {
                        return error.UnexpectedStoppedStream;
                    }
                } else {
                    sibling_stream_id = data.stream_id;
                }
                if (data.bytes > reuse_request.len - sibling_received or
                    !std.mem.eql(
                        u8,
                        read_buffer[0..data.bytes],
                        reuse_request[sibling_received..][0..data.bytes],
                    ))
                {
                    return error.UnexpectedStoppedStream;
                }
                sibling_received += data.bytes;
                if (data.fin) {
                    if (sibling_received != reuse_request.len) {
                        return error.UnexpectedStoppedStream;
                    }
                    sibling_finished = true;
                }
            },
            .reset => return error.UnexpectedStoppedStream,
        }
    }
    while (!sibling_finished) {
        const event = try session.readStream(&read_buffer);
        if (event != .data) return error.UnexpectedStream;
        const data = event.data;
        if (sibling_stream_id) |id| {
            if (data.stream_id != id) return error.UnexpectedStream;
        } else {
            sibling_stream_id = data.stream_id;
        }
        if (data.bytes > reuse_request.len - sibling_received or
            !std.mem.eql(
                u8,
                read_buffer[0..data.bytes],
                reuse_request[sibling_received..][0..data.bytes],
            ))
        {
            return error.UnexpectedStream;
        }
        sibling_received += data.bytes;
        if (data.fin) {
            if (sibling_received != reuse_request.len) {
                return error.UnexpectedStream;
            }
            sibling_finished = true;
        }
    }
    try session.sendDatagram(cancel_done);

    try session.sendStream(sibling_stream_id.?, reuse_response, true);

    var ready = try session.receiveDatagram();
    defer ready.deinit(allocator);
    if (!std.mem.eql(u8, ready.datagram.payload, close_ready)) {
        return error.UnexpectedCloseReady;
    }
    // wtransport does not expose DRAIN as an application event, but its
    // CONNECT-stream driver must skip this registered capsule without losing
    // framing. Follow it with a connection-level close to verify that netz
    // keeps WT Session shutdown and QUIC shutdown as distinct APIs.
    try session.drain();
    try session.closeConnection(77, "netz done");
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    std.debug.print(
        "netz WebTransport server interop passed: CONNECT DATAGRAM max_datagram_size={d} oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-connection-close=true close\n",
        .{max_datagram_size},
    );
}
