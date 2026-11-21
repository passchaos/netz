//! Default CRYPTO limits admit certificate flights beyond the 4-KiB minimum.
const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");
const tls_testing = @import("../../tls/testing.zig");
const backends = @import("../../runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

fn exercise(io: std.Io, comptime authenticate_client: bool, comptime chain_len: usize, comptime max_retries: ?u8) !void {
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const pin = key.public_key.toUncompressedSec1();
    var chain: [chain_len][]const u8 = undefined;
    for (&chain) |*entry| entry.* = &certificate;
    try std.testing.expect(chain.len * certificate.len > 4096);
    var server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 1200 });
    defer server.deinit();
    var client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 1200 });
    defer client.deinit();
    const server_options: handshake.ServerOptions = .{
        .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .handshake_recovery = .{
            .initial_pto_ms = 20,
            .max_pto_ms = 80,
            .max_retries = max_retries orelse 3,
        },
        .identity = .{ .certificate_chain = &chain, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .client_auth = if (authenticate_client) .{ .verifier = .{ .pinned_ecdsa_p256_public_key = pin } } else null,
    };
    const Peer = struct {
        fn run(endpoint: *quic.runtime.Endpoint, options: handshake.ServerOptions) !void {
            var established = try handshake.acceptWithDeadline(endpoint, options, deadline(endpoint.io));
            defer established.deinit();
            if (authenticate_client) {
                const received = established.peerCertificates().?;
                try std.testing.expectEqual(chain_len, received.len);
                for (received) |entry| try std.testing.expectEqualSlices(u8, options.identity.?.certificate_chain[0], entry);
            }
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, server_options });
    defer _ = peer.cancel(io) catch {};
    var established = try handshake.connectWithDeadline(&client, server.address(), .{
        .original_destination_connection_id = &.{ 11, 12, 13, 14, 15, 16, 17, 18 },
        .local_connection_id = &.{ 21, 22, 23, 24, 25, 26, 27, 28 },
        .server_name = "localhost",
        .handshake_recovery = .{
            .initial_pto_ms = 20,
            .max_pto_ms = 80,
            .max_retries = max_retries orelse 3,
        },
        .server_auth = .{ .pinned_ecdsa_p256_public_key = pin },
        .certificate_compression_algorithms = &.{},
        .client_identity = if (authenticate_client) .{ .certificate_chain = &chain, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } } else null,
    }, deadline(io));
    defer established.deinit();
    try std.testing.expectEqualStrings("h3", established.alpn);
    try peer.await(io);
}

test "QUIC default CRYPTO limit admits fragmented large certificate chains and client authentication" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    exercise(threaded.io(), false, 16, 5) catch |err| {
        std.debug.print("large certificate threaded server auth: {s}\n", .{@errorName(err)});
        return err;
    };
    exercise(threaded.io(), true, 16, 5) catch |err| {
        std.debug.print("large certificate threaded mTLS: {s}\n", .{@errorName(err)});
        return err;
    };
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    exercise(backend.io(), false, 16, 5) catch |err| {
        std.debug.print("large certificate zio server auth: {s}\n", .{@errorName(err)});
        return err;
    };
    exercise(backend.io(), true, 16, 5) catch |err| {
        std.debug.print("large certificate zio mTLS: {s}\n", .{@errorName(err)});
        return err;
    };
}

test "QUIC Handshake CRYPTO flight packetizes contiguous MTU-bounded ranges" {
    var payload: [5000]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    const options: quic.initial_exchange.SendInitialFlightOptions = .{
        .initial = .{
            .destination_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .source_connection_id = &.{ 9, 10, 11, 12 },
            .packet_number = 7,
            .crypto_data = &payload,
        },
        .max_datagram_size = 1200,
    };
    const count = try quic.initial_exchange
        .handshakeCryptoFlightPacketCount(options);
    try std.testing.expect(count > 1);
    const wire = try quic.initial_exchange
        .handshakeCryptoFlightWireLen(options);
    try std.testing.expect(wire <= count * options.max_datagram_size);
    var sent: usize = 0;
    while (sent < payload.len) {
        const chunk = try quic.initial_exchange
            .largestHandshakeCryptoChunk(options, sent);
        try std.testing.expect(chunk != 0);
        try std.testing.expect(chunk <= options.initial.max_crypto_frame_data_len);
        sent += chunk;
    }
    try std.testing.expectEqual(payload.len, sent);
}

test "QUIC default CRYPTO limit retains explicit smaller and final-span bounds" {
    var small = quic.crypto_stream.Reassembler.init(allocator, 4096);
    defer small.deinit();
    try std.testing.expectError(error.CryptoBufferTooLarge, small.insert(.{ .offset = 4096, .data = "x" }));
    try std.testing.expectEqual(@as(usize, 0), small.buffer.items.len);
    var standard = quic.crypto_stream.Reassembler.init(allocator, handshake.default_max_crypto_buffer);
    defer standard.deinit();
    try standard.insert(.{ .offset = 4096, .data = "x" });
    try std.testing.expectError(error.CryptoBufferTooLarge, standard.insert(.{ .offset = handshake.default_max_crypto_buffer, .data = "x" }));
    try std.testing.expectEqual(@as(usize, 4097), standard.buffer.items.len);
}

test "QUIC client probes while the server assembles a flight beyond the initial amplification budget" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    // 40 entries exceed the budget admitted by the client Initial alone. The
    // client's PTO probes must grow the server budget before max_retries.
    exercise(threaded.io(), false, 40, null) catch |err| {
        std.debug.print("large flight threaded: {s}\n", .{@errorName(err)});
        return err;
    };
    var backend = try backends.Backend.initZio(allocator);
    defer backend.deinit();
    exercise(backend.io(), false, 40, null) catch |err| {
        std.debug.print("large flight zio: {s}\n", .{@errorName(err)});
        return err;
    };
}
