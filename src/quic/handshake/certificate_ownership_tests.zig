const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");
const tls_testing = @import("../../tls/testing.zig");

test "QUIC compressed Certificate remains owned after the client handshake" {
    for ([_]quic.tls.certificate_compression.Algorithm{ .zlib, .brotli, .zstd }) |algorithm| try exercise(algorithm);
}

fn exercise(algorithm: quic.tls.certificate_compression.Algorithm) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const algorithms = [_]quic.tls.certificate_compression.Algorithm{algorithm};
    var server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        endpoint: *quic.runtime.Endpoint,
        options: handshake.ServerOptions,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var connection = handshake.acceptWithTimeout(self.endpoint, self.options, .fromSeconds(3)) catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
        }
    };
    var peer: Peer = .{ .endpoint = &server, .options = .{
        .local_connection_id = "cert-retain-server",
        .certificate_compression_algorithms = &algorithms,
        .identity = .{ .certificate_chain = &.{ &certificate, &certificate }, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } },
    } };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var connection = try handshake.connectWithTimeout(&endpoint, server.address(), .{
        .original_destination_connection_id = "cert-retain-origin",
        .local_connection_id = "cert-retain-client",
        .server_name = "localhost",
        .server_auth = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() },
        .certificate_compression_algorithms = &algorithms,
    }, .fromSeconds(3));
    defer connection.deinit();
    const selected = connection.certificate_compression orelse {
        std.debug.print("compression not used for {s}\n", .{@tagName(algorithm)});
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(algorithm, selected);
    const retained = connection.peerCertificates().?;
    try std.testing.expectEqual(@as(usize, 2), retained.len);
    for (retained) |der| try std.testing.expectEqualSlices(u8, &certificate, der);
    try quic.tls.trust.verifyServerCertificateIdentity(retained[0], "localhost");
    try std.testing.expectError(error.CertificateHostMismatch, quic.tls.trust.verifyServerCertificateIdentity(retained[0], "other.test"));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
