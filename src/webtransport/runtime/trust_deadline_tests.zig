const std = @import("std");
const client = @import("endpoint_client.zig");
const Probe = @import("../../internal/testing/trust_admission.zig").Probe;

test "WebTransport H3 trust startup deadline admits a timer before loading roots" {
    var probe: Probe = .{};
    var options: client.Options = .{};
    options.h3.handshake.original_destination_connection_id = "trust-origin";
    options.h3.handshake.local_connection_id = "trust-client";
    try std.testing.expectError(error.ConcurrencyUnavailable, client.Client.connectUriWithDeadline(std.testing.allocator, probe.io(), .{ .ip4 = .loopback(0) }, "https://trust.test/", options, probe.deadline()));
    try probe.expectRejected();
}

test "WebTransport H3 startup entropy includes preparation in the configured connect timeout" {
    const EntropyProbe = @import("../../internal/testing/startup_entropy.zig").Probe;
    inline for (.{ false, true }) |zero| {
        inline for (.{ false, true }) |bounded| {
            var probe: EntropyProbe = .{};
            var options: client.Options = .{};
            options.h3.connect_timeout = .fromMilliseconds(if (zero) 0 else 1000);
            const result = if (bounded)
                client.Client.connectUriWithDeadline(std.testing.allocator, probe.io(), .{ .ip4 = .loopback(0) }, "https://startup.test/", options, probe.deadline())
            else
                client.Client.connectUri(std.testing.allocator, probe.io(), .{ .ip4 = .loopback(0) }, "https://startup.test/", options);
            try std.testing.expectError(if (zero) error.HandshakeTimeout else error.ConcurrencyUnavailable, result);
            try probe.expectUntouched(if (zero) 0 else 1);
        }
    }
}

test "WebTransport H3 startup entropy URI authenticates with generated connection IDs" {
    const quic = @import("../../quic/mod.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var backend = try @import("zio").Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const Peer = struct {
        endpoint: *quic.runtime.Endpoint,
        options: quic.handshake.ServerOptions,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var established = quic.handshake.acceptWithTimeout(self.endpoint, self.options, .fromSeconds(3)) catch |err| {
                self.err = err;
                return;
            };
            defer established.deinit();
            self.release.wait(self.endpoint.io) catch |err| {
                self.err = err;
            };
        }
    };
    var peer: Peer = .{ .endpoint = &endpoint, .options = .{
        .local_connection_id = "startup-server",
        .alpn_protocol = "h3",
        .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
    } };
    var future = try std.Io.concurrent(io, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) future.cancel(io);
    const uri = try std.fmt.allocPrint(allocator, "https://127.0.0.1:{d}/", .{endpoint.address().ip4.port});
    defer allocator.free(uri);
    var connected = try client.Client.connectUriWithTimeout(allocator, io, .{ .ip4 = .loopback(0) }, uri, .{
        .limits = .{ .quic = .{ .max_datagram_size = 4096 } },
        .h3 = .{
            .connect_timeout = .fromSeconds(3),
            .handshake = .{
                .original_destination_connection_id = "",
                .local_connection_id = "",
                .server_auth = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() },
            },
        },
    }, .fromSeconds(3));
    defer connected.deinit();
    try std.testing.expect(connected.h3.established.peerCertificates() != null);
    peer.release.set(io);
    future.await(io);
    joined = true;
    if (peer.err) |err| return err;
}
