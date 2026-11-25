const std = @import("std");
const builtin = @import("builtin");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");
const tls_testing = @import("../../tls/testing.zig");

test "QUIC compressed Certificate remains owned after the client handshake" {
    for ([_]quic.tls.certificate_compression.Algorithm{ .zlib, .brotli, .zstd }) |algorithm| try exercise(algorithm);
}

test "QUIC client verifies native roots from SSL_CERT_FILE" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    try nativeRoots(true, false);
}

test "QUIC client verifies caller-owned roots from PEM file" {
    try nativeRoots(false, false);
}

test "QUIC trust precedence caller-owned CA survives conflicting TCP verifier" {
    try nativeRoots(false, true);
}

test "QUIC trust precedence SSL_CERT_FILE survives conflicting TCP verifier" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    try nativeRoots(true, true);
}

fn nativeRoots(comptime use_environment: bool, comptime conflicting_tcp: bool) !void {
    const allocator = std.testing.allocator;
    var backend = try @import("zio").Runtime.init(allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const pem = try pemCertificate(allocator, &certificate);
    defer allocator.free(pem);

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    {
        const ca_file = try temporary.dir.createFile(io, "ca.pem", .{});
        defer ca_file.close(io);
        // Windows zio files use OVERLAPPED handles without an implicit cursor.
        try ca_file.writePositionalAll(io, pem, 0);
    }
    const path = try temporary.dir.realPathFileAlloc(
        io,
        "ca.pem",
        allocator,
    );
    defer allocator.free(path);
    const file_entry = try std.fmt.allocPrintSentinel(
        allocator,
        "SSL_CERT_FILE={s}",
        .{path},
        0,
    );
    defer allocator.free(file_entry);
    var entries = [_]?[*:0]const u8{ file_entry.ptr, null };
    const environ: ?std.process.Environ = if (use_environment)
        .{ .block = .{ .slice = entries[0..1 :null] } }
    else
        null;
    var owned_store: ?quic.tls.trust.SystemStore = if (use_environment)
        null
    else
        try quic.tls.trust.SystemStore.initWithPaths(allocator, io, std.Io.Timestamp.now(io, .real), .{ .file = path });
    defer if (owned_store) |*store| store.deinit();

    var server = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const Peer = struct {
        endpoint: *quic.runtime.Endpoint,
        options: handshake.ServerOptions,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var connection = handshake.acceptWithTimeout(
                self.endpoint,
                self.options,
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
        }
    };
    var peer: Peer = .{ .endpoint = &server, .options = .{
        .local_connection_id = "native-root-server",
        .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
    } };
    var peer_future = try std.Io.concurrent(io, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) peer_future.cancel(io);
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    var client_options: handshake.ClientOptions = .{
        .original_destination_connection_id = "native-root-origin",
        .local_connection_id = "native-root-client",
        .server_name = "localhost",
        .system_environ = environ,
        .system_store = if (owned_store) |*store| store else null,
    };
    var inherited_store: ?quic.tls.trust.SystemStore = null;
    defer if (inherited_store) |*store| store.deinit();
    if (conflicting_tcp) {
        try quic.client_trust.applyClientTrustBefore(allocator, io, &client_options, .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(9) },
            .root_source = .bundled,
        }, &inherited_store, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
        try std.testing.expect(inherited_store == null);
    }
    var connection = try handshake.connectWithTimeout(&endpoint, server.address(), client_options, .fromSeconds(3));
    defer connection.deinit();
    try std.testing.expect(connection.peerCertificates() != null);
    peer_future.await(io);
    joined = true;
    if (peer.err) |err| return err;
}

fn pemCertificate(
    allocator: std.mem.Allocator,
    certificate_der: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    const encoded_start = result.items.len;
    try result.resize(allocator, encoded_start + encoded_len);
    _ = std.base64.standard.Encoder.encode(
        result.items[encoded_start..],
        certificate_der,
    );
    try result.appendSlice(allocator, "\n-----END CERTIFICATE-----\n");
    return result.toOwnedSlice(allocator);
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
