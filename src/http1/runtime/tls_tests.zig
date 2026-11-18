//! HTTP/1 TLS server, client, ALPN, and mTLS tests.

const std = @import("std");
const http1 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const CertificateBundle = runtime.CertificateBundle;
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const IdleSocketState = runtime.IdleSocketState;
const InformationalResponseHead = runtime.InformationalResponseHead;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const Server = runtime.Server;
const StapledOcspPolicy = runtime.StapledOcspPolicy;
const TlsServer = runtime.TlsServer;
const Tunnel = runtime.Tunnel;
const WriteScratch = runtime.WriteScratch;
const WriteStrategy = runtime.WriteStrategy;
const adjustResponseForServeLoop = runtime.adjustResponseForServeLoop;
const body_writer = runtime.body_writer;
const builtin = runtime.builtin;
const close_delimited = runtime.close_delimited;
const localTestCaBundle = runtime.localTestCaBundle;
const probeIdleSocket = runtime.probeIdleSocket;
const readExactForTest = runtime.readExactForTest;
const readMessageBytesBufferedWithContext = runtime.readMessageBytesBufferedWithContext;
const readRequestFromStream = runtime.readRequestFromStream;
const readResponseFromStreamBuffered = runtime.readResponseFromStreamBuffered;
const readResponseFromStreamBufferedForRequest = runtime.readResponseFromStreamBufferedForRequest;
const readResponseFromStreamForRequest = runtime.readResponseFromStreamForRequest;
const readSome = runtime.readSome;
const requestShouldSendContinue = runtime.requestShouldSendContinue;
const responseBatchWriteStrategy = runtime.responseBatchWriteStrategy;
const responseOptionsKeepAlive = runtime.responseOptionsKeepAlive;
const response_batch_borrow_threshold = runtime.response_batch_borrow_threshold;
const runtime_write = runtime.runtime_write;
const shutdownAfterTlsCloseNotify = runtime.shutdownAfterTlsCloseNotify;
const stream_io = runtime.stream_io;
const tls = runtime.tls;
const tls_stream = runtime.tls_stream;
const uriEndpoint = runtime.uriEndpoint;
const vail = runtime.vail;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const wire = runtime.wire;
const writeAllToStream = runtime.writeAllToStream;
const writeRequestToStream = runtime.writeRequestToStream;
const writeResponseToStream = runtime.writeResponseToStream;
const writeResponsesToTransportScratch = runtime.writeResponsesToTransportScratch;

test "HTTP/1 TLS server exchanges persistent requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            try std.testing.expect(connection.peerCertificates() == null);
            try std.testing.expectEqual(
                tls_stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
                connection.negotiatedCipherSuite().?,
            );
            try std.testing.expectEqual(
                tls_stream.TranscriptHash.sha256,
                connection.negotiatedTranscriptHash().?,
            );
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/first" else "/second",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
                if (index == 0) try connection.updateTrafficKeys(false);
            }
            const updates = connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 0), updates.received);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca = try localTestCaBundle(allocator, io);
    defer ca[0].deinit(allocator);
    var client = try Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .ca_bundle = .{
            .bundle = &ca[0],
            .lock = &ca[1],
        } },
    );
    defer client.close();
    var first = try client.request(.{ .target = "/first" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/second" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 negotiates TLS 1.2 with ALPN and serves a request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            if (connection.negotiatedTlsProtocol() != .tls12) {
                shared.err = error.InvalidProtocolVersion;
                return;
            }
            var request = connection.readRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(std.testing.allocator);
            if (!std.mem.eql(u8, request.request.target, "/tls12")) {
                shared.err = error.InvalidTarget;
                return;
            }
            connection.writeResponse(.{
                .body = "tls12-http1",
                .request_method = request.request.method,
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        },
    );
    defer client.close();
    try std.testing.expectEqual(
        tls_stream.Protocol.tls12,
        client.negotiatedTlsProtocol().?,
    );
    var response = try client.request(.{ .target = "/tls12" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("tls12-http1", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 vail TLS client exposes mTLS metadata and key updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *TlsServer,
        certificate: *const [tls_testing.certificate_der_len]u8,
        exporter: [32]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const chain = connection.peerCertificates() orelse
                return error.MissingPeerCertificate;
            try std.testing.expectEqual(@as(usize, 1), chain.len);
            try std.testing.expectEqualSlices(
                u8,
                shared.certificate,
                chain[0],
            );
            try std.testing.expectEqual(
                tls_stream.NegotiatedCipherSuite.aes_256_gcm_sha384,
                connection.negotiatedCipherSuite().?,
            );
            try std.testing.expectEqual(
                tls_stream.TranscriptHash.sha384,
                connection.negotiatedTranscriptHash().?,
            );
            try connection.exportKeyingMaterial(
                "EXPORTER-netz-http1",
                "context",
                &shared.exporter,
            );
            try connection.updateTrafficKeys(true);
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/before" else "/after",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
            }
            const updates = connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 1), updates.received);
            try std.testing.expect(!updates.awaiting_peer_response);
        }
    };
    var shared = Shared{
        .server = &server,
        .certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_256_gcm_sha384},
        },
    );
    defer client.close();
    const chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqualSlices(u8, &certificate_der, chain[0]);
    try std.testing.expectEqualStrings(
        "http/1.1",
        client.negotiatedAlpn().?,
    );
    try std.testing.expectEqual(
        tls_stream.NegotiatedCipherSuite.aes_256_gcm_sha384,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        tls_stream.TranscriptHash.sha384,
        client.negotiatedTranscriptHash().?,
    );
    var exporter: [32]u8 = undefined;
    try client.exportKeyingMaterial(
        "EXPORTER-netz-http1",
        "context",
        &exporter,
    );
    var first = try client.request(.{ .target = "/before" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    var second = try client.request(.{ .target = "/after" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqualSlices(u8, &shared.exporter, &exporter);
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    try std.testing.expect(!updates.awaiting_peer_response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 vail TLS options preserve stapled OCSP policy" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .stapled_ocsp = .require,
        .request_ocsp = true,
        .root_source = .bundled,
    });
    try std.testing.expectEqual(StapledOcspPolicy.require, mapped.stapled_ocsp);
    try std.testing.expect(mapped.request_ocsp);
    try std.testing.expectEqual(tls_stream.RootSource.bundled, mapped.root_source);
}
