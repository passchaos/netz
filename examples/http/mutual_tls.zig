//! Mutual TLS with a client certificate.
//!
//! Mirrors `reqwest`'s `Identity::from_pem` / `curl --cert --key`: the server
//! requires an authenticated client certificate, and the client presents one
//! in addition to verifying the server. Both sides pin the deterministic test
//! key so the example needs no files; production deployments use distinct
//! client and server identities.
//!
//! The handler can inspect `connection.peerCertificates()` before serving.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const certificate_chain = [_][]const u8{&certificate_der};

    var server = try netz.http1.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &certificate_chain,
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            // Require a client certificate and trust exactly this key.
            .client_auth = .{ .verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(5),
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.TlsServer,
        err: ?anyerror = null,
        peer_certificates: usize = 0,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const chain = connection.peerCertificates() orelse
                return error.MissingClientCertificate;
            self.peer_certificates = chain.len;
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello from mutual TLS",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/mtls",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            // The client certificate sent when the server requests one.
            .client_identity = .{
                .certificate_chain = &certificate_chain,
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("mTLS {t} {d}: {s} (peer certs={d})\n", .{
        response.protocol(),
        response.status(),
        response.body(),
        task.peer_certificates,
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
