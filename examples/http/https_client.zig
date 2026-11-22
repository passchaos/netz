//! HTTPS with an explicit server verifier.
//!
//! Mirrors `curl --cacert` / a pinned-key `reqwest` client: the server runs
//! the HTTP/1.1 TLS listener with the test identity, and the client trusts
//! exactly that ECDSA P-256 public key instead of the system root store.

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

    var server = try netz.http1.runtime.TlsServer.listen(
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
            .limits = .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(5),
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello over verified TLS",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/secure",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    // The pinned key replaces the system trust store for this client. Remove
    // `server_verifier` to use the platform roots (the test certificate is
    // not trusted there, so the handshake would fail).
    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
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
    std.debug.print("HTTPS {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
