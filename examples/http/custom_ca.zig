//! HTTPS with a custom CA bundle, mirroring `curl --cacert`.
//!
//! The client trusts exactly the deterministic test certificate through an
//! in-memory `netz.tls.trust.SystemStore`. Unlike `.tls.ca_bundle`, which only
//! covers TCP TLS, a `system_store` is also inherited by the HTTP/3 route, so
//! the same private CA works for H1/H2 and Alt-Svc H3.

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
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const certificate_chain = [_][]const u8{&certificate_der};

    // curl --cacert: start from an empty store and add only this CA. The
    // platform roots are not consulted.
    var store = netz.tls.trust.SystemStore.initEmpty(allocator);
    defer store.deinit();
    const now = std.Io.Timestamp.now(io, .real);
    _ = try store.addCompatibleCertificate(&certificate_der, now.toSeconds());

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
            .alpn_protocols = &.{"http/1.1"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(5),
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
                .body = "hello from a custom CA",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/ca",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        .tls = .{ .system_store = &store },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("custom CA {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
