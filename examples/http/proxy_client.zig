//! HTTPS through an HTTP/1.1 CONNECT proxy.
//!
//! Mirrors `curl -x http://proxy https://origin` / the `reqwest` proxy
//! example: a local CONNECT proxy tunnels to a local TLS origin, and the
//! unified client authenticates the origin with a pinned key while sending
//! proxy credentials only on CONNECT.

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

    var origin = try netz.http1.runtime.TlsServer.listen(
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
    defer origin.deinit();

    const OriginTask = struct {
        origin: *netz.http1.runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.origin.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.origin.allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello through the CONNECT proxy",
                .request_method = request.request.method,
            });
        }
    };

    var origin_task = OriginTask{ .origin = &origin };
    var origin_thread = try std.Thread.spawn(
        .{},
        OriginTask.run,
        .{&origin_task},
    );
    var origin_joined = false;
    defer if (!origin_joined) origin_thread.join();

    // Example-only policy: anonymous access and an allow-all ACL. Production
    // proxies should configure explicit credentials and destination rules.
    var proxy = try netz.proxy.http_connect.server.Server.init(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .auth = .{ .allow_anonymous = true },
            .acl = .{ .default_action = .allow },
        },
    );
    defer proxy.deinit();
    const ProxyTask = struct {
        proxy: *netz.proxy.http_connect.server.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.proxy.serve() catch |err| {
                self.err = err;
            };
        }
    };
    var proxy_task = ProxyTask{ .proxy = &proxy };
    const proxy_thread = try std.Thread.spawn(
        .{},
        ProxyTask.run,
        .{&proxy_task},
    );
    var proxy_joined = false;
    defer if (!proxy_joined) {
        proxy.requestStop();
        // Unblock the blocking accept so the serve loop observes the stop.
        if (proxy.listener.socket.address.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
        } else |_| {}
        proxy_thread.join();
    };

    const proxy_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{proxy.listener.socket.address.ip4.port},
    );
    defer allocator.free(proxy_uri);
    const origin_uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/via-proxy",
        .{origin.address().ip4.port},
    );
    defer allocator.free(origin_uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        .http_proxy = .{ .uri = proxy_uri },
        .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        origin_uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("proxied HTTPS {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    origin_thread.join();
    origin_joined = true;
    if (origin_task.err) |err| return err;

    proxy.requestStop();
    var unblock = try proxy.listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    unblock.close(io);
    proxy_thread.join();
    proxy_joined = true;
    if (proxy_task.err) |err| return err;
}
