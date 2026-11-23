//! One TLS port serving both HTTP/2 and HTTP/1.1 through ALPN.
//!
//! Mirrors how production TLS servers (nginx `listen 443 ssl http2`, Hyper's
//! auto mode, Go's `http.Server`) share one listener: `netz.tls.alpn_server`
//! completes the handshake and reports the selected protocol, then the
//! application hands the same TLS connection to the HTTP/2 or HTTP/1.1
//! runtime with `adoptNegotiatedTlsServer`.
//!
//! The two clients below pin the test key and request the same origin with
//! `.http2_only` and `.http1_only`, so both branches are exercised on one
//! port.

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

    var listener = try netz.tls.alpn_server.Server.listen(allocator, io, .{
        .address = .{ .ip4 = .loopback(0) },
        .tls = .{
            .identity = .{
                .certificate_chain = &certificate_chain,
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            // Server preference order. The client's list decides the result;
            // a client that offers only one of these still connects.
            .alpn_protocols = &.{ "h2", "http/1.1" },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .handshake_timeout = .fromSeconds(5),
        },
    });
    defer listener.deinit();

    const ServerTask = struct {
        listener: *netz.tls.alpn_server.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            // Two connections, one per client below, in request order.
            for (0..2) |_| {
                const accepted = try self.listener.acceptWithTimeout(
                    .fromSeconds(10),
                );
                const alpn = accepted.tls.negotiatedAlpn() orelse {
                    return error.MissingAlpn;
                };
                if (std.mem.eql(u8, alpn, "h2")) {
                    try self.serveHttp2(accepted);
                } else if (std.mem.eql(u8, alpn, "http/1.1")) {
                    try self.serveHttp1(accepted);
                } else {
                    return error.UnexpectedAlpn;
                }
            }
        }

        fn serveHttp2(
            self: *@This(),
            accepted: netz.tls.alpn_server.Accepted,
        ) !void {
            const connection_allocator = self.listener.allocator;
            var connection = try netz.http2.runtime.adoptNegotiatedTlsServer(
                connection_allocator,
                self.listener.io,
                accepted.stream,
                accepted.tls,
                .{ .max_body_bytes = 4096 },
            );
            defer connection.close();
            var request = try connection.readRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(connection_allocator);
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello over HTTP/2 ALPN",
            });
        }

        fn serveHttp1(
            self: *@This(),
            accepted: netz.tls.alpn_server.Accepted,
        ) !void {
            const connection_allocator = self.listener.allocator;
            var connection = try netz.http1.runtime.adoptNegotiatedTlsServer(
                connection_allocator,
                self.listener.io,
                accepted.stream,
                accepted.tls,
                .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
            );
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(connection_allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello over HTTP/1.1 ALPN",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .listener = &listener };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/alpn",
        .{listener.address().ip4.port},
    );
    defer allocator.free(uri);

    try fetch(allocator, io, uri, .http2_only, public_key);
    try fetch(allocator, io, uri, .http1_only, public_key);

    server_task.await(io);
    if (task.err) |err| return err;
}

fn fetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    policy: netz.http.ProtocolPolicy,
    public_key: anytype,
) !void {
    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = policy,
        .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("ALPN {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });
}
