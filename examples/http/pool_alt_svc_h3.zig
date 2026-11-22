//! Alt-Svc HTTP/3 upgrade through the unified pool.
//!
//! Mirrors a real deployment: the first request is ordinary H2 over TLS and
//! the response advertises `alt-svc: h3=":port"`. The pool caches that
//! alternative, so the second request to the same origin uses QUIC/H3 without
//! another probe. `.http3 = .{}` uses the default H3 limits, generated
//! connection IDs, and trust inherited from `client.tls`.

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
    const identity: @FieldType(
        netz.http2.runtime.TlsListenOptions,
        "identity",
    ) = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };

    const server_cid = [_]u8{ 0x70, 0x71, 0x72, 0x73 };
    var h3_server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = identity,
        } },
    );
    defer h3_server.deinit();

    const alt_svc = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{h3_server.address().ip4.port},
    );
    defer allocator.free(alt_svc);

    var tcp_server = try netz.http2.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = identity,
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(5),
        },
    );
    defer tcp_server.deinit();

    const TcpTask = struct {
        server: *netz.http2.runtime.TlsServer,
        alt_svc: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{
                    .name = "alt-svc",
                    .value = self.alt_svc,
                }},
                .body = "tcp discovery",
                .request_method = request.method,
            });
        }
    };

    const H3Task = struct {
        server: *netz.http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello over Alt-Svc HTTP/3",
            });
        }
    };

    var tcp_task = TcpTask{ .server = &tcp_server, .alt_svc = alt_svc };
    var tcp_future = io.async(TcpTask.run, .{&tcp_task});
    defer tcp_future.cancel(io);
    var h3_task = H3Task{ .server = &h3_server };
    var h3_future = io.async(H3Task.run, .{&h3_task});
    defer h3_future.cancel(io);

    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        } },
        // Defaults: inherited trust, generated connection IDs, 250 ms probe
        // and idempotent-method TCP replay on H3 setup failure.
        .http3 = .{},
        .max_connections = 2,
    });
    defer pool.deinit();

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/alt-svc",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(uri);

    var first = try pool.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer first.deinit();
    std.debug.print("first {t} {d}: {s}\n", .{
        first.protocol(),
        first.status(),
        first.body(),
    });

    var second = try pool.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer second.deinit();
    std.debug.print("second {t} {d}: {s}\n", .{
        second.protocol(),
        second.status(),
        second.body(),
    });

    tcp_future.await(io);
    if (tcp_task.err) |err| return err;
    h3_future.await(io);
    if (h3_task.err) |err| return err;
}
