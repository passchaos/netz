//! `prefer_http3` with the unified client against a local QUIC/TLS origin.
//!
//! Mirrors `curl --http3` policy selection: the unified client probes H3
//! first, authenticates the origin with a pinned key, and reports the
//! negotiated protocol. No TCP listener exists here, so a failed H3 probe has
//! no H2/H1 fallback.

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

    const server_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 512,
            },
        },
    );
    defer server.deinit();

    const ServerTask = struct {
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
                .body = "hello from prefer_http3",
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/h3",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    const original_dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    const client_cid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };
    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .prefer_http3,
        .http3 = .{
            // The probe budget only bounds H3 feasibility before TCP
            // fallback; keep it generous for loaded hosts.
            .preference_timeout = .fromSeconds(2),
            .handshake = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .max_crypto_buffer = 64 * 1024,
            } },
            .limits = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 16,
            } },
        },
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("prefer_http3 {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
