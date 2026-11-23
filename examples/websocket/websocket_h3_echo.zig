//! WebSocket over HTTP/3 (RFC 9220) with a real QUIC/TLS handshake.
//!
//! The extended CONNECT runs on a QUIC request stream, so one HTTP/3
//! connection can carry independent WebSocket sessions without a TCP Upgrade.
//! The server presents the deterministic test identity and the client pins it.

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

    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var server = try netz.websocket.runtime.h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .random = [_]u8{0x61} ** 32,
            .x25519_secret_key = [_]u8{0x62} ** 32,
            .max_crypto_buffer = 64 * 1024,
        } },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.websocket.runtime.h3.Server,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .{ .protocols = &.{"echo.v1"} },
                .fromSeconds(5),
            );
            defer connection.close();
            defer closeIgnoringEvents(&connection, self.allocator);
            var message = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer message.deinit(self.allocator);
            std.debug.print(
                "RFC 9220 server received: {s}\n",
                .{message.payload},
            );
            try connection.sendText(message.payload);
        }
    };

    var task = ServerTask{ .server = &server, .allocator = allocator };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const original_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    var connection = try netz.websocket.runtime.h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .random = [_]u8{0x95} ** 32,
            .x25519_secret_key = [_]u8{0x96} ** 32,
            .max_crypto_buffer = 64 * 1024,
        } },
        .{
            .authority = "localhost",
            .path = "/echo",
            .protocols = &.{"echo.v1"},
        },
    );
    defer connection.close();
    defer closeIgnoringEvents(&connection, allocator);
    std.debug.print(
        "RFC 9220 negotiated ALPN: {s}\n",
        .{connection.negotiatedAlpn()},
    );
    const server_chain = connection.peerCertificates() orelse
        return error.MissingPeerCertificate;
    std.debug.print(
        "RFC 9220 server certificate chain: {d}\n",
        .{server_chain.len},
    );
    try connection.sendMessage(.text, "hello over RFC 9220");
    var reply = try connection.receiveMessageWithTimeout(.fromSeconds(5));
    defer reply.deinit(allocator);
    std.debug.print("RFC 9220 client received: {s}\n", .{reply.payload});
    var close_event = connection.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "bye" },
        .fromSeconds(1),
    ) catch null;
    if (close_event) |*event| event.deinit(allocator);

    server_task.await(io);
    if (task.err) |err| return err;
}

/// Close-handshake events own the surfaced Close or in-flight application
/// frame; release them even when the example does not inspect the result.
fn closeIgnoringEvents(connection: anytype, allocator: std.mem.Allocator) void {
    var event = connection.closeWithTimeout(null, .fromSeconds(1)) catch return;
    event.deinit(allocator);
}
