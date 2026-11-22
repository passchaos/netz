//! WebTransport DATAGRAM echo.
//!
//! Complements the stream example: the session sends unreliable DATAGRAMs in
//! both directions, once with an owned receive and once into caller storage.

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

    const original_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    const server_cid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90 };

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .random = [_]u8{0x91} ** 32,
            .x25519_secret_key = [_]u8{0x92} ** 32,
        } },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.webtransport.runtime.HandshakeServer,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            for (0..2) |_| {
                var received = try session.receiveDatagramWithTimeout(
                    .fromSeconds(5),
                );
                defer received.deinit(self.allocator);
                try session.sendDatagram(received.datagram.payload);
            }
        }
    };

    var task = ServerTask{ .server = &server, .allocator = allocator };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    var client = try netz.webtransport.runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-datagram",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .random = [_]u8{0x93} ** 32,
                .x25519_secret_key = [_]u8{0x94} ** 32,
            } },
        },
    );
    defer client.deinit();

    try client.sendDatagram("hello datagram");
    var owned = try client.receiveDatagramWithTimeout(.fromSeconds(5));
    defer owned.deinit(allocator);
    std.debug.print("DATAGRAM echo (owned): {s}\n", .{
        owned.datagram.payload,
    });

    try client.sendDatagram("caller buffer");
    var buffer: [64]u8 = undefined;
    const into = try client.receiveDatagramIntoWithTimeout(
        &buffer,
        .fromSeconds(5),
    );
    std.debug.print("DATAGRAM echo (into): {s}\n", .{into});

    server_task.await(io);
    if (task.err) |err| return err;
}
