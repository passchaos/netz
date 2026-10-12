//! Two-connection TLS 1.2 server used by the OpenSSL RFC 5077 gate.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var keyring = try netz.tls.stream.Tls12TicketKeyring.init(.{
        .id = 23,
        .secret = [_]u8{0x71} ** netz.tls.stream.tls12_ticket_key_len,
    });
    defer keyring.deinit();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(port) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    std.debug.print(
        "netz TLS 1.2 ticket server listening server_io=zio-std-io\n",
        .{},
    );

    for (0..2) |index| {
        const stream = try listener.accept(io);
        var stream_owned = true;
        defer if (stream_owned) stream.close(io);
        const connection = try netz.tls.stream.ServerConnection.init(
            allocator,
            io,
            stream,
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .tls12_cipher_suites = &.{
                    .ecdhe_ecdsa_aes_128_gcm_sha256,
                },
                .protocol_policy = .tls12_only,
                .alpn_protocols = &.{"http/1.1"},
                .tls12_session_tickets = .{
                    .keyring = &keyring,
                    .server_id = "localhost",
                    .lifetime_seconds = 3600,
                },
            },
        );
        stream_owned = false;
        defer connection.deinit();
        if (connection.negotiatedProtocol() != .tls12 or
            connection.wasResumed() != (index == 1))
        {
            return error.InvalidSessionResumption;
        }
        try connection.writeAll("ticket-ok\n");
        std.debug.print(
            "netz accepted OpenSSL TLS 1.2 handshake resumed={}\n",
            .{connection.wasResumed()},
        );
    }
}
