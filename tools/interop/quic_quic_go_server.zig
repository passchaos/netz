//! One-shot QUIC v1 echo server for process-boundary interop with quic-go.

const std = @import("std");
const netz = @import("netz");

const payloads = [_][]const u8{ "hello", "world" };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();

    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .max_datagram_size = 8192 },
    );
    defer endpoint.deinit();
    std.debug.print(
        "netz QUIC interop server listening on {f}\n",
        .{endpoint.address()},
    );

    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var established = try netz.quic.handshake.accept(&endpoint, .{
        .local_connection_id = &server_cid,
        .alpn_protocol = "hq-interop",
        .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        },
        .max_crypto_buffer = 64 * 1024,
        .handshake_recovery = .{
            .initial_pto_ms = 250,
            .max_pto_ms = 2000,
            .max_retries = 4,
            .max_duration_ms = 10_000,
        },
        .initial_one_rtt_config = .{
            .max_datagram_size = 8192,
        },
    });
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, "hq-interop")) {
        return error.InvalidAlpn;
    }

    for (payloads, 0..) |expected, index| {
        const stream_id: u64 = @intCast(index * 4);
        var received: usize = 0;
        while (received < expected.len or
            !established.connection.receivedStreamComplete(stream_id))
        {
            if (established.connection.availableReceivedStream(
                stream_id,
            )) |available| {
                if (available.len != 0) {
                    const end = std.math.add(
                        usize,
                        received,
                        available.len,
                    ) catch return error.UnexpectedRequest;
                    if (end > expected.len or !std.mem.eql(
                        u8,
                        available,
                        expected[received..end],
                    )) return error.UnexpectedRequest;
                    try established.connection.releaseReceivedCapacity(
                        stream_id,
                        available.len,
                    );
                    received = end;
                }
            }
            if (received == expected.len and
                established.connection.receivedStreamComplete(stream_id))
            {
                break;
            }
            var packet = try established.connection
                .receivePacketServicingTimers();
            defer packet.deinit(allocator);
        }
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = 0,
            .data = expected,
            .fin = true,
        } }});
    }

    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    std.debug.print(
        "netz QUIC server interoperated with quic-go: alpn=hq-interop streams=2 bytes=10\n",
        .{},
    );
}
