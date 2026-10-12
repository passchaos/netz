const std = @import("std");
const netz = @import("netz");
const benchmark = @import("quic_datagram_bench.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4 or !std.mem.eql(u8, args[1], "bench-server")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    if (port == 0) return error.InvalidArgument;
    const role_pair = args[3];
    if (!std.mem.eql(u8, role_pair, "quinn-client+netz-server") and
        !std.mem.eql(u8, role_pair, "netz-client+netz-server"))
    {
        return error.InvalidArgument;
    }
    const config = try benchmark.Config.parse(args[4..]);
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
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_datagram_size = benchmark.mtu,
            .enable_gso_send = config.window > 1,
            .enable_gro_receive = config.window > 1,
        },
    );
    defer endpoint.deinit();
    std.debug.print("NETZ_QUIC_DATAGRAM_BENCH_PORT={d}\n", .{
        endpoint.address().ip4.port,
    });
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &local_cid);
    var established = try netz.quic.handshake.acceptWithTimeout(
        &endpoint,
        .{
            .local_connection_id = &local_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .alpn_protocol = benchmark.alpn,
            .local_transport_parameters = config.transportParameters(),
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .max_crypto_buffer = 64 * 1024,
            .initial_one_rtt_config = config.oneRttConfig(),
        },
        config.timeout(),
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, benchmark.alpn) or
        !established.connection.datagramsEnabled())
    {
        return error.InvalidNegotiation;
    }
    benchmark.printConfig(
        "netz",
        role_pair,
        "server",
        config,
        established.connection.maxDatagramPayloadSize().?,
    );
    const result = try benchmark.runServer(&established.connection, config);
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    try established.connection.closeApplication(
        59,
        "datagram benchmark complete",
    );
    inline for (0..2) |_| {
        try std.Io.sleep(io, .fromMilliseconds(50), .awake);
        established.connection.resendClose() catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
    }
    benchmark.printServerComplete("netz", role_pair, config, result);
}
