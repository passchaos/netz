const std = @import("std");
const netz = @import("netz");
const benchmark = @import("quic_datagram_bench.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 5 or !std.mem.eql(u8, args[1], "bench-client")) {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[3])) {
        return error.InvalidArgument;
    }
    const role_pair = args[4];
    if (!std.mem.eql(u8, role_pair, "netz-client+quinn-server") and
        !std.mem.eql(u8, role_pair, "netz-client+netz-server"))
    {
        return error.InvalidArgument;
    }
    const config = try benchmark.Config.parse(args[5..]);
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const now = std.Io.Clock.real.now(io);
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.addCertsFromFilePathAbsolute(allocator, io, now, args[3]);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &bundle,
        .now_seconds = now.toSeconds(),
    };
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = benchmark.mtu,
            .enable_gso_send = config.window > 1,
            .enable_gro_receive = config.window > 1,
        },
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &local_cid);
    var established = try netz.quic.handshake.connectWithTimeout(
        &endpoint,
        .{ .ip4 = .loopback(port) },
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &local_cid,
            .version = .version_1,
            .available_versions = &.{.version_1},
            .server_name = "localhost",
            .alpn_protocols = &.{benchmark.alpn},
            .key_exchange_groups = &.{.x25519},
            .server_auth = netz.quic.tls.auth.ClientVerifier.fromTrustVerifier(verifier.clientVerifier()),
            .local_transport_parameters = config.transportParameters(),
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
        "client",
        config,
        established.connection.maxDatagramPayloadSize().?,
    );
    _ = try benchmark.runClient(
        allocator,
        io,
        &established.connection,
        config,
        "netz",
        role_pair,
    );
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = config.timeout(),
    });
    try benchmark.waitForBenchmarkClose(&established.connection, deadline);
}
