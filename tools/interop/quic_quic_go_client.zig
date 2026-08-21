//! Certificate-verified QUIC v1 stream interop client for the quic-go fixture
//! maintained in the audited local quicz checkout.

const std = @import("std");
const netz = @import("netz");

const payloads = [_][]const u8{ "hello", "world" };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };

    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 8192 },
    );
    defer endpoint.deinit();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);

    var established = try netz.quic.handshake.connect(
        &endpoint,
        .{ .ip4 = .loopback(port) },
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .alpn_protocols = &.{"hq-interop"},
            .server_auth = verifier.clientVerifier(),
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
        },
    );
    defer established.deinit();
    if (!std.mem.eql(u8, established.alpn, "hq-interop")) {
        return error.InvalidAlpn;
    }

    var stream_ids: [payloads.len]u64 = undefined;
    for (payloads, 0..) |payload, index| {
        stream_ids[index] = try established.connection.openStream();
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = stream_ids[index],
            .offset = 0,
            .data = payload,
            .fin = true,
        } }});
    }

    var offsets = [_]usize{0} ** payloads.len;
    var complete = [_]bool{false} ** payloads.len;
    while (!std.mem.allEqual(bool, &complete, true)) {
        var packet = try established.connection
            .receivePacketServicingTimers();
        defer packet.deinit(allocator);
        inline for (stream_ids, payloads, 0..) |stream_id, payload, index| {
            if (established.connection.availableReceivedStream(
                stream_id,
            )) |available| {
                if (available.len != 0) {
                    const end = std.math.add(
                        usize,
                        offsets[index],
                        available.len,
                    ) catch return error.UnexpectedEcho;
                    if (end > payload.len or !std.mem.eql(
                        u8,
                        available,
                        payload[offsets[index]..end],
                    )) return error.UnexpectedEcho;
                    try established.connection.releaseReceivedCapacity(
                        stream_id,
                        available.len,
                    );
                    offsets[index] = end;
                }
            }
            complete[index] = offsets[index] == payload.len and
                established.connection.receivedStreamComplete(stream_id);
        }
    }

    try established.connection.closeApplication(
        0,
        "netz interop complete",
    );
    std.debug.print(
        "netz QUIC client interoperated with quic-go: verified=true alpn=hq-interop streams=2 bytes=10\n",
        .{},
    );
}
