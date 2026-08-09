const std = @import("std");
const netz = @import("netz");

const iterations: usize = 1_000_000;

pub fn main(init: std.process.Init) !void {
    const key = [16]u8{
        0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
        0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
    };
    const config = netz.quic.quic_lb.Config{
        .config_rotation = 2,
        .server_id_len = 8,
        .nonce_len = 9,
        .key = key,
    };
    const server_id = [_]u8{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f };
    const nonce = [_]u8{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5, 0x5d };
    var cid_storage: [netz.quic.quic_lb.max_connection_id_len]u8 = undefined;
    const cid = try netz.quic.quic_lb.encode(
        config,
        &server_id,
        &nonce,
        0,
        &cid_storage,
    );
    var decoded: [netz.quic.quic_lb.max_server_id_len]u8 = undefined;

    var checksum: usize = 0;
    const started = nowNs(init.io);
    for (0..iterations) |_| {
        const routed = try netz.quic.quic_lb.decodeServerId(
            config,
            cid,
            &decoded,
        );
        checksum +%= routed[0];
    }
    const elapsed = nowNs(init.io) - started;
    std.debug.print(
        \\QUIC-LB encrypted routing benchmark
        \\  iterations: {d}, CID bytes: {d}, SID bytes: {d}
        \\  ns/route: {d}
        \\  checksum: {d}
        \\
    , .{
        iterations,
        cid.len,
        server_id.len,
        elapsed / iterations,
        checksum,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
