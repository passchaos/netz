const std = @import("std");
const netz = @import("netz");

const ticket = netz.quic.resumption.ticket;
const iterations: usize = 200_000;

pub fn main(init: std.process.Init) !void {
    var threaded = std.Io.Threaded.init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var keyring = try ticket.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0x41} ** ticket.keyring.key_len,
    });
    defer keyring.deinit();
    try keyring.rotate(.{
        .id = 2,
        .secret = [_]u8{0x42} ** ticket.keyring.key_len,
    });

    const opened = ticket.keyring.Opened{
        .secret = [_]u8{0x77} ** 32,
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
    };
    const identity = try keyring.seal(
        [_]u8{0x51} ** ticket.keyring.nonce_len,
        "benchmark.example:443",
        "h3",
        opened,
    );

    const seal_started = nowNs(io);
    var seal_checksum: u64 = 0;
    for (0..iterations) |i| {
        var nonce = [_]u8{0} ** ticket.keyring.nonce_len;
        std.mem.writeInt(u64, nonce[nonce.len - 8 ..], i, .big);
        const sealed = try keyring.seal(
            nonce,
            "benchmark.example:443",
            "h3",
            opened,
        );
        seal_checksum +%= sealed[sealed.len - 1];
    }
    const seal_ns = nowNs(io) -| seal_started;

    const open_started = nowNs(io);
    var open_checksum: u64 = 0;
    for (0..iterations) |_| {
        const decoded = try keyring.open(
            &identity,
            "benchmark.example:443",
            "h3",
            1500,
        );
        open_checksum +%= decoded.secret[0];
    }
    const open_ns = nowNs(io) -| open_started;

    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writer.print(
        "quic_ticket_keyring iterations={d} sealed_bytes={d}\n" ++
            "  seal: {d} ns/op ({d} checksum)\n" ++
            "  open: {d} ns/op ({d} checksum)\n",
        .{
            iterations,
            ticket.keyring.sealed_len,
            seal_ns / iterations,
            seal_checksum,
            open_ns / iterations,
            open_checksum,
        },
    );
    try std.Io.File.stdout().writeStreamingAll(io, writer.buffered());
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
