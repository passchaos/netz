const std = @import("std");
const owner = @import("proxy/hysteria/shared/server.zig");
const Pump = owner.Pump;
const Connection = owner.Connection;
const byte_bucket = @import("proxy/internal/byte_bucket.zig");
const relay_mod = @import("proxy/internal/relay_queue.zig");
const Relay = relay_mod.Relay;
fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

test "audit review backpressured relay retains the complete FIFO suffix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pump: Pump = undefined;
    pump.io = io;
    pump.allocator = std.testing.allocator;
    var conn: Connection = undefined;
    conn.pump = &pump;
    // This rate cap forces the production sender to return backpressure
    // before it accesses the QUIC endpoint, without mocking the drain loop.
    conn.send_bucket = byte_bucket.ByteBucket.init(1, nowNs(io));
    var relay: Relay = undefined;
    relay.pending_out = null;
    relay.outbound = .init(&relay.outbound_storage);
    var payloads: [3][32]u8 = @splat(@splat(0x5a));
    for (&payloads) |*payload| try relay.outbound.putOne(io, .{ .data = payload });
    conn.flushRelayOutbound(&relay);
    var remainder: [8]relay_mod.Outbound = undefined;
    const queued = try relay.outbound.get(io, &remainder, 0);
    const retained = queued + @as(usize, @intFromBool(relay.pending_out != null));
    std.debug.print("audit relay input=3 retained={d} orphaned={d}\n", .{ retained, 3 - retained });
    try std.testing.expectEqual(@as(usize, 3), retained);
}

test "audit review fractional rate refill preserves elapsed credit" {
    var bucket = byte_bucket.ByteBucket.init(1, 0);
    try std.testing.expect(bucket.tryConsume(1, 0));
    var sent: usize = 0;
    for (1..1001) |millis| {
        if (bucket.tryConsume(1, @intCast(millis * std.time.ns_per_ms))) sent += 1;
    }
    std.debug.print("audit limiter rate=1 byte/s polls=1000 elapsed=1s sent={d} tokens={d}\n", .{ sent, bucket.tokens });
    try std.testing.expectEqual(@as(usize, 1), sent);
}

test "audit overflow advertised byte rate supports a refill" {
    var bucket = byte_bucket.ByteBucket.init(std.math.maxInt(u64), 0);
    _ = bucket.tryConsume(1, 2);
}

test "audit boundary raw QUIC rejects a default relay sized chunk" {
    const quic = @import("quic/mod.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** 32);
    var conn = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .max_datagram_size = 4096,
        .enable_pacing = false,
    });
    defer conn.deinit();
    var bytes: [16 * 1024]u8 = @splat(0x5a);
    const result = conn.trySend(&.{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = &bytes, .fin = false } }});
    result catch |err| std.debug.print("audit raw relay payload=16384 datagram_limit=4096 error={s}\n", .{@errorName(err)});
    try std.testing.expectError(error.DatagramTooLarge, result);
}
