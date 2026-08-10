const std = @import("std");
const netz = @import("netz");

const iterations: usize = 10_000;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.webtransport.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    });
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.Server,
        err: ?anyerror = null,
        handled: usize = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept();
            defer accepted.deinit(shared.server.h3.quic_server.endpoint.allocator);

            while (shared.handled < iterations) : (shared.handled += 1) {
                var datagram = try shared.server.receiveDatagram();
                defer datagram.deinit(shared.server.h3.quic_server.endpoint.allocator);
                if (datagram.datagram.session_id.value != accepted.session_id.value) {
                    return error.UnexpectedSessionId;
                }
                try shared.server.sendDatagram(
                    datagram.quic_datagram.from,
                    accepted.session_id,
                    datagram.datagram.payload,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.webtransport.runtime.ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/bench-wt",
            .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        },
    );
    defer client.deinit();

    const payload = "webtransport bench datagram";
    const start = nowNs(io);
    var checksum: usize = 0;
    for (0..iterations) |_| {
        try client.sendDatagram(payload);
        var response = try client.receiveDatagram();
        defer response.deinit(allocator);
        if (response.datagram.session_id.value != client.session_id.value) {
            return error.UnexpectedSessionId;
        }
        checksum +%= response.datagram.payload.len;
        checksum +%= response.datagram.payload[0];
    }
    const elapsed = nowNs(io) -| start;
    const datagrams = iterations * 2;
    const datagrams_per_second = if (elapsed == 0)
        0
    else
        (@as(u64, datagrams) *| std.time.ns_per_s) / elapsed;

    thread.join();
    if (shared.err) |err| return err;

    std.debug.print(
        \\WebTransport datagram runtime benchmark
        \\  iterations: {d}
        \\  datagrams: {d}
        \\  payload bytes: {d}
        \\  checksum: {d}
        \\  ns/roundtrip: {d}
        \\  ns/datagram: {d}
        \\  datagrams/s: {d}
        \\
    , .{
        iterations,
        datagrams,
        payload.len,
        checksum,
        elapsed / iterations,
        elapsed / datagrams,
        datagrams_per_second,
    });
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
