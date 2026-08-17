const std = @import("std");
const netz = @import("netz");

const transfer_bytes: usize = 4 * 1024 * 1024;
const read_buffer_bytes: usize = 16 * 1024;
const stream_window: u64 = 64 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const io = init.io;
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x42, 0x01, 0x57, 0x54, 0x42, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x42, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x42, 0x04 };

    const payload = try allocator.alloc(u8, transfer_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = payloadByte(index);

    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = smallWindowTransportParameters(),
                .initial_one_rtt_config = .{
                    .stream_receive_window = stream_window,
                },
                .random = [_]u8{0xc3} ** 32,
                .x25519_secret_key = [_]u8{0xc4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.webtransport.runtime.HandshakeServer,
        err: ?anyerror = null,
        received: usize = 0,
        events: usize = 0,
        checksum: u64 = 0,
        io: std.Io,
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
            shared.finished.set(shared.io);
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var buffer: [read_buffer_bytes]u8 = undefined;
            while (true) {
                shared.started.set(shared.io);
                const event = try session.readStream(&buffer);
                switch (event) {
                    .data => |data| {
                        if (data.direction != .bidirectional or
                            data.locally_initiated)
                        {
                            return error.UnexpectedStream;
                        }
                        for (buffer[0..data.bytes]) |byte| {
                            shared.checksum +%= byte;
                        }
                        shared.received += data.bytes;
                        shared.events += 1;
                        if (data.fin) break;
                    },
                    else => return error.UnexpectedStreamEvent,
                }
            }
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.webtransport.runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-stream-bench",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = smallWindowTransportParameters(),
                    .initial_one_rtt_config = .{
                        .stream_receive_window = stream_window,
                    },
                    .server_name = "localhost",
                    .random = [_]u8{0xc1} ** 32,
                    .x25519_secret_key = [_]u8{0xc2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    shared.started.waitUncancelable(io);
    const stream_id = try client.openBidirectionalStream();
    const started_ns = nowNs(io);
    var write_calls: usize = 0;
    var written: usize = 0;
    while (written < payload.len) {
        written += try client.writeStream(
            stream_id,
            payload[written..],
        );
        write_calls += 1;
    }
    try client.finishStream(stream_id);
    shared.finished.waitUncancelable(io);
    const elapsed_ns = nowNs(io) -| started_ns;
    thread.join();
    if (shared.err) |err| return err;
    if (shared.received != payload.len) return error.IncompleteTransfer;

    const mib_per_second = if (elapsed_ns == 0)
        0
    else
        (@as(u64, payload.len) *| std.time.ns_per_s) /
            (elapsed_ns *| 1024 * 1024);
    std.debug.print(
        \\WebTransport incremental stream benchmark
        \\  transfer bytes: {d}
        \\  receive window: {d}
        \\  caller buffer: {d}
        \\  partial writes: {d}
        \\  read events: {d}
        \\  checksum: {d}
        \\  elapsed ns: {d}
        \\  throughput MiB/s: {d}
        \\
    , .{
        payload.len,
        stream_window,
        read_buffer_bytes,
        write_calls,
        shared.events,
        shared.checksum,
        elapsed_ns,
        mib_per_second,
    });
}

fn smallWindowTransportParameters() netz.quic.TransportParameters {
    var parameters = netz.quic.practical_transport_parameters;
    parameters.initial_max_data = stream_window * 2;
    parameters.initial_max_stream_data_bidi_local = stream_window;
    parameters.initial_max_stream_data_bidi_remote = stream_window;
    parameters.initial_max_stream_data_uni = stream_window;
    return parameters;
}

fn payloadByte(index: usize) u8 {
    return @truncate((index *% 131) ^ (index >> 3));
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}
