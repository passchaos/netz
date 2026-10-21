const std = @import("std");
const netz = @import("netz");
const benchmark = @import("webtransport_wtransport_bench.zig");
const churn = @import("webtransport_wtransport_churn_client.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

const client_datagram = "wtransport datagram";
const server_datagram = "netz datagram";
const client_bidi = "wtransport bidi";
const server_bidi = "netz bidi";
const client_uni = "wtransport uni";
const server_uni = "netz uni";
const client_reset = "wtransport reset";
const server_stop = "netz stop";
const reuse_request = "after cancel";
const reuse_response = "session reused";
const reset_ready = "reset ready";
const cancel_done = "cancel done";
const close_ready = "close ready";

const StopLoss = struct {
    armed: bool = false,
    dropped: usize = 0,

    fn shouldDrop(context: *anyopaque, _: []const u8) bool {
        const self: *StopLoss = @ptrCast(@alignCast(context));
        if (!self.armed or self.dropped != 0) return false;
        self.dropped = 1;
        return true;
    }
};

fn receiveExpectedStream(
    session: anytype,
    buffer: []u8,
    expected_stream_id: ?u62,
    direction: netz.webtransport.StreamDirection,
    locally_initiated: bool,
    expected: []const u8,
    expect_fin: bool,
) !u62 {
    var stream_id = expected_stream_id;
    var received: usize = 0;
    while (true) {
        const event = try session.readStream(buffer);
        switch (event) {
            .data => |data| {
                if (stream_id) |id| {
                    if (data.stream_id != id) return error.UnexpectedStream;
                } else {
                    stream_id = data.stream_id;
                }
                if (data.direction != direction or
                    data.locally_initiated != locally_initiated or
                    data.bytes > expected.len - received or
                    !std.mem.eql(
                        u8,
                        buffer[0..data.bytes],
                        expected[received..][0..data.bytes],
                    ))
                {
                    return error.UnexpectedStream;
                }
                received += data.bytes;
                if (data.fin) {
                    if (!expect_fin or received != expected.len) {
                        return error.UnexpectedStream;
                    }
                    return stream_id.?;
                }
                if (!expect_fin and received == expected.len) {
                    return stream_id.?;
                }
            },
            .reset, .stopped => return error.UnexpectedStream,
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "churn-client")) {
        return churn.run(init, args[2..]);
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "bench-client")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const socks5_port: ?u16 = if (args.len == 3) blk: {
        if (!std.mem.startsWith(u8, args[2], "--socks5-port=")) {
            return error.InvalidArgument;
        }
        const value = try std.fmt.parseInt(
            u16,
            args[2]["--socks5-port=".len..],
            10,
        );
        if (value == 0) return error.InvalidArgument;
        break :blk value;
    } else null;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const original_dcid = [_]u8{ 0x77, 0x74, 0x63, 0x6c, 0x69, 0x00, 0x00, 0x01 };
    const client_cid = [_]u8{ 0x77, 0x74, 0x63, 0x6c, 0x69, 0x00, 0x00, 0x02 };
    var stop_loss = StopLoss{};
    const rejected_original_dcid =
        [_]u8{ 0x77, 0x74, 0x72, 0x65, 0x6a, 0x00, 0x00, 0x01 };
    const rejected_client_cid =
        [_]u8{ 0x77, 0x74, 0x72, 0x65, 0x6a, 0x00, 0x00, 0x02 };
    if (socks5_port) |proxy_port| {
        const rejected_uri = try std.fmt.allocPrint(
            allocator,
            "https://localhost:{d}/rejected",
            .{port},
        );
        defer allocator.free(rejected_uri);
        try std.testing.expectError(
            error.SessionRejected,
            netz.webtransport.runtime.HandshakeClientSession.connectUri(
                allocator,
                io,
                .{ .ip4 = .loopback(0) },
                rejected_uri,
                .{
                    .h3 = .{ .handshake = .{
                        .original_destination_connection_id = &rejected_original_dcid,
                        .local_connection_id = &rejected_client_cid,
                        .server_name = "localhost",
                        .max_crypto_buffer = 64 * 1024,
                    } },
                    .socks5_proxy = socksProxy(proxy_port),
                },
            ),
        );
    } else try std.testing.expectError(
        error.SessionRejected,
        netz.webtransport.runtime.HandshakeClientSession.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(port) },
            .{
                .authority = "127.0.0.1",
                .path = "/rejected",
                .h3 = .{ .handshake = .{
                    .original_destination_connection_id = &rejected_original_dcid,
                    .local_connection_id = &rejected_client_cid,
                    .server_name = "127.0.0.1",
                    .max_crypto_buffer = 64 * 1024,
                } },
            },
        ),
    );

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://{s}:{d}/interop",
        .{ if (socks5_port != null) "localhost" else "127.0.0.1", port },
    );
    defer allocator.free(uri);
    var client = try netz.webtransport.runtime.HandshakeClientSession.connectUri(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .headers = &.{
                .{
                    .name = "authorization",
                    .value = "Bearer netz-interop",
                },
                .{
                    .name = "user-agent",
                    .value = "netz-wtransport-client",
                },
            },
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 16,
                .send_interceptor = .{
                    .context = &stop_loss,
                    .should_drop = StopLoss.shouldDrop,
                },
            } } },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .max_crypto_buffer = 64 * 1024,
                },
                .session = .{
                    .max_stream_buffer = 64 * 1024,
                    .max_stream_frame_data = 1200,
                },
            },
            .socks5_proxy = if (socks5_port) |proxy_port|
                socksProxy(proxy_port)
            else
                null,
        },
    );
    defer client.deinit();
    if (!std.mem.eql(
        u8,
        client.responseHeader("x-wtransport-admission") orelse
            return error.UnexpectedHeader,
        "accepted",
    )) return error.UnexpectedHeader;
    const max_datagram_size = client.maxDatagramSize();
    if (max_datagram_size == 0) return error.UnexpectedDatagramLimit;
    const oversized_datagram = try allocator.alloc(
        u8,
        max_datagram_size + 1,
    );
    defer allocator.free(oversized_datagram);
    @memset(oversized_datagram, 0xa5);
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagram(oversized_datagram),
    );

    try client.sendDatagram(client_datagram);
    var datagram = try client.receiveDatagram();
    defer datagram.deinit(allocator);
    if (!std.mem.eql(u8, datagram.datagram.payload, server_datagram)) {
        return error.UnexpectedDatagram;
    }

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, client_bidi, true);
    var read_buffer: [64]u8 = undefined;
    _ = try receiveExpectedStream(
        &client,
        &read_buffer,
        bidi,
        .bidirectional,
        true,
        server_bidi,
        true,
    );

    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, client_uni, true);
    _ = try receiveExpectedStream(
        &client,
        &read_buffer,
        null,
        .unidirectional,
        false,
        server_uni,
        true,
    );

    const reset_stream = try client.openUnidirectionalStream();
    try client.sendStream(reset_stream, client_reset, false);
    var reset_signal = try client.receiveDatagram();
    defer reset_signal.deinit(allocator);
    if (!std.mem.eql(u8, reset_signal.datagram.payload, reset_ready)) {
        return error.UnexpectedResetReady;
    }
    try client.resetStream(reset_stream, 73);

    const stop_stream = try receiveExpectedStream(
        &client,
        &read_buffer,
        null,
        .unidirectional,
        false,
        server_stop,
        false,
    );
    // The sibling exists before cancellation and its response is withheld by
    // the peer until STOP_SENDING arrives. Drop the first control datagram so
    // receiveDatagram must service QUIC recovery instead of sleeping forever.
    const reused_stream = try client.openBidirectionalStream();
    try client.sendStream(reused_stream, reuse_request, true);
    stop_loss.armed = true;
    try client.stopStream(stop_stream, 74);
    var cancel_signal = try client.receiveDatagram();
    defer cancel_signal.deinit(allocator);
    if (!std.mem.eql(u8, cancel_signal.datagram.payload, cancel_done) or
        stop_loss.dropped != 1)
    {
        return error.UnexpectedCancelDone;
    }

    _ = try receiveExpectedStream(
        &client,
        &read_buffer,
        reused_stream,
        .bidirectional,
        true,
        reuse_response,
        true,
    );

    try client.sendDatagram(close_ready);
    const close = try client.receivePeerConnectionClose();
    switch (close) {
        .application => |application| {
            if (application.error_code != 0 or
                !std.mem.eql(
                    u8,
                    application.reason_phrase,
                    "interop complete",
                ))
            {
                return error.UnexpectedConnectionClose;
            }
        },
        .transport => return error.UnexpectedConnectionClose,
    }
    std.debug.print(
        "netz WebTransport client interop passed: CONNECT uri=true rejection=404 admission-headers=true DATAGRAM max_datagram_size={d} oversized_rejected=true bidi uni reset=73 stop=74 dropped_stop_sending=1 concurrent_sibling=true reuse=true peer-close client_io=zio-std-io server_io=wtransport-quinn-tokio\n",
        .{max_datagram_size},
    );
    if (socks5_port != null) {
        std.debug.print(
            "netz WebTransport SOCKS5 route passed: udp_associations=2 " ++
                "remote_dns=true rejection=404 datagram=true streams=true " ++
                "peer_close=true\n",
            .{},
        );
    }
}

fn socksProxy(port: u16) netz.http3.socks5_runtime.Proxy {
    return .{
        .host = "127.0.0.1",
        .port = port,
        .options = .{
            .credentials = .{
                .username = "user",
                .password = "secret",
            },
            .allow_no_authentication = false,
        },
    };
}

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len == 0) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    if (port == 0) return error.InvalidArgument;
    var stats = false;
    var traffic = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else if (std.mem.eql(u8, arg, "--traffic") and !traffic) {
            traffic = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    if (stats and traffic) return error.InvalidArgument;
    const config = try benchmark.Config.parse(config_args.items);
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    try runBenchmarkWithAllocator(allocator, port, config, traffic);
    if (stats) {
        const snapshot = counting.snapshot();
        if (snapshot.current_bytes != 0) return error.MemoryLeak;
        benchmark.printNetzMemory(
            "netz-client+wtransport-server",
            "client",
            config,
            snapshot,
        );
    }
}

fn runBenchmarkWithAllocator(
    allocator: std.mem.Allocator,
    port: u16,
    config: benchmark.Config,
    traffic: bool,
) !void {
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const original_dcid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x62, 0x00, 0x00, 0x01 };
    const client_cid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x62, 0x00, 0x00, 0x02 };
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/benchmark",
        .{port},
    );
    defer allocator.free(uri);
    var client = try netz.webtransport.runtime.HandshakeClientSession.connectUri(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .headers = &.{.{
                .name = "user-agent",
                .value = "netz-benchmark",
            }},
            .limits = .{
                .http3 = .{ .quic = .{
                    .max_datagram_size = benchmark.max_datagram_size,
                    .max_frames_per_datagram = 256,
                    .enable_gso_send = false,
                    .enable_gro_receive = false,
                    .socket_traffic_counters = if (traffic)
                        &socket_traffic
                    else
                        null,
                } },
                .max_session_streams = try config.sessionStreams(),
            },
            .h3 = .{
                .connect_timeout = config.timeout(),
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = try config.transportParameters(),
                    .initial_one_rtt_config = try config.oneRttConfig(),
                    .max_crypto_buffer = 64 * 1024,
                },
                .session = try config.sessionOptions(),
            },
        },
    );
    defer client.deinit();
    const datagram_limit = try benchmark.validateDatagramLimit(&client, config);
    try benchmark.printConfig(
        "netz",
        "netz-client+wtransport-server",
        "client",
        config,
        datagram_limit,
    );
    const control = try benchmark.openControlClient(&client, config);
    try benchmark.runClient(allocator, io, &client, control, config);
    try benchmark.sendCloseReady(&client, control, config);
    try benchmark.receiveCloseAck(&client, control, config);
    try benchmark.finishControlAndReceivePeerFin(&client, control, config);
    if (traffic) {
        benchmark.printNetzTraffic(
            "netz-client+wtransport-server",
            "client",
            config,
            socket_traffic.stats(),
        );
    }
}
