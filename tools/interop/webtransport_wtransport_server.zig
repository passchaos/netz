const std = @import("std");
const netz = @import("netz");
const benchmark = @import("webtransport_wtransport_bench.zig");
const browser_reset = @import("webtransport_browser_reset.zig");
const churn = @import("webtransport_wtransport_churn_server.zig");
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
const reset_flush = "reset flush";
const stop_flush = "stop flush";
const cancel_done = "cancel done";
const close_ready = "close ready";

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

fn receiveExpectedResetStream(
    session: anytype,
    buffer: []u8,
    expected: []const u8,
    application_code: u32,
    association_prefix_len: usize,
) !u62 {
    var validator = browser_reset.Validator{
        .expected = expected,
        .application_code = application_code,
        .association_prefix_len = association_prefix_len,
    };
    while (true) {
        const event = try session.readStream(buffer);
        switch (event) {
            .data => |data| {
                try validator.observeData(
                    data.stream_id,
                    data.direction,
                    data.locally_initiated,
                    data.fin,
                    buffer[0..data.bytes],
                );
            },
            .reset => |reset| {
                return validator.observeReset(
                    reset.stream_id,
                    reset.direction,
                    reset.locally_initiated,
                    reset.error_info.application_code,
                    reset.final_size,
                );
            },
            .stopped => return error.UnexpectedResetStream,
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 4 and std.mem.eql(u8, args[1], "churn-server")) {
        return churn.run(init, args[2..]);
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "bench-server")) {
        return runBenchmark(init, args[2..]);
    }
    // Browser certificate hashes impose a <=14-day validity window, so the
    // browser gates supply a freshly generated DER leaf and raw P-256 scalar.
    // Native wtransport interop keeps using the stable built-in test identity.
    if (args.len != 2 and args.len != 4 and args.len != 5 and
        args.len != 6 and args.len != 7 and args.len != 8)
    {
        return error.InvalidArgument;
    }
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var built_in_certificate_der: [
        netz.tls.testing.certificate_der_len
    ]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &built_in_certificate_der,
        netz.tls.testing.certificate_base64,
    );
    var owned_certificate_der: ?[]u8 = null;
    defer if (owned_certificate_der) |bytes| allocator.free(bytes);
    var owned_private_scalar: ?[]u8 = null;
    defer if (owned_private_scalar) |bytes| allocator.free(bytes);
    const certificate_der: []const u8 = if (args.len >= 4) blk: {
        owned_certificate_der = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[2],
            allocator,
            .limited(16 * 1024),
        );
        break :blk owned_certificate_der.?;
    } else &built_in_certificate_der;
    const key_pair = if (args.len >= 4) blk: {
        owned_private_scalar = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[3],
            allocator,
            .limited(33),
        );
        if (owned_private_scalar.?.len != 32) return error.InvalidArgument;
        const secret = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey
            .fromBytes(owned_private_scalar.?[0..32].*);
        break :blk try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair
            .fromSecretKey(secret);
    } else try netz.tls.testing.serverKeyPair();
    const server_cid = [_]u8{ 0x77, 0x74, 0x69, 0x6f, 0x70, 0x00, 0x00, 0x01 };

    const allowed_origins: []const []const u8 = if (args.len >= 5)
        args[4..5]
    else
        &.{};
    const browser_mode = if (args.len >= 6) args[5] else "";
    const origin_only = std.mem.eql(u8, browser_mode, "origin-only");
    const reject_origin = std.mem.eql(u8, browser_mode, "reject-origin");
    const client_io = if (args.len >= 7)
        args[6]
    else if (args.len >= 4)
        "chromium-network-service"
    else
        "wtransport-quinn-tokio";
    if (args.len >= 6 and !origin_only and !reject_origin and
        !std.mem.eql(u8, browser_mode, "full"))
    {
        return error.InvalidArgument;
    }
    if (args.len >= 7 and args[6].len == 0) return error.InvalidArgument;
    if (args.len >= 7 and
        !std.mem.eql(u8, client_io, "chromium-network-service") and
        !std.mem.eql(u8, client_io, "firefox-necko"))
    {
        return error.InvalidArgument;
    }
    const stream_cancellation_mode = if (args.len == 8)
        args[7]
    else if (std.mem.eql(u8, client_io, "firefox-necko"))
        "reset-only"
    else
        "full";
    if (!std.mem.eql(u8, stream_cancellation_mode, "full") and
        !std.mem.eql(u8, stream_cancellation_mode, "reset-only"))
    {
        return error.InvalidArgument;
    }
    if (std.mem.eql(u8, stream_cancellation_mode, "reset-only") and
        !std.mem.eql(u8, client_io, "firefox-necko"))
    {
        return error.InvalidArgument;
    }
    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 256,
            } },
            .origin_policy = if (allowed_origins.len == 0)
                .same_origin_or_absent
            else
                .{ .exact = allowed_origins },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .max_crypto_buffer = 64 * 1024,
                .identity = .{
                    .certificate_chain = &.{certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz WebTransport interop server listening on {f}\n",
        .{server.address()},
    );

    var pending = try server.receiveSessionRequest();
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.path(), "/interop")) {
        return error.UnexpectedPath;
    }
    // Firefox sends User-Agent on its Extended CONNECT. Chromium currently
    // does not, so its artifact identity is verified by the Puppeteer driver.
    if (std.mem.eql(u8, client_io, "firefox-necko")) {
        const user_agent = pending.userAgent() orelse
            return error.UnexpectedHeader;
        if (std.mem.indexOf(u8, user_agent, "Firefox/") == null) {
            return error.UnexpectedHeader;
        }
    }
    if (allowed_origins.len != 0) {
        const origin = pending.origin() orelse return error.UnexpectedHeader;
        if (reject_origin) {
            if (std.mem.eql(u8, origin, allowed_origins[0])) {
                return error.UnexpectedHeader;
            }
            try std.testing.expectError(error.InvalidOrigin, pending.accept());
            var rejected = try pending.forbidden();
            pending_owned = false;
            defer rejected.deinit();
            std.debug.print(
                "netz WebTransport Origin policy passed: rejected=403 client_io={s} server_io=zio-std-io\n",
                .{client_io},
            );
            try std.Io.sleep(io, .fromMilliseconds(100), .awake);
            return;
        }
        if (!std.mem.eql(u8, origin, allowed_origins[0])) {
            return error.UnexpectedHeader;
        }
    } else {
        if (!std.mem.eql(
            u8,
            pending.userAgent() orelse return error.UnexpectedHeader,
            "netz-wtransport-gate",
        )) return error.UnexpectedHeader;
        const authorization = blk: {
            for (pending.headers()) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
                    break :blk header.value;
                }
            }
            return error.UnexpectedHeader;
        };
        if (!std.mem.eql(u8, authorization, "Bearer wtransport-interop")) {
            return error.UnexpectedHeader;
        }
    }
    var session = try pending.acceptWithHeaders(&.{.{
        .name = "x-netz-admission",
        .value = "accepted",
    }});
    pending_owned = false;
    defer session.deinit();
    const max_datagram_size = session.maxDatagramSize();
    if (max_datagram_size == 0) return error.UnexpectedDatagramLimit;
    const oversized_datagram = try allocator.alloc(
        u8,
        max_datagram_size + 1,
    );
    defer allocator.free(oversized_datagram);
    @memset(oversized_datagram, 0xa5);
    try std.testing.expectError(
        error.DatagramTooLarge,
        session.sendDatagram(oversized_datagram),
    );
    std.debug.print(
        "netz WebTransport interop accepted CONNECT with admission metadata\n",
        .{},
    );
    if (origin_only) {
        std.debug.print(
            "netz WebTransport Origin policy passed: exact-origin=true client_io={s} server_io=zio-std-io\n",
            .{client_io},
        );
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
        return;
    }

    var datagram = try session.receiveDatagram();
    defer datagram.deinit(allocator);
    if (!std.mem.eql(u8, datagram.datagram.payload, client_datagram)) {
        return error.UnexpectedDatagram;
    }
    std.debug.print("netz WebTransport interop received DATAGRAM\n", .{});
    try session.sendDatagram(server_datagram);

    var read_buffer: [64]u8 = undefined;
    const bidi_stream_id = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .bidirectional,
        false,
        client_bidi,
        true,
    );
    std.debug.print("netz WebTransport interop received bidi\n", .{});
    try session.sendStream(bidi_stream_id, server_bidi, true);
    try session.waitForStreamRecoveryIdleWithTimeout(bidi_stream_id, .fromSeconds(2));

    _ = try receiveExpectedStream(
        &session,
        &read_buffer,
        null,
        .unidirectional,
        false,
        client_uni,
        true,
    );
    std.debug.print("netz WebTransport interop received uni\n", .{});
    const response_uni = try session.openUnidirectionalStream();
    try session.sendStream(response_uni, server_uni, true);
    try session.waitForStreamRecoveryIdleWithTimeout(response_uni, .fromSeconds(2));
    if (allowed_origins.len != 0) {
        // Browser WritableStreams do not promise that a completed write was
        // placed on the wire before a following abort. Accept any validated
        // prefix, but require the reset's absolute QUIC final size to include
        // the complete association header and application write.
        var reset_header: std.ArrayList(u8) = .empty;
        defer reset_header.deinit(allocator);
        try netz.webtransport.UnidirectionalStreamHeader.writeWebTransport(
            &reset_header,
            allocator,
            session.sessionId(),
        );
        var reset_barrier = try session.receiveDatagram();
        defer reset_barrier.deinit(allocator);
        if (!std.mem.eql(u8, reset_barrier.datagram.payload, reset_flush)) {
            return error.UnexpectedResetBarrier;
        }
        _ = try receiveExpectedResetStream(
            &session,
            &read_buffer,
            client_reset,
            71,
            reset_header.items.len,
        );
        try session.sendDatagram(reset_ready);
    } else {
        const reset_stream_id = try receiveExpectedStream(
            &session,
            &read_buffer,
            null,
            .unidirectional,
            false,
            client_reset,
            false,
        );
        try session.sendDatagram(reset_ready);
        while (true) {
            const event = try session.readStream(&read_buffer);
            switch (event) {
                .reset => |reset| {
                    if (reset.stream_id != reset_stream_id or
                        reset.direction != .unidirectional or
                        reset.locally_initiated or
                        reset.error_info.application_code != 71)
                    {
                        return error.UnexpectedResetStream;
                    }
                    break;
                },
                .data, .stopped => return error.UnexpectedResetStream,
            }
        }
    }
    if (std.mem.eql(u8, stream_cancellation_mode, "reset-only")) {
        const reuse_stream_id = try receiveExpectedStream(
            &session,
            &read_buffer,
            null,
            .bidirectional,
            false,
            reuse_request,
            true,
        );
        try session.sendStream(reuse_stream_id, reuse_response, true);
        var ready = try session.receiveDatagram();
        defer ready.deinit(allocator);
        if (!std.mem.eql(u8, ready.datagram.payload, close_ready)) {
            return error.UnexpectedCloseReady;
        }
        try session.drain();
        try session.close(77, "netz done");
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
        std.debug.print(
            "netz WebTransport server interop passed: CONNECT DATAGRAM max_datagram_size={d} oversized_rejected=true bidi uni reset=71 reuse-after-reset=true drain-before-close=true close client_io={s} server_io=zio-std-io\n",
            .{ max_datagram_size, client_io },
        );
        return;
    }
    const stop_stream = try session.openUnidirectionalStream();
    try session.sendStream(stop_stream, server_stop, false);
    if (allowed_origins.len != 0) {
        var stop_barrier = try session.receiveDatagram();
        defer stop_barrier.deinit(allocator);
        if (!std.mem.eql(u8, stop_barrier.datagram.payload, stop_flush)) {
            return error.UnexpectedStopBarrier;
        }
    }
    var sibling_stream_id: ?u62 = null;
    var sibling_received: usize = 0;
    var sibling_finished = false;
    while (true) {
        const event = try session.readStream(&read_buffer);
        switch (event) {
            .stopped => |stopped| {
                if (stopped.stream_id != stop_stream or
                    stopped.direction != .unidirectional or
                    !stopped.locally_initiated or
                    stopped.error_info.application_code != 72)
                {
                    return error.UnexpectedStoppedStream;
                }
                break;
            },
            .data => |data| {
                if (data.direction != .bidirectional or
                    data.locally_initiated)
                {
                    return error.UnexpectedStoppedStream;
                }
                if (sibling_stream_id) |id| {
                    if (data.stream_id != id) {
                        return error.UnexpectedStoppedStream;
                    }
                } else {
                    sibling_stream_id = data.stream_id;
                }
                if (data.bytes > reuse_request.len - sibling_received or
                    !std.mem.eql(
                        u8,
                        read_buffer[0..data.bytes],
                        reuse_request[sibling_received..][0..data.bytes],
                    ))
                {
                    return error.UnexpectedStoppedStream;
                }
                sibling_received += data.bytes;
                if (data.fin) {
                    if (sibling_received != reuse_request.len) {
                        return error.UnexpectedStoppedStream;
                    }
                    sibling_finished = true;
                }
            },
            .reset => return error.UnexpectedStoppedStream,
        }
    }
    while (!sibling_finished) {
        const event = try session.readStream(&read_buffer);
        if (event != .data) return error.UnexpectedStream;
        const data = event.data;
        if (sibling_stream_id) |id| {
            if (data.stream_id != id) return error.UnexpectedStream;
        } else {
            sibling_stream_id = data.stream_id;
        }
        if (data.bytes > reuse_request.len - sibling_received or
            !std.mem.eql(
                u8,
                read_buffer[0..data.bytes],
                reuse_request[sibling_received..][0..data.bytes],
            ))
        {
            return error.UnexpectedStream;
        }
        sibling_received += data.bytes;
        if (data.fin) {
            if (sibling_received != reuse_request.len) {
                return error.UnexpectedStream;
            }
            sibling_finished = true;
        }
    }
    try session.sendDatagram(cancel_done);

    try session.sendStream(sibling_stream_id.?, reuse_response, true);

    var ready = try session.receiveDatagram();
    defer ready.deinit(allocator);
    if (!std.mem.eql(u8, ready.datagram.payload, close_ready)) {
        return error.UnexpectedCloseReady;
    }
    // wtransport does not expose DRAIN as an application event, but its
    // CONNECT-stream driver must skip this registered capsule without losing
    // framing. Follow it with CLOSE_WEBTRANSPORT_SESSION and CONNECT FIN so
    // the browser resolves `transport.closed` with the exact session metadata.
    try session.drain();
    if (allowed_origins.len == 0) {
        // wtransport 0.7 does not expose peer session-close metadata. Retain
        // the native gate's independent QUIC application-close assertion.
        try session.closeConnection(77, "netz done");
    } else {
        try session.close(77, "netz done");
    }
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    std.debug.print(
        "netz WebTransport server interop passed: CONNECT DATAGRAM max_datagram_size={d} oversized_rejected=true bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true {s} close client_io={s} server_io=zio-std-io\n",
        .{
            max_datagram_size,
            if (allowed_origins.len == 0)
                "drain-before-connection-close=true"
            else
                "drain-before-close=true",
            client_io,
        },
    );
}

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len == 0) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
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
            "wtransport-client+netz-server",
            "server",
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

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const server_cid =
        [_]u8{ 0x6e, 0x7a, 0x77, 0x74, 0x73, 0x00, 0x00, 0x01 };
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    var server = try netz.webtransport.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .http3 = .{ .quic = .{
                .max_datagram_size = benchmark.max_datagram_size,
                .max_frames_per_datagram = 16,
                .enable_gso_send = false,
                .enable_gro_receive = false,
                .socket_traffic_counters = if (traffic)
                    &socket_traffic
                else
                    null,
            } },
            .max_session_streams = try config.sessionStreams(),
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = try config.transportParameters(),
                .initial_one_rtt_config = try config.oneRttConfig(),
                .max_crypto_buffer = 64 * 1024,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
            },
            .session = try config.sessionOptions(),
        },
    );
    defer server.deinit();
    std.debug.print("NETZ_BENCH_PORT={d}\n", .{server.address().ip4.port});

    var pending = try server.receiveSessionRequestWithTimeout(config.timeout());
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.path(), "/benchmark") or
        !std.mem.eql(
            u8,
            pending.userAgent() orelse return error.UnexpectedHeader,
            "wtransport-benchmark",
        ))
    {
        return error.UnexpectedBenchmarkConnect;
    }
    var session = try pending.accept();
    pending_owned = false;
    defer session.deinit();
    const datagram_limit = try benchmark.validateDatagramLimit(&session, config);
    try benchmark.printConfig(
        "netz",
        "wtransport-client+netz-server",
        "server",
        config,
        datagram_limit,
    );
    const control = try benchmark.acceptControlServer(&session, config);
    try benchmark.runServer(allocator, &session, control, config);
    try benchmark.receiveCloseReady(&session, control, config);
    try benchmark.sendCloseAck(&session, control, config);
    try benchmark.receiveControlFinAndFinish(&session, control, config);
    benchmark.printServerComplete(
        "wtransport-client+netz-server",
        config,
    );
    if (traffic) {
        benchmark.printNetzTraffic(
            "wtransport-client+netz-server",
            "server",
            config,
            socket_traffic.stats(),
        );
    }
}
