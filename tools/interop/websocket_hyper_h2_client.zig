//! RFC 8441 client for process-boundary interoperability with Hyper's HTTP/2
//! Extended CONNECT and upgraded byte-stream implementation.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("websocket_hyper_h2_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "bench-client")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .enable_connect_protocol = true,
        .handshake_timeout = .fromSeconds(5),
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    var exported: [32]u8 = undefined;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    var h2 = if (tls_enabled)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer h2.close();
    var websocket = try netz.websocket.runtime.H2Client.open(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .path = "/websocket",
            .scheme = "http",
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
        },
    );
    defer websocket.close();
    if (tls_enabled) {
        const chain = websocket.peerCertificates() orelse
            return error.MissingPeerCertificate;
        if (chain.len == 0 or
            !std.mem.eql(u8, websocket.negotiatedAlpn().?, "h2") or
            websocket.negotiatedCipherSuite() == null or
            websocket.negotiatedTranscriptHash() == null)
        {
            return error.InvalidTlsMetadata;
        }
        try websocket.exportKeyingMaterial(
            "EXPORTER-netz-rfc8441",
            "hyper",
            &exported,
        );
    } else {
        if (websocket.peerCertificates() != null or
            websocket.negotiatedAlpn() != null or
            websocket.keyUpdateCounts() != null)
        {
            return error.InvalidTlsMetadata;
        }
    }

    try websocket.sendFragmented(.text, &.{ "netz ", "websocket ", "h2" });
    var response = try websocket.receiveMessage();
    defer response.deinit(allocator);
    if (response.opcode != .text or
        !std.mem.eql(u8, response.payload, "hyper websocket h2"))
    {
        return error.UnexpectedWebSocketMessage;
    }
    if (tls_enabled) {
        var peer_exporter = try websocket.receiveMessage();
        defer peer_exporter.deinit(allocator);
        if (peer_exporter.opcode != .binary or
            !std.mem.eql(u8, peer_exporter.payload, &exported))
        {
            return error.InvalidExporter;
        }
        const updates = websocket.keyUpdateCounts() orelse
            return error.MissingKeyUpdate;
        if (updates.received != 1 or updates.sent != 1 or
            updates.awaiting_peer_response)
        {
            return error.InvalidKeyUpdateCount;
        }
    }

    var application = try websocket.pingWithTimeout("ping", .fromSeconds(1));
    defer application.deinit(allocator);
    if (application != .application or
        application.application.header.opcode != .binary or
        !std.mem.eql(u8, application.application.payload, "during probe")) return error.UnexpectedWebSocketMessage;
    var pong = try websocket.continuePingWithTimeout("ping", .fromSeconds(1));
    defer pong.deinit(allocator);
    if (pong != .pong) {
        return error.UnexpectedPong;
    }
    std.debug.print("netz RFC 8441 Ping tolerated unsolicited Pong and preserved interleaved data: transport={s}\n", .{if (tls_enabled) "tls" else "h2c"});

    var close_event = try websocket.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "done" },
        .fromSeconds(1),
    );
    defer close_event.deinit(allocator);
    const close = close_event.closed orelse
        return error.MissingClosePayload;
    if (close.code != .normal_closure or
        !std.mem.eql(u8, close.reason, "done"))
    {
        return error.UnexpectedClose;
    }

    std.debug.print(
        "netz RFC 8441 client interoperated with Hyper: transport={s} fragmented-text ping pong bounded-close tls_metadata={s} key_update={s} client_io=zio-std-io server_io=hyper-tokio\n",
        .{
            if (tls_enabled) "tls" else "h2c",
            if (tls_enabled) "verified" else "n/a",
            if (tls_enabled) "verified" else "n/a",
        },
    );
}

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len == 0) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    if (port == 0) return error.InvalidArgument;
    var stats = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const config = try benchmark.Config.parse(config_args.items);
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    try runBenchmarkWithAllocator(allocator, port, config);
    if (stats) {
        const snapshot = counting.snapshot();
        if (snapshot.current_bytes != 0) return error.MemoryLeak;
        benchmark.printNetzMemory(
            "netz-client+hyper-server",
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
) !void {
    // Keep zio's executor bookkeeping outside the explicit protocol allocator
    // so --stats remains comparable with the historical workload scope.
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();
    var h2 = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        config.clientH2Limits(),
    );
    defer h2.close();
    var warmup_header: [10]u8 = undefined;
    var iterations_header: [10]u8 = undefined;
    var payload_header: [10]u8 = undefined;
    var timeout_header: [10]u8 = undefined;
    const headers = try config.headers(
        &warmup_header,
        &iterations_header,
        &payload_header,
        &timeout_header,
    );
    var ws = try netz.websocket.runtime.H2Client.openWithTimeout(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .path = benchmark.path,
            .scheme = "http",
            .origin = benchmark.origin,
            .protocols = &.{benchmark.protocol},
            .extra_headers = &headers,
            .limits = config.wsLimits(),
        },
        config.timeout(),
    );
    defer ws.close();
    if (ws.permessage_deflate or ws.selected_protocol == null or
        !std.mem.eql(u8, ws.selected_protocol.?, benchmark.protocol))
    {
        return error.InvalidNegotiatedMetadata;
    }
    var ready_message = try ws.receiveMessageWithTimeout(config.timeout());
    defer ready_message.deinit(allocator);
    if (ready_message.opcode != .binary or
        !std.mem.eql(u8, ready_message.payload, benchmark.ready))
    {
        return error.InvalidBenchmarkControl;
    }
    benchmark.printConfig("netz-client+hyper-server", config);
    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    const response = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(response);
    for (0..config.warmup) |round| {
        _ = try benchmarkRound(&ws, payload, response, @intCast(round), config);
    }
    const started = benchmark.nowNs(io);
    var checksum: u64 = 0;
    for (0..config.iterations) |sample| {
        const round = std.math.add(u32, config.warmup, @intCast(sample)) catch
            return error.InvalidArgument;
        checksum +%= try benchmarkRound(&ws, payload, response, round, config);
    }
    const elapsed = benchmark.nowNs(io) -| started;
    var close_event = try ws.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "done" },
        config.timeout(),
    );
    defer close_event.deinit(allocator);
    const close = close_event.closed orelse return error.MissingClosePayload;
    if (close.code != .normal_closure or !std.mem.eql(u8, close.reason, "done")) {
        return error.UnexpectedClose;
    }
    benchmark.printResult("netz-client+hyper-server", config, elapsed, checksum);
}

fn benchmarkRound(
    ws: *netz.websocket.runtime.H2Connection,
    payload: []u8,
    response_storage: []u8,
    round: u32,
    config: benchmark.Config,
) !u64 {
    const expected = benchmark.fillPayload(payload, round);
    try ws.sendBinary(payload);
    const response = try ws.receiveMessageIntoWithTimeout(
        response_storage,
        config.timeout(),
    );
    if (response.opcode != .binary or response.was_compressed or
        response.payload.len != payload.len) return error.InvalidBenchmarkPayload;
    const checksum = try benchmark.verifyPayload(response.payload, round);
    if (checksum != expected) return error.InvalidBenchmarkPayload;
    return checksum;
}
