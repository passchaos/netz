//! Certificate-verified RFC 9220 client for process-boundary interoperability
//! with a quic-go HTTP/3 server and its independent RFC 6455 codec.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("websocket_h3_quic_go_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 4 and std.mem.eql(u8, args[1], "bench-client")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len < 3 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    const version = try parseVersion(args[3..]);

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

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
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);

    var connection = try netz.websocket.runtime.h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = version,
                .available_versions = availableVersions(version),
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{
                    .key_update_profile = if (version == .version_2)
                        .quic_go_v0_59
                    else
                        .rfc,
                },
            },
            // Splitting HTTP/3 DATA prevents the external exchange from
            // accidentally depending on one WebSocket frame per QUIC write.
            // Five-byte DATA contributions push the pinned quic-go peer past
            // its first automatic key update while RFC 9220 frames are split.
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/rfc9220",
            .origin = "https://example.test",
            .protocols = &.{"netz-chat"},
            .enable_permessage_deflate = true,
            .compression_threshold = 1,
            .limits = websocketLimits(),
        },
    );
    defer connection.deinit();
    if (!std.mem.eql(u8, connection.negotiatedAlpn(), "h3") or
        connection.peerCertificates() == null or
        connection.peerCertificates().?.len == 0 or
        !connection.permessage_deflate or
        connection.selectedProtocol() == null or
        !std.mem.eql(
            u8,
            connection.selectedProtocol().?,
            "netz-chat",
        ))
    {
        return error.InvalidNegotiatedMetadata;
    }

    try connection.sendFragmented(.text, &.{
        "netz websocket ",
        "h3",
    });
    var response = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer response.deinit(allocator);
    if (response.opcode != .text or
        !std.mem.eql(u8, response.payload, "quic-go websocket h3"))
    {
        return error.UnexpectedWebSocketMessage;
    }
    try connection.sendText(
        "netz compressed websocket h3 netz compressed websocket h3 netz compressed websocket h3",
    );
    var compressed_response = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed_response.deinit(allocator);
    if (compressed_response.opcode != .text or
        !compressed_response.was_compressed or
        !std.mem.eql(
            u8,
            compressed_response.payload,
            "quic-go compressed websocket h3 quic-go compressed websocket h3 quic-go compressed websocket h3",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }
    try connection.sendText(
        "netz second compressed message netz second compressed message netz second compressed message",
    );
    var compressed_again = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed_again.deinit(allocator);
    if (compressed_again.opcode != .text or
        !compressed_again.was_compressed or
        !std.mem.eql(
            u8,
            compressed_again.payload,
            "quic-go second compressed message quic-go second compressed message quic-go second compressed message",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }

    try connection.sendPing("probe");
    var pong = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer pong.deinit(allocator);
    if (pong.header.opcode != .pong or
        !std.mem.eql(u8, pong.payload, "probe"))
    {
        return error.UnexpectedPong;
    }

    try connection.sendClose(.normal_closure, "done");
    var close = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    if (close.header.opcode != .close) return error.UnexpectedClose;
    const parsed = (try netz.websocket.parseClosePayload(close.payload)) orelse
        return error.MissingClosePayload;
    if (parsed.code != .normal_closure or
        !std.mem.eql(u8, parsed.reason, "done"))
    {
        return error.UnexpectedClose;
    }
    const local_key_updates = connection.localKeyUpdateCount();
    const peer_key_updates = connection.peerKeyUpdateCount();
    if (version == .version_2 and
        (local_key_updates == 0 or peer_key_updates == 0))
    {
        return error.MissingKeyUpdate;
    }

    std.debug.print(
        "netz RFC 9220 client interoperated with quic-go: version={d} extended_connect=true tls_verified=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done local_key_updates={d} peer_key_updates={d} client_io=zio-std-io server_io=quic-go-netpoll\n",
        .{ versionNumber(version), local_key_updates, peer_key_updates },
    );
}

fn runBenchmark(_: std.process.Init, args: []const []const u8) !void {
    if (args.len < 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[0], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[1])) {
        return error.InvalidArgument;
    }
    var stats = false;
    var config_args: std.ArrayList([]const u8) = .empty;
    defer config_args.deinit(std.heap.c_allocator);
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--stats") and !stats) {
            stats = true;
        } else {
            try config_args.append(std.heap.c_allocator, arg);
        }
    }
    const config = try benchmark.Config.parse(config_args.items);
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const allocator = if (stats) counting.allocator() else std.heap.c_allocator;
    try runBenchmarkWithAllocator(allocator, port, args[1], config);
    if (stats) {
        const snapshot = counting.snapshot();
        if (snapshot.current_bytes != 0) return error.MemoryLeak;
        benchmark.printNetzMemory(
            "netz-client+quic-go-server",
            "client",
            config,
            snapshot,
        );
    }
}

fn runBenchmarkWithAllocator(
    allocator: std.mem.Allocator,
    port: u16,
    ca_path: []const u8,
    config: benchmark.Config,
) !void {
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, ca_path);
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);
    var warmup_header: [10]u8 = undefined;
    var iterations_header: [10]u8 = undefined;
    var payload_header: [10]u8 = undefined;
    var timeout_header: [10]u8 = undefined;
    var version_header: [1]u8 = undefined;
    const headers = try config.headers(
        &warmup_header,
        &iterations_header,
        &payload_header,
        &timeout_header,
        &version_header,
    );
    var connection = try netz.websocket.runtime.h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 256,
            .enable_gso_send = false,
            .enable_gro_receive = false,
        } },
        .{
            .connect_timeout = config.timeout(),
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = config.version,
                .available_versions = config.availableVersions(),
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .local_transport_parameters = config.transportParameters(),
                .initial_one_rtt_config = config.oneRttConfig(),
                .max_crypto_buffer = 64 * 1024,
            },
            .session = config.sessionOptions(),
        },
        .{
            .authority = "localhost",
            .path = benchmark.path,
            .origin = benchmark.origin,
            .protocols = &.{benchmark.protocol},
            .extra_headers = &headers,
            .limits = config.websocketLimits(),
        },
    );
    defer connection.deinit();
    if (!std.mem.eql(u8, connection.negotiatedAlpn(), "h3") or
        connection.peerCertificates() == null or
        connection.peerCertificates().?.len == 0 or
        connection.permessage_deflate or
        connection.selectedProtocol() == null or
        !std.mem.eql(u8, connection.selectedProtocol().?, benchmark.protocol))
    {
        return error.InvalidNegotiatedMetadata;
    }

    var ready = try connection.receiveMessageWithTimeout(config.timeout());
    defer ready.deinit(allocator);
    if (ready.opcode != .binary or
        !std.mem.eql(u8, ready.payload, "NZWSREADY"))
    {
        return error.InvalidBenchmarkControl;
    }
    benchmark.printConfig("netz-client+quic-go-server", "client", config);
    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    const response_storage = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(response_storage);
    for (0..config.warmup) |round| {
        _ = try benchmarkRound(
            &connection,
            payload,
            response_storage,
            @intCast(round),
            config.timeout(),
        );
    }
    const started = benchmark.nowNs(io);
    var checksum: u64 = 0;
    for (0..config.iterations) |sample| {
        const round = std.math.add(u32, config.warmup, @intCast(sample)) catch
            return error.InvalidArgument;
        checksum +%= try benchmarkRound(
            &connection,
            payload,
            response_storage,
            round,
            config.timeout(),
        );
    }
    const elapsed = benchmark.nowNs(io) -| started;
    try connection.sendClose(.normal_closure, "done");
    var close = try connection.receiveFrameWithTimeout(config.timeout());
    defer close.deinit(allocator);
    if (close.header.opcode != .close) return error.UnexpectedClose;
    const parsed = (try netz.websocket.parseClosePayload(close.payload)) orelse
        return error.MissingClosePayload;
    if (parsed.code != .normal_closure or
        !std.mem.eql(u8, parsed.reason, "done"))
    {
        return error.UnexpectedClose;
    }
    benchmark.printResult(
        "netz-client+quic-go-server",
        config,
        elapsed,
        checksum,
    );
}

fn benchmarkRound(
    connection: *netz.websocket.runtime.h3.ClientConnection,
    payload: []u8,
    response_storage: []u8,
    round: u32,
    timeout: std.Io.Duration,
) !u64 {
    const expected_checksum = benchmark.fillPayload(payload, round);
    try connection.sendBinary(payload);
    const response = try connection.receiveMessageIntoWithTimeout(
        response_storage,
        timeout,
    );
    if (response.opcode != .binary or response.was_compressed or
        response.payload.len != payload.len)
    {
        return error.InvalidBenchmarkResponse;
    }
    const checksum = try benchmark.verifyPayload(response.payload, round);
    if (checksum != expected_checksum) return error.InvalidBenchmarkResponse;
    return checksum;
}

fn parseVersion(args: []const []const u8) !netz.quic.Version {
    if (args.len == 0) return .version_1;
    if (args.len == 1 and std.mem.eql(u8, args[0], "--version=2")) {
        return .version_2;
    }
    return error.InvalidArgument;
}

fn availableVersions(version: netz.quic.Version) []const netz.quic.Version {
    return if (version == .version_2)
        &.{.version_2}
    else
        &.{ .version_1, .version_2 };
}

fn versionNumber(version: netz.quic.Version) u8 {
    return if (version == .version_2) 2 else 1;
}

fn websocketLimits() netz.websocket.runtime.Limits {
    return .{
        .max_frame_bytes = 4096,
        .max_message_bytes = 4096,
    };
}
