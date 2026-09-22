//! One-session RFC 9220 server for process-boundary interoperability with a
//! quic-go client and its independent RFC 6455 codec.

const std = @import("std");
const netz = @import("netz");
const benchmark = @import("websocket_h3_quic_go_bench.zig");
const CountingAllocator = @import("benchmark_counting_allocator")
    .CountingAllocator;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "bench-server")) {
        return runBenchmark(init, args[2..]);
    }
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const version = try parseVersion(args[2..]);

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);

    var server = try netz.websocket.runtime.h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = version,
                .available_versions = availableVersions(version),
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{
                    .key_update_profile = if (version == .version_2)
                        .quic_go_v0_59
                    else
                        .rfc,
                },
            },
            // Five-byte DATA contributions push the pinned quic-go peer past
            // its first automatic key update while RFC 9220 frames are split.
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz RFC 9220 quic-go interop server listening on {f}\n",
        .{server.address()},
    );

    var connection = try server.accept(.{
        .protocols = &.{"netz-chat"},
        .allowed_origins = &.{"https://example.test"},
        .enable_permessage_deflate = true,
        .compression_threshold = 1,
        .limits = websocketLimits(),
    });
    defer connection.deinit();
    if (!std.mem.eql(u8, connection.negotiatedAlpn(), "h3") or
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

    // Inspect both frames rather than using the message aggregator so this
    // external gate proves quic-go emitted a continuation frame on the wire.
    var first = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer first.deinit(allocator);
    var second = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer second.deinit(allocator);
    if (first.header.fin or first.header.opcode != .text or
        !second.header.fin or second.header.opcode != .continuation)
    {
        return error.UnexpectedWebSocketMessage;
    }
    var message: ["netz websocket h3".len]u8 = undefined;
    if (first.payload.len + second.payload.len != message.len) {
        return error.UnexpectedWebSocketMessage;
    }
    @memcpy(message[0..first.payload.len], first.payload);
    @memcpy(message[first.payload.len..], second.payload);
    if (!std.mem.eql(u8, &message, "netz websocket h3")) {
        return error.UnexpectedWebSocketMessage;
    }

    try connection.sendText("quic-go websocket h3");
    var compressed_message = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed_message.deinit(allocator);
    if (compressed_message.opcode != .text or
        !compressed_message.was_compressed or
        !std.mem.eql(
            u8,
            compressed_message.payload,
            "netz compressed websocket h3 netz compressed websocket h3 netz compressed websocket h3",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }
    try connection.sendText(
        "quic-go compressed websocket h3 quic-go compressed websocket h3 quic-go compressed websocket h3",
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
            "netz second compressed message netz second compressed message netz second compressed message",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }
    try connection.sendText(
        "quic-go second compressed message quic-go second compressed message quic-go second compressed message",
    );
    var ping = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer ping.deinit(allocator);
    if (ping.header.opcode != .ping or
        !std.mem.eql(u8, ping.payload, "probe"))
    {
        return error.UnexpectedPing;
    }

    // receiveFrame automatically mirrors the close payload after validating
    // client masking, leaving us to assert the exact application close data.
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

    // Let the standalone client process consume and acknowledge the close
    // response before this one-shot server destroys the QUIC connection.
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    std.debug.print(
        "netz RFC 9220 server interoperated with quic-go: version={d} extended_connect=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done local_key_updates={d} peer_key_updates={d} client_io=quic-go-netpoll server_io=zio-std-io\n",
        .{ versionNumber(version), local_key_updates, peer_key_updates },
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
            "quic-go-client+netz-server",
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
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var server = try netz.websocket.runtime.h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 256,
            .enable_gso_send = false,
            .enable_gro_receive = false,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = config.version,
                .available_versions = config.availableVersions(),
                .local_transport_parameters = config.transportParameters(),
                .initial_one_rtt_config = config.oneRttConfig(),
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = config.sessionOptions(),
        },
    );
    defer server.deinit();
    std.debug.print(
        "NETZ_WEBSOCKET_H3_BENCH_PORT={d}\n",
        .{server.address().ip4.port},
    );
    var pending = try server.receiveUpgradeRequestWithTimeout(.{
        .protocols = &.{benchmark.protocol},
        .require_subprotocol = true,
        .allowed_origins = &.{benchmark.origin},
        .limits = config.websocketLimits(),
    }, config.timeout());
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.target(), benchmark.path) or
        pending.authority() == null or
        !std.mem.eql(u8, pending.authority().?, "localhost") or
        !std.meta.eql(try benchmark.Config.fromUpgrade(pending), config))
    {
        return error.InvalidBenchmarkConfig;
    }
    var connection = try pending.accept();
    pending_owned = false;
    defer connection.deinit();
    try connection.sendBinary("NZWSREADY");
    benchmark.printConfig("quic-go-client+netz-server", "server", config);
    const storage = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(storage);
    var checksum: u64 = 0;
    for (0..try config.rounds()) |round| {
        const message = try connection.receiveMessageIntoWithTimeout(
            storage,
            config.timeout(),
        );
        if (message.opcode != .binary or message.was_compressed or
            message.payload.len != config.payload_bytes)
        {
            return error.InvalidBenchmarkPayload;
        }
        const round_checksum = try benchmark.verifyPayload(
            message.payload,
            @intCast(round),
        );
        if (round >= config.warmup) checksum +%= round_checksum;
        try connection.sendBinary(message.payload);
    }
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
    benchmark.printServerComplete(
        "quic-go-client+netz-server",
        config,
        checksum,
    );
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
