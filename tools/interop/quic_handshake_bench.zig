const std = @import("std");
const netz = @import("netz");

const alpn = "netz-handshake-bench";
const close_code: u64 = 67;
const close_reason = "handshake benchmark complete";

const Config = struct {
    role_pair: []const u8,
    warmup: usize = 10,
    iterations: usize = 100,
    run: usize = 1,
    timeout_ms: u32 = 10_000,

    fn parse(args: []const []const u8) !Config {
        var role_pair: ?[]const u8 = null;
        var result = Config{ .role_pair = undefined };
        for (args) |arg| {
            if (option(arg, "--role-pair=")) |value| {
                if (role_pair != null) return error.InvalidArgument;
                role_pair = value;
            } else if (option(arg, "--warmup=")) |value| {
                result.warmup = try parseNonNegative(usize, value);
            } else if (option(arg, "--iterations=")) |value| {
                result.iterations = try parsePositive(usize, value);
            } else if (option(arg, "--run=")) |value| {
                result.run = try parsePositive(usize, value);
            } else if (option(arg, "--timeout-ms=")) |value| {
                result.timeout_ms = try parsePositive(u32, value);
            } else {
                return error.InvalidArgument;
            }
        }
        result.role_pair = role_pair orelse return error.InvalidArgument;
        if (!validRolePair(result.role_pair) or result.warmup > 4096 or
            result.iterations > 4096 or result.timeout_ms > 600_000 or
            result.warmup > std.math.maxInt(u64) - result.iterations)
        {
            return error.InvalidArgument;
        }
        return result;
    }

    fn total(self: Config) usize {
        return self.warmup + self.iterations;
    }

    fn timeout(self: Config) std.Io.Duration {
        return .fromMilliseconds(self.timeout_ms);
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) return error.InvalidArgument;
    if (std.mem.eql(u8, args[1], "client")) {
        if (args.len < 5 or !std.Io.Dir.path.isAbsolute(args[3])) {
            return error.InvalidArgument;
        }
        const port = try parsePositive(u16, args[2]);
        return runClient(port, args[3], try Config.parse(args[4..]));
    }
    if (std.mem.eql(u8, args[1], "server")) {
        const port = try parseNonNegative(u16, args[2]);
        return runServer(port, try Config.parse(args[3..]));
    }
    return error.InvalidArgument;
}

fn runClient(
    port: u16,
    ca_path: []const u8,
    config: Config,
) !void {
    const allocator = std.heap.c_allocator;
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
    const latencies = try allocator.alloc(u64, config.iterations);
    defer allocator.free(latencies);
    var measured_index: usize = 0;
    var checksum: u64 = 0;
    for (0..config.total()) |round| {
        var endpoint = try netz.quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer endpoint.deinit();
        var original_dcid: [8]u8 = undefined;
        var client_cid: [8]u8 = undefined;
        try std.Io.randomSecure(io, &original_dcid);
        try std.Io.randomSecure(io, &client_cid);
        const started = nowNs(io);
        var established = try netz.quic.handshake.connectWithTimeout(
            &endpoint,
            .{ .ip4 = .loopback(port) },
            .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
                .server_name = "localhost",
                .alpn_protocols = &.{alpn},
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .server_auth = verifier.clientVerifier(),
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{ .max_datagram_size = 4096 },
            },
            config.timeout(),
        );
        const elapsed = nowNs(io) -| started;
        defer established.deinit();
        try validateHandshake(established, true);
        try clientEchoAndClose(&established.connection, round, config);
        checksum +%= @intCast(round);
        if (round >= config.warmup) {
            latencies[measured_index] = elapsed;
            measured_index += 1;
            std.debug.print(
                "record=handshake-sample implementation=netz protocol=quic-v1 " ++
                    "mode=handshake role_pair={s} endpoint_role=client " ++
                    "run={d} sample={d} client_io={s} server_io={s} " ++
                    "timeout_ms={d} elapsed_ns={d} verified=true\n",
                .{
                    config.role_pair,           config.run,                 measured_index,
                    clientIo(config.role_pair), serverIo(config.role_pair), config.timeout_ms,
                    elapsed,
                },
            );
        }
    }
    try printResult("netz", config, latencies, checksum);
}

fn runServer(port: u16, config: Config) !void {
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
    var endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    std.debug.print("NETZ_HANDSHAKE_BENCH_PORT={d}\n", .{endpoint.address().ip4.port});
    var checksum: u64 = 0;
    for (0..config.total()) |round| {
        var server_cid: [8]u8 = undefined;
        try std.Io.randomSecure(io, &server_cid);
        var established = try netz.quic.handshake.acceptWithTimeout(
            &endpoint,
            .{
                .local_connection_id = &server_cid,
                .version = .version_1,
                .available_versions = &.{.version_1},
                .alpn_protocol = alpn,
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
                },
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{ .max_datagram_size = 4096 },
            },
            config.timeout(),
        );
        defer established.deinit();
        try validateHandshake(established, false);
        try serverEchoAndWaitClose(&established.connection, round, config);
        checksum +%= @intCast(round);
    }
    std.debug.print(
        "record=server-complete implementation=netz protocol=quic-v1 " ++
            "mode=handshake role_pair={s} endpoint_role=server run={d} " ++
            "warmup={d} iterations={d} " ++
            "client_io={s} server_io={s} timeout_ms={d} " ++
            "connections={d} echo_bytes={d} checksum={d} " ++
            "echo_verified=true peer_close=true complete=true\n",
        .{
            config.role_pair,  config.run,                 config.warmup,
            config.iterations, clientIo(config.role_pair), serverIo(config.role_pair),
            config.timeout_ms, config.total(),             config.total() * 32,
            checksum,
        },
    );
}

fn validateHandshake(
    established: netz.quic.handshake.EstablishedConnection,
    require_peer_certificate: bool,
) !void {
    if (!std.mem.eql(u8, established.alpn, alpn) or
        established.retry_processed or
        (require_peer_certificate and established.peerCertificates() == null) or
        established.negotiatedCipherSuite() != .aes_128_gcm_sha256)
    {
        return error.InvalidHandshake;
    }
}

fn clientEchoAndClose(
    connection: *netz.quic.one_rtt.Connection,
    round: usize,
    config: Config,
) !void {
    const stream_id = try connection.openStream();
    if (stream_id != 0) return error.UnexpectedStream;
    const marker = makeMarker(round);
    try connection.send(&.{.{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .data = &marker,
        .fin = true,
    } }});
    try receiveExactStream(connection, stream_id, &marker, config);
    try connection.closeApplication(close_code, close_reason);
    // Keep the per-round UDP endpoint alive long enough for the already
    // submitted CONNECTION_CLOSE to reach the peer. This occurs after the
    // measured handshake and verified echo.
    try std.Io.sleep(
        connection.endpoint.io,
        .fromMilliseconds(if (round + 1 == config.total()) 100 else 5),
        .awake,
    );
}

fn serverEchoAndWaitClose(
    connection: *netz.quic.one_rtt.Connection,
    round: usize,
    config: Config,
) !void {
    const marker = makeMarker(round);
    try receiveExactStream(connection, 0, &marker, config);
    try connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = &marker,
        .fin = true,
    } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(
        connection.endpoint.io,
        .{ .clock = .awake, .raw = config.timeout() },
    );
    while (connection.peerCloseInfo() == null) {
        connection.servicePacketServicingTimersDeadline(deadline) catch |err|
            switch (err) {
                error.ConnectionClosed => break,
                else => return err,
            };
    }
    const close = connection.peerCloseInfo() orelse return error.MissingPeerClose;
    if (close != .application or close.application.error_code != close_code or
        !std.mem.eql(u8, close.application.reason_phrase, close_reason))
    {
        return error.UnexpectedPeerClose;
    }
}

fn receiveExactStream(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    expected: []const u8,
    config: Config,
) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(
        connection.endpoint.io,
        .{ .clock = .awake, .raw = config.timeout() },
    );
    var received: usize = 0;
    while (received != expected.len or !connection.receivedStreamComplete(stream_id)) {
        if (connection.availableReceivedStream(stream_id)) |available| {
            if (available.len != 0) {
                const end = received + available.len;
                if (end > expected.len or
                    !std.mem.eql(u8, available, expected[received..end]))
                {
                    return error.InvalidEcho;
                }
                try connection.releaseReceivedCapacity(stream_id, available.len);
                received = end;
            }
        }
        if (received == expected.len and connection.receivedStreamComplete(stream_id)) break;
        try connection.servicePacketServicingTimersDeadline(deadline);
    }
}

fn printResult(
    implementation: []const u8,
    config: Config,
    latencies: []u64,
    checksum: u64,
) !void {
    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    var total_elapsed_ns: u64 = 0;
    for (latencies) |elapsed| total_elapsed_ns +|= elapsed;
    std.debug.print(
        "record=result implementation={s} protocol=quic-v1 mode=handshake " ++
            "role_pair={s} endpoint_role=client run={d} " ++
            "timing_scope=client-connect-only " ++
            "client_io={s} server_io={s} timeout_ms={d} " ++
            "verification=certificate resumption=disabled " ++
            "key_exchange=x25519 cipher=aes-128-gcm-sha256 " ++
            "warmup={d} iterations={d} connections={d} echo_bytes={d} " ++
            "checksum={d} total_elapsed_ns={d} p50_ns={d} p99_ns={d} " ++
            "echo_verified=true complete=true\n",
        .{
            implementation,             config.role_pair,           config.run,
            clientIo(config.role_pair), serverIo(config.role_pair), config.timeout_ms,
            config.warmup,              config.iterations,          config.total(),
            config.total() * 32,        checksum,                   total_elapsed_ns,
            percentile(latencies, 50),  percentile(latencies, 99),
        },
    );
}

fn makeMarker(round: usize) [16]u8 {
    var marker = [_]u8{0} ** 16;
    @memcpy(marker[0..8], "NZQHSB1\x00");
    std.mem.writeInt(u64, marker[8..16], @intCast(round), .big);
    return marker;
}

fn percentile(sorted: []const u64, percent: usize) u64 {
    return sorted[@min(sorted.len - 1, sorted.len * percent / 100)];
}

fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    return @intCast(@max(value, 0));
}

fn validRolePair(value: []const u8) bool {
    return std.mem.eql(u8, value, "netz-client+quic-go-server") or
        std.mem.eql(u8, value, "quic-go-client+quic-go-server") or
        std.mem.eql(u8, value, "quic-go-client+netz-server") or
        std.mem.eql(u8, value, "netz-client+quinn-server") or
        std.mem.eql(u8, value, "quinn-client+quinn-server") or
        std.mem.eql(u8, value, "quinn-client+netz-server") or
        std.mem.eql(u8, value, "netz-client+netz-server");
}

fn clientIo(role_pair: []const u8) []const u8 {
    if (std.mem.startsWith(u8, role_pair, "netz-client")) {
        return "zio-std-io";
    }
    if (std.mem.startsWith(u8, role_pair, "quinn-client")) {
        return "quinn-tokio-rustls";
    }
    return "quic-go-netpoll";
}

fn serverIo(role_pair: []const u8) []const u8 {
    if (std.mem.endsWith(u8, role_pair, "netz-server")) {
        return "zio-std-io";
    }
    if (std.mem.endsWith(u8, role_pair, "quinn-server")) {
        return "quinn-tokio-rustls";
    }
    return "quic-go-netpoll";
}

fn option(arg: []const u8, prefix: []const u8) ?[]const u8 {
    return if (std.mem.startsWith(u8, arg, prefix)) arg[prefix.len..] else null;
}

fn parsePositive(comptime T: type, value: []const u8) !T {
    const parsed = std.fmt.parseInt(T, value, 10) catch return error.InvalidArgument;
    if (parsed == 0) return error.InvalidArgument;
    return parsed;
}

fn parseNonNegative(comptime T: type, value: []const u8) !T {
    return std.fmt.parseInt(T, value, 10) catch error.InvalidArgument;
}

test "QUIC handshake benchmark configuration and marker are stable" {
    const config = try Config.parse(&.{
        "--role-pair=netz-client+quic-go-server",
        "--warmup=2",
        "--iterations=5",
        "--run=3",
        "--timeout-ms=1000",
    });
    try std.testing.expectEqual(@as(usize, 7), config.total());
    try std.testing.expectEqual(@as(usize, 3), config.run);
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{
            "--role-pair=netz-client+quic-go-server",
            "--iterations=0",
        }),
    );
    const first = makeMarker(0);
    const second = makeMarker(1);
    try std.testing.expectEqualStrings("NZQHSB1\x00", first[0..8]);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "QUIC handshake benchmark percentile matches verifier convention" {
    const values = [_]u64{ 1, 2, 3, 4, 5 };
    try std.testing.expectEqual(@as(u64, 3), percentile(&values, 50));
    try std.testing.expectEqual(@as(u64, 5), percentile(&values, 99));
}
