const std = @import("std");
const netz = @import("netz");
const vail = @import("vail");
const identity = @import("quic_handshake/identity.zig");
const timed_verifier = @import("quic_handshake/timed_verifier.zig");

const alpn = "netz-handshake-bench";
const close_code: u64 = 67;
const close_reason = "handshake benchmark complete";

const Config = struct {
    role_pair: []const u8,
    warmup: usize = 10,
    iterations: usize = 100,
    run: usize = 1,
    timeout_ms: u32 = 10_000,
    trust_cache: bool = true,
    prepared_p256_certificate: ?[]const u8 = null,

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
            } else if (option(arg, "--trust-cache=")) |value| {
                result.trust_cache = if (std.mem.eql(u8, value, "enabled"))
                    true
                else if (std.mem.eql(u8, value, "disabled"))
                    false
                else
                    return error.InvalidArgument;
            } else if (option(arg, "--prepared-p256-certificate=")) |value| {
                if (result.prepared_p256_certificate != null or
                    !std.Io.Dir.path.isAbsolute(value))
                {
                    return error.InvalidArgument;
                }
                result.prepared_p256_certificate = value;
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
        if (args.len >= 4 and std.mem.startsWith(u8, args[3], "--")) {
            return runServer(
                port,
                null,
                null,
                try Config.parse(args[3..]),
            );
        }
        if (args.len < 6 or
            !std.Io.Dir.path.isAbsolute(args[3]) or
            !std.Io.Dir.path.isAbsolute(args[4]))
        {
            return error.InvalidArgument;
        }
        return runServer(
            port,
            args[3],
            args[4],
            try Config.parse(args[5..]),
        );
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
    var trust_cache_entries: [64]netz.tls.trust_cache.Entry = undefined;
    var trust_cache = netz.tls.trust_cache.BundleVerifierCache.init(
        io,
        &ca_bundle,
        now.toSeconds(),
        trust_cache_entries[0..if (config.trust_cache)
            trust_cache_entries.len
        else
            0],
    );
    var verifier = timed_verifier.Timed{
        .io = io,
        .verifier = trust_cache.clientVerifier(),
    };
    var prepared_p256: ?vail.crypto.p256.PreparedVerifier =
        if (config.prepared_p256_certificate) |path|
            try loadPreparedP256Verifier(allocator, io, path)
        else
            null;
    var socket_traffic: netz.quic.runtime.SocketTrafficCounters = .{};
    const latencies = try allocator.alloc(u64, config.iterations);
    defer allocator.free(latencies);
    var measured_index: usize = 0;
    var checksum: u64 = 0;
    for (0..config.total()) |round| {
        var endpoint = try netz.quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .max_datagram_size = 4096,
                .socket_traffic_counters = &socket_traffic,
            },
        );
        defer endpoint.deinit();
        const traffic_before = socket_traffic.stats();
        var original_dcid: [8]u8 = undefined;
        var client_cid: [8]u8 = undefined;
        try std.Io.randomSecure(io, &original_dcid);
        try std.Io.randomSecure(io, &client_cid);
        const started = nowNs(io);
        verifier.reset(started);
        var client_verifier = verifier.clientVerifier();
        if (prepared_p256) |*prepared| {
            client_verifier.prepared_p256_verifier = prepared;
        }
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
                .server_auth = client_verifier,
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{ .max_datagram_size = 4096 },
            },
            config.timeout(),
        );
        const completed = nowNs(io);
        const elapsed = completed -| started;
        const phases = try verifier.phases(completed);
        const traffic = socket_traffic.stats().since(traffic_before);
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
                    "timeout_ms={d} elapsed_ns={d} " ++
                    "connect_tx_datagrams={d} connect_tx_bytes={d} " ++
                    "connect_rx_datagrams={d} connect_rx_bytes={d} " ++
                    "pre_trust_ns={d} trust_ns={d} post_trust_ns={d} " ++
                    "trust_cache={s} certificate_verify={s} " ++
                    "verified=true\n",
                .{
                    config.role_pair,              config.run,                 measured_index,
                    clientIo(config.role_pair),    serverIo(config.role_pair), config.timeout_ms,
                    elapsed,                       traffic.sent_datagrams,     traffic.sent_bytes,
                    traffic.received_datagrams,    traffic.received_bytes,     phases.pre_trust_ns,
                    phases.trust_ns,               phases.post_trust_ns,       trustCacheName(config.trust_cache),
                    certificateVerifyName(config),
                },
            );
        }
    }
    const cache_stats = trust_cache.stats();
    std.debug.print(
        "record=trust-cache role_pair={s} run={d} mode={s} " ++
            "capacity={d} hits={d} " ++
            "misses={d} complete=true\n",
        .{
            config.role_pair,                                       config.run,       trustCacheName(config.trust_cache),
            if (config.trust_cache) trust_cache_entries.len else 0, cache_stats.hits, cache_stats.misses,
        },
    );
    try printResult("netz", config, latencies, checksum);
}

fn runServer(
    port: u16,
    certificate_path: ?[]const u8,
    private_scalar_path: ?[]const u8,
    config: Config,
) !void {
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var built_in_certificate: [netz.tls.testing.certificate_der_len]u8 =
        undefined;
    var loaded_identity: ?identity.Loaded = if (certificate_path) |cert|
        try identity.Loaded.init(
            allocator,
            io,
            cert,
            private_scalar_path orelse return error.InvalidArgument,
        )
    else
        null;
    defer if (loaded_identity) |*loaded| loaded.deinit(allocator);
    const server_identity = if (loaded_identity) |*loaded|
        loaded.serverIdentity()
    else built_in: {
        try std.base64.standard.Decoder.decode(
            &built_in_certificate,
            netz.tls.testing.certificate_base64,
        );
        break :built_in netz.quic.tls.auth.ServerIdentity{
            .certificate_chain = &.{&built_in_certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = try netz.tls.testing.serverKeyPair(),
            } },
        };
    };
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
                .identity = server_identity,
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
        .fromMilliseconds(if (round + 1 == config.total()) 100 else 20),
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
            "trust_cache={s} certificate_verify={s} " ++
            "key_exchange=x25519 cipher=aes-128-gcm-sha256 " ++
            "warmup={d} iterations={d} connections={d} echo_bytes={d} " ++
            "checksum={d} total_elapsed_ns={d} p50_ns={d} p99_ns={d} " ++
            "echo_verified=true complete=true\n",
        .{
            implementation,                     config.role_pair,              config.run,
            clientIo(config.role_pair),         serverIo(config.role_pair),    config.timeout_ms,
            trustCacheName(config.trust_cache), certificateVerifyName(config), config.warmup,
            config.iterations,                  config.total(),                config.total() * 32,
            checksum,                           total_elapsed_ns,              percentile(latencies, 50),
            percentile(latencies, 99),
        },
    );
}

fn trustCacheName(enabled: bool) []const u8 {
    return if (enabled) "enabled" else "disabled";
}

fn certificateVerifyName(config: Config) []const u8 {
    return if (config.prepared_p256_certificate != null)
        "prepared-p256"
    else
        "fresh-p256";
}

fn loadPreparedP256Verifier(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !vail.crypto.p256.PreparedVerifier {
    const certificate_der = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(certificate_der);
    return prepareP256Verifier(certificate_der);
}

fn prepareP256Verifier(
    certificate_der: []const u8,
) !vail.crypto.p256.PreparedVerifier {
    const parsed = std.crypto.Certificate.parse(.{
        .buffer = certificate_der,
        .index = 0,
    }) catch return error.InvalidCertificate;
    if (parsed.pub_key_algo != .X9_62_id_ecPublicKey or
        parsed.pub_key_algo.X9_62_id_ecPublicKey != .X9_62_prime256v1)
    {
        return error.UnsupportedCertificateKey;
    }
    const public_key = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey
        .fromSec1(parsed.pubKey()) catch return error.InvalidCertificate;
    return vail.crypto.p256.PreparedVerifier.init(public_key.p) catch
        return error.InvalidCertificate;
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
        "--trust-cache=disabled",
        "--prepared-p256-certificate=/tmp/leaf.der",
    });
    try std.testing.expectEqual(@as(usize, 7), config.total());
    try std.testing.expectEqual(@as(usize, 3), config.run);
    try std.testing.expect(!config.trust_cache);
    try std.testing.expectEqualStrings(
        "/tmp/leaf.der",
        config.prepared_p256_certificate.?,
    );
    try std.testing.expectEqualStrings(
        "prepared-p256",
        certificateVerifyName(config),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{
            "--role-pair=netz-client+quic-go-server",
            "--iterations=0",
        }),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{
            "--role-pair=netz-client+quic-go-server",
            "--trust-cache=maybe",
        }),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Config.parse(&.{
            "--role-pair=netz-client+quic-go-server",
            "--prepared-p256-certificate=relative.der",
        }),
    );
    const first = makeMarker(0);
    const second = makeMarker(1);
    try std.testing.expectEqualStrings("NZQHSB1\x00", first[0..8]);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
}

test "QUIC handshake benchmark prepares the fixed P-256 leaf identity" {
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const prepared = try prepareP256Verifier(&certificate_der);
    const key_pair = try netz.tls.testing.serverKeyPair();
    try std.testing.expect(prepared.matchesPublicKey(key_pair.public_key.p));
}

test "QUIC handshake benchmark percentile matches verifier convention" {
    const values = [_]u64{ 1, 2, 3, 4, 5 };
    try std.testing.expectEqual(@as(u64, 3), percentile(&values, 50));
    try std.testing.expectEqual(@as(u64, 5), percentile(&values, 99));
}
