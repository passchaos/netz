const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const source_peer = @import("source_peer.zig");
const target_peer = @import("target_peer.zig");

const mqtt = netz.mqtt;
const outbound = mqtt.bridge.outbound;
const runtime = mqtt.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, false);
}

pub fn runTlsSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, true);
}

fn runSequenceWithTransport(
    input: []const u8,
    comptime tls: bool,
) !model.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    const Server = if (tls) mqtt.tls_runtime.Server else runtime.Server;
    var source_server: Server = try listen(
        Server,
        tls,
        allocator,
        io,
        &certificate_chain,
        key_pair,
    );
    var source_only_open = true;
    errdefer if (source_only_open) source_server.deinit();
    var target_server: Server = try listen(
        Server,
        tls,
        allocator,
        io,
        &certificate_chain,
        key_pair,
    );
    source_only_open = false;
    var servers_open = true;
    defer if (servers_open) {
        target_server.deinit();
        source_server.deinit();
    };

    const sequence = input[0..@min(input.len, model.max_operations)];
    var signals = model.Signals{};
    const SourceState = source_peer.State(Server, tls);
    const TargetState = target_peer.State(Server, tls);
    var source = SourceState{
        .server = &source_server,
        .allocator = allocator,
        .io = io,
        .input = sequence,
        .signals = &signals,
    };
    var target = TargetState{
        .server = &target_server,
        .allocator = allocator,
        .io = io,
        .input = sequence,
        .signals = &signals,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        SourceState.run,
        .{&source},
    );
    const target_thread = std.Thread.spawn(
        .{},
        TargetState.run,
        .{&target},
    ) catch |err| {
        signals.abort(io);
        shutdownListener(&source_server, io);
        shutdownListener(&target_server, io);
        source_thread.join();
        source_server.deinit();
        target_server.deinit();
        servers_open = false;
        return err;
    };
    var joined = false;

    var shutdown: std.Io.Event = .unset;
    const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var source_connector = if (tls) tlsConnector(
        source_server.address(),
        public_key,
    ) else {};
    var target_connector = if (tls) tlsConnector(
        target_server.address(),
        public_key,
    ) else {};
    const options: outbound.MultiOptions = .{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "fuzz-outbound-source",
            .clean_start = false,
            .connect_timeout = model.packet_timeout,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "fuzz-outbound-target",
            .clean_start = false,
            .connect_timeout = model.packet_timeout,
            .properties = &session_expiry,
        },
        .source_reconnect_policy = .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
            .max_attempts = 1,
        },
        .target_reconnect_policy = .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
            .max_attempts = 1,
        },
        .rules = &.{
            .{
                .filter = model.bridge_filters[0],
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
            .{
                .filter = model.bridge_filters[1],
                .qos = .at_least_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
        },
    };
    var bridge: ?outbound.Bridge = (if (tls)
        outbound.Bridge.initConnectorMany(
            allocator,
            io,
            source_connector.connector(),
            target_connector.connector(),
            options,
            &shutdown,
        )
    else
        outbound.Bridge.initMany(
            allocator,
            io,
            source_server.address(),
            target_server.address(),
            options,
            &shutdown,
        )) catch |err| {
        signals.abort(io);
        shutdownListener(&source_server, io);
        shutdownListener(&target_server, io);
        source_thread.join();
        target_thread.join();
        source_server.deinit();
        target_server.deinit();
        servers_open = false;
        return err;
    };
    defer if (bridge) |*value| value.deinit();
    defer if (!joined) {
        if (bridge) |*value| {
            shutdownBridge(value);
            signals.abort(io);
            shutdownListener(&source_server, io);
            shutdownListener(&target_server, io);
            value.deinit();
            bridge = null;
        } else {
            signals.abort(io);
            shutdownListener(&source_server, io);
            shutdownListener(&target_server, io);
        }
        source_thread.join();
        target_thread.join();
        target_server.deinit();
        source_server.deinit();
        servers_open = false;
    };

    const connected = try bridge.?.connect();
    try std.testing.expect(!connected.source_session_present);
    try std.testing.expect(!connected.target_session_present);
    if (tls) try validateBridgeTls(&bridge.?);

    for (sequence, 0..) |_, index| {
        const operation_deadline = std.Io.Clock.awake.now(io).addDuration(
            model.coordination_timeout,
        );
        var attempts: usize = 0;
        while (signals.source_completed.load(.acquire) < index + 1 or
            signals.target_completed.load(.acquire) < index + 1)
        {
            if (source.failed.load(.acquire)) return source.err.?;
            if (target.failed.load(.acquire)) return target.err.?;
            if (attempts == 64) return error.BridgeProgressLimitExceeded;
            const remaining = std.Io.Clock.awake.now(io)
                .durationTo(operation_deadline);
            if (remaining.nanoseconds <= 0) {
                return error.BridgeProgressLimitExceeded;
            }
            _ = try bridge.?.step(.{
                .timeout = remaining,
                .cancellation_check_interval = .fromMilliseconds(5),
            });
            attempts += 1;
        }
        if (tls) try validateBridgeTls(&bridge.?);
    }

    try bridge.?.disconnect(0);
    source_thread.join();
    target_thread.join();
    joined = true;
    if (source.err) |err| return err;
    if (target.err) |err| return err;

    var summary = target.summary;
    summary.source_resumed = source.summary.source_resumed;
    summary.source_fresh = source.summary.source_fresh;
    summary.source_subscription_replays = source.summary
        .source_subscription_replays;
    return summary;
}

fn shutdownBridge(bridge: *outbound.Bridge) void {
    if (bridge.source.connection()) |connection| {
        connection.shutdown() catch {};
    }
    if (bridge.target.connection()) |connection| {
        connection.shutdown() catch {};
    }
}

fn shutdownListener(server: anytype, io: std.Io) void {
    const stream: std.Io.net.Stream = .{
        .socket = server.listener.socket,
    };
    stream.shutdown(io, .both) catch {};
}

fn listen(
    comptime Server: type,
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    certificate_chain: []const []const u8,
    key_pair: anytype,
) !Server {
    return if (tls)
        mqtt.tls_runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = certificate_chain,
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = .{ .max_packet_size = 4096 },
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .alpn_protocols = &.{"mqtt"},
                .tls_handshake_timeout = model.packet_timeout,
            },
        )
    else
        runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_packet_size = 4096 },
        );
}

fn tlsConnector(
    address: std.Io.net.IpAddress,
    public_key: [65]u8,
) mqtt.tls_runtime.ReconnectConnector {
    return .{
        .address = address,
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = model.packet_timeout,
        },
    };
}

fn validateBridgeTls(bridge: *outbound.Bridge) !void {
    try validateTls(bridge.source.connection() orelse
        return error.MissingSourceConnection);
    try validateTls(bridge.target.connection() orelse
        return error.MissingTargetConnection);
}

fn validateTls(connection: *runtime.Connection) !void {
    try std.testing.expectEqualStrings(
        "mqtt",
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
}
