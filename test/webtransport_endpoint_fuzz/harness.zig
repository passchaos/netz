const std = @import("std");
const netz = @import("netz");
const client_mod = @import("client.zig");
const model = @import("model.zig");
const server_mod = @import("server.zig");

const runtime = netz.webtransport.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    const sequence = input[0..@min(input.len, model.max_operations)];
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
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } } },
        .{
            .handshake = .{
                .local_connection_id = "wt-fuzz-endpoint",
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .random = [_]u8{0x21} ** 32,
                .x25519_secret_key = [_]u8{0x22} ** 32,
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 40,
                    .max_duration_ms = 2_000,
                },
                .initial_one_rtt_config = .{ .enable_pacing = false },
            },
            .session = .{
                .local_settings = netz.webtransport.defaultSettings(.{}),
                .max_stream_frame_data = 256,
                .max_frames_per_packet = 8,
            },
        },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = model.client_count,
        .max_connections = model.client_count,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    var clients: [model.client_count]client_mod.Task = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .public_key = public_key,
            .input = sequence,
            .client_index = index,
        };
    }
    var threads: [model.client_count]std.Thread = undefined;
    var started: usize = 0;
    defer {
        for (clients[0..started]) |*client| client.release.set(io);
        if (started != 0 and endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        for (threads[0..started]) |thread| thread.join();
    }
    for (&clients, 0..) |*client, index| {
        threads[index] = try std.Thread.spawn(.{}, client_mod.Task.run, .{client});
        started += 1;
    }

    const expected = model.expected(sequence);
    const summary = try server_mod.run(&endpoint, expected, &clients);
    for (threads) |thread| thread.join();
    started = 0;
    for (&clients) |*client| if (client.err) |err| return err;
    try std.testing.expectEqual(expected.sessions, summary.sessions);
    try std.testing.expectEqual(expected.datagrams, summary.datagrams);
    try std.testing.expectEqual(expected.streams, summary.streams);
    try std.testing.expectEqual(expected.drains, summary.drains);
    try std.testing.expectEqual(expected.closes, summary.closes);
    return summary;
}
