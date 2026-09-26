const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const server_mod = @import("server.zig");

const http1 = netz.http1;
const runtime = http1.runtime;

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
    const sequence = input[0..@min(input.len, model.max_operations)];
    if (sequence.len == 0) return .{};
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const limits: runtime.Limits = .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const Server = if (tls) runtime.TlsServer else runtime.Server;
    var server: Server = if (tls)
        try runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = limits,
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls_handshake_timeout = model.timeout,
                .alpn_protocols = &.{"http/1.1"},
            },
        )
    else
        try runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            limits,
        );
    var server_open = true;
    defer if (server_open) server.deinit();
    const ServerState = server_mod.State(Server, tls);
    var server_state = ServerState{
        .server = &server,
        .allocator = allocator,
        .input = sequence,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerState.run,
        .{&server_state},
    );
    var joined = false;
    defer if (!joined) {
        server.deinit();
        server_open = false;
        server_thread.join();
    };

    var client: ?runtime.Client = null;
    defer if (client) |*value| value.close();
    var summary = model.Summary{};
    var connection_key_updates: u64 = 0;
    for (sequence, 0..) |operation, index| {
        if (client == null) {
            client = if (tls)
                try runtime.Client.connectVailTlsAddressWithTimeout(
                    allocator,
                    io,
                    server.address(),
                    "localhost",
                    limits,
                    .{
                        .server_verifier = .{
                            .pinned_ecdsa_p256_public_key = public_key,
                        },
                        .alpn_protocols = &.{"http/1.1"},
                        .cipher_suites = &.{.aes_128_gcm_sha256},
                        .handshake_timeout = model.timeout,
                    },
                    model.timeout,
                )
            else
                try runtime.Client.connectWithTimeout(
                    allocator,
                    io,
                    server.address(),
                    limits,
                    model.timeout,
                );
            if (tls) try validateTls(&client.?);
            connection_key_updates = 0;
            if (index != 0) summary.reconnects += 1;
        }
        if (tls and model.requestsKeyUpdate(operation)) {
            try client.?.updateTrafficKeys(true);
        }
        switch (model.kind(operation)) {
            0, 1, 4, 5, 6, 7 => try completeExchange(
                &client.?,
                operation,
                index,
                &summary,
            ),
            2 => try fixedStreamingRequest(
                &client.?,
                operation,
                index,
                &summary,
            ),
            3 => try chunkedStreamingRequest(
                &client.?,
                operation,
                index,
                &summary,
            ),
        }
        summary.requests += 1;
        if (tls and model.requestsKeyUpdate(operation)) {
            connection_key_updates += 1;
            summary.key_updates += 1;
            try validateKeyUpdates(&client.?, connection_key_updates);
        }
        if (model.closesConnection(operation)) {
            try std.testing.expect(!client.?.isReusable());
            client.?.close();
            client = null;
            if (model.kind(operation) == 5) {
                summary.server_closes += 1;
            } else {
                summary.client_closes += 1;
            }
        } else {
            try std.testing.expect(client.?.isReusable());
            summary.reused += 1;
        }
    }

    if (client) |*value| {
        value.close();
        client = null;
    }
    server_thread.join();
    joined = true;
    if (server_state.err) |err| return err;
    try std.testing.expectEqual(summary.requests, server_state.summary.requests);
    try std.testing.expectEqual(
        summary.server_closes + summary.client_closes,
        server_state.summary.server_closes,
    );
    try std.testing.expectEqual(
        summary.key_updates,
        server_state.summary.key_updates,
    );
    return summary;
}

fn validateTls(client: *runtime.Client) !void {
    try std.testing.expectEqualStrings(
        "http/1.1",
        client.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.CipherSuite.aes_128_gcm_sha256,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        client.negotiatedTranscriptHash().?,
    );
}

fn validateKeyUpdates(client: *runtime.Client, expected: u64) !void {
    const counts = client.keyUpdateCounts() orelse
        return error.MissingTlsState;
    try std.testing.expectEqual(expected, counts.sent);
    try std.testing.expectEqual(expected, counts.received);
    try std.testing.expect(!counts.awaiting_peer_response);
}

fn completeExchange(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    const headers: []const http1.Header = switch (model.kind(operation)) {
        5 => &.{.{ .name = "TE", .value = "trailers" }},
        7 => &.{.{ .name = "Connection", .value = "close" }},
        else => &.{},
    };
    var response = try client.requestWithTimeout(.{
        .method = model.method(operation),
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .headers = headers,
        .body = if (model.requestHasBody(operation))
            &request_body.value
        else
            &.{},
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.complete_bodies += 1;
    switch (model.kind(operation)) {
        4 => summary.streaming_fixed_responses += 1,
        5 => summary.streaming_chunked_responses += 1,
        6 => summary.head_responses += 1,
        else => {},
    }
}

fn fixedStreamingRequest(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .body_length = request_body.value.len,
    });
    defer writer.deinit();
    try writer.write(request_body.value[0..1]);
    try writer.writeChunks(&.{
        request_body.value[1..2],
        &.{},
        request_body.value[2..],
    });
    try writer.finish();
    var response = try writer.readResponseWithTimeout(model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.streaming_fixed_requests += 1;
}

fn chunkedStreamingRequest(
    client: *runtime.Client,
    operation: u8,
    index: usize,
    summary: *model.Summary,
) !void {
    var target_storage: [32]u8 = undefined;
    const request_body = model.Bytes.request(operation, index);
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = try model.targetBuffer(&target_storage, operation, index),
        .host = "localhost",
        .trailer_names = &.{"X-Request-Digest"},
    });
    defer writer.deinit();
    try writer.writeChunks(&.{
        request_body.value[0..1],
        request_body.value[1..],
    });
    try writer.finishTrailers(&.{.{
        .name = "X-Request-Digest",
        .value = "complete",
    }});
    var response = try writer.readResponseWithTimeout(model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response.response, operation, index);
    summary.streaming_chunked_requests += 1;
}

fn validateResponse(
    response: http1.Response,
    operation: u8,
    index: usize,
) !void {
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const expected = model.Bytes.response(operation, index);
    if (model.method(operation) == .HEAD) {
        try std.testing.expectEqual(@as(usize, 0), response.body.len);
        try std.testing.expectEqual(
            @as(?usize, expected.value.len),
            http1.contentLength(response.headers),
        );
        return;
    }
    try std.testing.expectEqualSlices(u8, &expected.value, response.body);
    if (model.kind(operation) == 5) {
        try std.testing.expectEqual(http1.BodyFraming.chunked, response.body_framing);
        try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
        try std.testing.expectEqualStrings(
            "X-Response-Digest",
            response.trailers[0].name,
        );
        try std.testing.expectEqualStrings(
            "complete",
            response.trailers[0].value,
        );
    }
}
