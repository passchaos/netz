const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const server_mod = @import("server.zig");

const http2 = netz.http2;
const runtime = http2.runtime;

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
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_ping_frames = 16,
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

    var client: ?runtime.Connection = null;
    defer if (client) |*value| value.close();
    var summary = model.Summary{};
    var connection_key_updates: u64 = 0;
    for (sequence, 0..) |operation, index| {
        if (client == null) {
            client = if (tls)
                try runtime.Client.connectTlsAddressWithTimeout(
                    allocator,
                    io,
                    server.address(),
                    "localhost",
                    "localhost",
                    limits,
                    .{
                        .server_verifier = .{
                            .pinned_ecdsa_p256_public_key = public_key,
                        },
                        .cipher_suites = &.{.aes_128_gcm_sha256},
                        .tls_handshake_timeout = model.timeout,
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
            0 => {
                try completeRequest(&client.?, operation, index, "");
                summary.requests += 1;
                summary.simple += 1;
            },
            1 => {
                try requestWithTrailers(&client.?, operation, index);
                summary.requests += 1;
                summary.request_trailers += 1;
            },
            2 => {
                try streamingRequest(&client.?, operation, index);
                summary.requests += 1;
                summary.streaming_requests += 1;
            },
            3 => {
                try streamingResponse(&client.?, operation, index);
                summary.requests += 1;
                summary.streaming_responses += 1;
            },
            4 => {
                try batch(&client.?, operation, index);
                summary.requests += 2;
                summary.batches += 1;
            },
            5 => {
                const payload = server_mod.pingPayload(operation, index);
                try std.testing.expectEqual(
                    payload,
                    try client.?.pingWithTimeout(payload, model.timeout),
                );
                summary.pings += 1;
            },
            6 => {
                try cancelRequest(&client.?, operation, index);
                summary.requests += 1;
                summary.cancellations += 1;
            },
            7 => {
                var goaway = try client.?.readGoAwayWithTimeout(model.timeout);
                defer goaway.deinit(allocator);
                try std.testing.expectEqual(
                    http2.ErrorCode.no_error,
                    goaway.goaway.error_code,
                );
                try std.testing.expectEqualStrings(
                    "fuzz-rotate",
                    goaway.goaway.debug_data,
                );
                try std.testing.expect(!client.?.isReusable());
                client.?.close();
                client = null;
                summary.goaways += 1;
                continue;
            },
        }
        if (tls and model.requestsKeyUpdate(operation)) {
            connection_key_updates += 1;
            summary.key_updates += 1;
            try validateKeyUpdates(&client.?, connection_key_updates);
        }
        try std.testing.expect(client.?.isReusable());
    }

    if (client) |*value| {
        value.close();
        client = null;
    }
    server_thread.join();
    joined = true;
    if (server_state.err) |err| return err;
    try std.testing.expectEqual(summary.goaways, server_state.summary.goaways);
    try std.testing.expectEqual(
        summary.key_updates,
        server_state.summary.key_updates,
    );
    return summary;
}

fn validateTls(client: *runtime.Connection) !void {
    try std.testing.expectEqualStrings(
        "h2",
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

fn validateKeyUpdates(client: *runtime.Connection, expected: u64) !void {
    const counts = client.keyUpdateCounts() orelse
        return error.MissingTlsState;
    try std.testing.expectEqual(expected, counts.sent);
    try std.testing.expectEqual(expected, counts.received);
    try std.testing.expect(!counts.awaiting_peer_response);
}

fn completeRequest(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
    suffix: []const u8,
) !void {
    var path_storage: [40]u8 = undefined;
    var response = try client.requestWithTimeout(.{
        .path = try model.pathBuffer(&path_storage, operation, index, suffix),
        .authority = "localhost",
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response, operation, index, false);
}

fn requestWithTrailers(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const body = model.Bytes.request(operation, index);
    var response = try client.requestWithTimeout(.{
        .method = "POST",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
        .body = &body.value,
        .trailers = &.{.{ .name = "x-request-state", .value = "complete" }},
    }, model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response, operation, index, false);
}

fn streamingRequest(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    const body = model.Bytes.request(operation, index);
    var writer = try client.startRequestWithTimeout(.{
        .method = "POST",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
        .body_length = body.value.len,
    }, model.timeout);
    defer writer.deinit();
    try writer.writeWithTimeout(body.value[0..1], model.timeout);
    try writer.finishDataWithTimeout(body.value[1..], model.timeout);
    var response = try writer.readResponseWithTimeout(model.timeout);
    defer response.deinit(std.testing.allocator);
    try validateResponse(response, operation, index, false);
}

fn streamingResponse(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    var response = try client.requestStreamingWithTimeout(.{
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
    }, model.timeout, &body, struct {
        fn consume(output: *std.ArrayList(u8), bytes: []const u8) !void {
            try output.appendSlice(std.testing.allocator, bytes);
        }
    }.consume);
    defer response.deinit(std.testing.allocator);
    const expected = model.Bytes.response(operation, index);
    try std.testing.expectEqualSlices(u8, &expected.value, body.items);
    try std.testing.expectEqual(expected.value.len, response.body_bytes);
}

fn batch(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    var first_path: [40]u8 = undefined;
    var second_path: [40]u8 = undefined;
    const requests = [_]runtime.RequestOptions{
        .{
            .path = try model.pathBuffer(&first_path, operation, index, "/a"),
            .authority = "localhost",
        },
        .{
            .path = try model.pathBuffer(&second_path, operation, index, "/b"),
            .authority = "localhost",
        },
    };
    var responses: [requests.len]runtime.OwnedResponse = undefined;
    try client.requestBatchIntoWithTimeout(
        &requests,
        &responses,
        model.timeout,
    );
    defer for (&responses) |*response| response.deinit(std.testing.allocator);
    try validateResponse(responses[0], operation, index, false);
    try validateResponse(responses[1], operation, index, true);
}

fn cancelRequest(
    client: *runtime.Connection,
    operation: u8,
    index: usize,
) !void {
    var path_storage: [40]u8 = undefined;
    var writer = try client.startRequestWithTimeout(.{
        .method = "GET",
        .path = try model.pathBuffer(&path_storage, operation, index, ""),
        .authority = "localhost",
        .body_length = 0,
    }, model.timeout);
    try writer.finishWithTimeout(model.timeout);
    try writer.cancel(.cancel);
    writer.deinit();
}

fn validateResponse(
    response: runtime.OwnedResponse,
    operation: u8,
    index: usize,
    second: bool,
) !void {
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const expected = model.Bytes.response(operation, index);
    if (second) {
        const second_body = [_]u8{
            expected.value[0],
            expected.value[1],
            expected.value[2] ^ 0xff,
        };
        try std.testing.expectEqualSlices(u8, &second_body, response.body);
    } else {
        try std.testing.expectEqualSlices(u8, &expected.value, response.body);
    }
}
