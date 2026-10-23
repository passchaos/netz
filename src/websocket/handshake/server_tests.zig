const std = @import("std");
const wire = @import("../../internal/wire.zig");
const server = @import("server.zig");
const writeServerHandshake = server.write;

test "WebSocket server handshake grouped sizing includes all negotiated fields" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const protocol = [_]wire.Header{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" }};
    const extension = [_]wire.Header{.{ .name = "Sec-WebSocket-Extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" }};
    const custom = [_]wire.Header{.{ .name = "X-Test", .value = "ok" }};
    const expected =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Protocol: chat.v1\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "X-Test: ok\r\n\r\n";
    try std.testing.expectEqual(expected.len, try server.encodedLen(key, &.{ &protocol, &extension, &custom }));
    try std.testing.expectError(error.InvalidHandshake, server.encodedLen(key, &.{ &protocol, &protocol }));
    try std.testing.expectError(error.InvalidHandshake, server.encodedLen(key, &.{ &extension, &extension }));
    try std.testing.expectError(error.MalformedHeader, server.encodedLen(key, &.{ &protocol, &.{.{ .name = "X-Last", .value = "ok\r\nInjected: yes" }} }));
}

test "WebSocket server handshake writer validates generated response" {
    const allocator = std.testing.allocator;
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    const original = "existing output";
    try response.appendSlice(allocator, original);

    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "not-base64",
        &.{},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Accept", .value = "duplicate" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2" },
        },
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "bad protocol" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);
    try std.testing.expectError(error.MalformedHeader, writeServerHandshake(
        &response,
        allocator,
        "dGhlIHNhbXBsZSBub25jZQ==",
        &.{.{ .name = "X-Test", .value = "ok\r\nInjected: yes" }},
    ));
    try std.testing.expectEqualStrings(original, response.items);

    for ([_]wire.Header{
        .{ .name = "cOnTeNt-LeNgTh", .value = "0" },
        .{ .name = "TrAnSfEr-EnCoDiNg", .value = "chunked" },
        .{ .name = "TrAiLeR", .value = "X-Checksum" },
    }) |header| {
        try std.testing.expectError(error.InvalidHandshake, writeServerHandshake(
            &response,
            allocator,
            "dGhlIHNhbXBsZSBub25jZQ==",
            &.{header},
        ));
        try std.testing.expectEqualStrings(original, response.items);
    }
}

test "WebSocket server handshake write is transactional and exactly reserved" {
    const allocator = std.testing.allocator;
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const extra_headers = &[_]wire.Header{
        .{ .name = "X-Test", .value = "ok" },
    };
    const expected =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "X-Test: ok\r\n" ++
        "\r\n";

    var failure: std.ArrayList(u8) = .empty;
    defer failure.deinit(allocator);
    try failure.ensureTotalCapacityPrecise(allocator, "seed".len);
    failure.appendSliceAssumeCapacity("seed");
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeServerHandshake(
            &failure,
            fail_first.allocator(),
            client_key,
            extra_headers,
        ),
    );
    try std.testing.expectEqualStrings("seed", failure.items);

    var exact_storage: [expected.len]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeServerHandshake(
        &exact,
        no_alloc.allocator(),
        client_key,
        extra_headers,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualStrings(expected, exact.items);
}
