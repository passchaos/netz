//! Tests moved out of the module runtime root.

const std = @import("std");
const websocket = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const H2Client = runtime.H2Client;
const H2Connection = runtime.H2Connection;
const H2Server = runtime.H2Server;
const Limits = runtime.Limits;
const MessageWriteProgress = runtime.MessageWriteProgress;
const PendingH2Write = runtime.PendingH2Write;
const PendingWrite = runtime.PendingWrite;
const Server = runtime.Server;
const acceptH2Extensions = runtime.acceptH2Extensions;
const canSendOpcode = runtime.canSendOpcode;
const common = runtime.common;
const compression_scratch = runtime.compression_scratch;
const failReceive = runtime.failReceive;
const h3 = runtime.h3;
const handshake_acceptance = runtime.handshake_acceptance;
const http1 = runtime.http1;
const http1HandshakeRequestParseOptions = runtime.http1HandshakeRequestParseOptions;
const http1HandshakeResponseParseOptions = runtime.http1HandshakeResponseParseOptions;
const http2 = runtime.http2;
const http2_runtime = runtime.http2_runtime;
const masked_write_scratch_len = runtime.masked_write_scratch_len;
const readHttpHead = runtime.readHttpHead;
const receive_failure = runtime.receive_failure;
const rejectH2ExtendedConnectLegacyHeaders = runtime.rejectH2ExtendedConnectLegacyHeaders;
const requiredH2SingletonHeader = runtime.requiredH2SingletonHeader;
const selectH2Subprotocol = runtime.selectH2Subprotocol;
const selectHttp1Subprotocol = runtime.selectHttp1Subprotocol;
const testing = runtime.testing;
const validateH2ClientExtraHeaders = runtime.validateH2ClientExtraHeaders;
const validateH2ServerExtraHeaders = runtime.validateH2ServerExtraHeaders;
const validateH2ServerHandshake = runtime.validateH2ServerHandshake;
const validateServerHandshake = runtime.validateServerHandshake;
const wire = runtime.wire;
const writeAllToStream = runtime.writeAllToStream;

test "WebSocket HTTP/1 connection keeps resumable writes compact" {
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 296), @sizeOf(PendingWrite));
        // Includes the receive-owned slot for controls waiting on a writer.
        try std.testing.expectEqual(@as(usize, 1616), @sizeOf(Connection));
    }
}

test "WebSocket RFC 8441 connection keeps resumable writes compact" {
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 296), @sizeOf(PendingH2Write));
        // OwnedTunnelData now keeps the read-ahead backing pointer introduced
        // by HTTP/2 retained frames (a597be32), including while reads resume.
        try std.testing.expectEqual(@sizeOf(http2_runtime.OwnedFrame) + @sizeOf(usize), @sizeOf(http2_runtime.RetainedFrame));
        try std.testing.expectEqual(@as(usize, 1648), @sizeOf(H2Connection));
    }
}

test "WebSocket client handshake accepts split Connection and rejects duplicate critical headers" {
    const allocator = std.testing.allocator;
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";

    const split_connection =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var response = try http1.parseResponse(
        allocator,
        split_connection,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(?[]u8, null), try validateServerHandshake(allocator, response, client_key, &.{}));
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try validateServerHandshake(
            allocator,
            response,
            client_key,
            &.{"chat.v1"},
        ),
    );

    const listed_upgrade =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: h2c/1, WebSocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var listed_response = try http1.parseResponse(
        allocator,
        listed_upgrade,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer listed_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try validateServerHandshake(
            allocator,
            listed_response,
            client_key,
            &.{},
        ),
    );

    const split_upgrade =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: h2c/1\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var split_upgrade_response = try http1.parseResponse(
        allocator,
        split_upgrade,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer split_upgrade_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try validateServerHandshake(
            allocator,
            split_upgrade_response,
            client_key,
            &.{},
        ),
    );

    const wrong_status =
        "HTTP/1.1 200 OK\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    var wrong_status_response = try http1.parseResponse(
        allocator,
        wrong_status,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer wrong_status_response.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateServerHandshake(
            allocator,
            wrong_status_response,
            client_key,
            &.{},
        ),
    );

    const malformed_upgrade =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: h2c/bad/version, websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var malformed_upgrade_response = try http1.parseResponse(
        allocator,
        malformed_upgrade,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer malformed_upgrade_response.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateServerHandshake(
            allocator,
            malformed_upgrade_response,
            client_key,
            &.{},
        ),
    );

    const duplicate_accept =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var duplicate_response = try http1.parseResponse(
        allocator,
        duplicate_accept,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer duplicate_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_response, client_key, &.{}));

    const duplicate_extensions =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "\r\n";
    var duplicate_extensions_response = try http1.parseResponse(
        allocator,
        duplicate_extensions,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer duplicate_extensions_response.deinit(allocator);
    try std.testing.expectError(error.InvalidExtension, validateServerHandshake(allocator, duplicate_extensions_response, client_key, &.{}));

    const content_length_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    var content_length_response = try http1.parseResponse(
        allocator,
        content_length_101,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer content_length_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, content_length_response, client_key, &.{}));

    const transfer_encoding_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    var transfer_encoding_response = try http1.parseResponse(
        allocator,
        transfer_encoding_101,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer transfer_encoding_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, transfer_encoding_response, client_key, &.{}));

    const trailer_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "TrAiLeR: X-Checksum\r\n" ++
        "\r\n";
    var trailer_response = try http1.parseResponse(
        allocator,
        trailer_101,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer trailer_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, trailer_response, client_key, &.{}));
}

test "WebSocket server negotiates split subprotocol request headers" {
    const allocator = std.testing.allocator;

    const selected = (try selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "unknown" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    )).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1, bad protocol" }},
        &.{"chat.v1"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" }},
        &.{"bad supported"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    ));
}

test "WebSocket over HTTP/2 handshake rejects duplicate critical headers" {
    const allocator = std.testing.allocator;

    const duplicate_request_version = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try std.testing.expectError(error.InvalidHandshake, requiredH2SingletonHeader(&duplicate_request_version, "sec-websocket-version"));

    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-version", .value = "13" },
    }));
    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    }));

    const duplicate_response_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(std.testing.allocator, &duplicate_response_protocol, &.{"chat.v1"}));
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerExtraHeaders(&.{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    }));

    const legacy_accept_response = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-accept", .value = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(allocator, &legacy_accept_response, &.{}));

    const legacy_key_request = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    try std.testing.expectError(error.InvalidHandshake, rejectH2ExtendedConnectLegacyHeaders(&legacy_key_request));

    const duplicate_extensions = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        websocket.ExtensionNegotiation
            .validateResponseHeadersForOfferWithPolicy(
            &duplicate_extensions,
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            .{ .enable_permessage_deflate = true },
        ),
    );

    const split_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "x-unknown" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted = try acceptH2Extensions(allocator, &split_offer, .{
        .enable_permessage_deflate = true,
    });
    defer if (accepted) |value| allocator.free(value);
    try std.testing.expect(accepted != null);

    const declined_offer = [_]http2.Hpack.HeaderField{.{
        .name = "sec-websocket-extensions",
        .value = "permessage-deflate; unknown=1",
    }};
    try std.testing.expect(
        try acceptH2Extensions(
            allocator,
            &declined_offer,
            .{ .enable_permessage_deflate = true },
        ) == null,
    );

    const malformed_later_extension = [_]http2.Hpack.HeaderField{
        .{
            .name = "sec-websocket-extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "sec-websocket-extensions",
            .value = "broken extension",
        },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        acceptH2Extensions(
            allocator,
            &malformed_later_extension,
            .{ .enable_permessage_deflate = true },
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        acceptH2Extensions(
            allocator,
            &malformed_later_extension,
            .{ .enable_permessage_deflate = false },
        ),
    );

    const split_protocol_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "unknown" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    const selected = (try selectH2Subprotocol(allocator, &split_protocol_offer, &.{ "chat.v1", "chat.v2" })).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    const invalid_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "bad protocol" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &invalid_split_protocol, &.{"chat.v1"}));
    const duplicate_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &duplicate_split_protocol, &.{ "chat.v1", "chat.v2" }));
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try validateH2ServerHandshake(
            allocator,
            &.{},
            &.{"chat.v1"},
        ),
    );
}

test "WebSocket runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 5,
            .max_message_bytes = 5,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expect(frame.header.masked);
            try std.testing.expectEqualStrings("hello", frame.payload);

            try std.testing.expectError(
                error.MessageTooLarge,
                connection.sendText("world!"),
            );
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            try std.testing.expect(connection.close_received.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/chat",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 5,
            .max_message_bytes = 5,
        },
    });
    defer client.close();

    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendText("hello!"),
    );
    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
    try std.testing.expect(!response.header.masked);
    try std.testing.expectEqualStrings("world", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime streams large immutable payload without mutation" {
    const allocator = std.testing.allocator;
    const payload_len = masked_write_scratch_len + 257;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    );
    defer server.deinit();

    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    const expected = try allocator.dupe(u8, payload);
    defer allocator.free(expected);

    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept(.{});
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                message.payload,
            );
            try connection.sendBinary(message.payload);
            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server, .expected = expected };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/immutable-large",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();
    try client.sendBinary(payload);
    try std.testing.expectEqualSlices(u8, expected, payload);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, expected, response.payload);
    try client.sendClose(.normal_closure, "");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket binary slices preserve one frame across length boundaries" {
    const allocator = std.testing.allocator;
    const payload = "0123456789abcdef" ** 4096;
    const lengths = [_]usize{ 0, 125, 126, 65_535, 65_536 };
    const trailing_empty_parts = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "",
        "",
    };
    const trailing_empty_payload = "0123456789abcde";
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            for (lengths) |len| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(frame.header.fin);
                try std.testing.expectEqualSlices(u8, payload[0..len], frame.payload);
                const middle = len / 2;
                try connection.sendBinarySlices(if (len == 0)
                    &.{}
                else
                    &.{ payload[0..1], "", payload[1..middle], payload[middle..len] });
            }
            try connection.sendBinarySlices(&trailing_empty_parts);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/binary-parts",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();
    for (lengths) |len| {
        const middle = len / 2;
        try client.sendBinarySlices(if (len == 0)
            &.{}
        else
            &.{ payload[0..1], "", payload[1..middle], payload[middle..len] });
        var response = try client.receiveFrame();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, response.header.opcode);
        try std.testing.expect(response.header.fin);
        try std.testing.expectEqualSlices(u8, payload[0..len], response.payload);
    }
    var trailing_empty = try client.receiveFrame();
    defer trailing_empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, trailing_empty.header.opcode);
    try std.testing.expect(trailing_empty.header.fin);
    try std.testing.expectEqualStrings(
        trailing_empty_payload,
        trailing_empty.payload,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{ .protocols = &.{ "chat.v2", "superchat" } });
            defer connection.close();
            try std.testing.expectEqualStrings("superchat", connection.selected_protocol.?);

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", frame.payload);
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/subprotocol",
        .protocols = &.{ "video", "superchat" },
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectEqualStrings("superchat", client.selected_protocol.?);

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", request.payload);
            try connection.sendText("dns-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .target = "/dns",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("dns-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by ws URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("uri-hello", request.payload);
            try connection.sendText("uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://localhost:{d}/uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(error.UnsupportedScheme, Client.connectUri(allocator, io, "ftp://localhost/chat", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws:///missing-host", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws://user:pass@localhost/chat", .{}));
}

test "WebSocket client connects by bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("ipv6-uri-hello", request.payload);
            try connection.sendText("ipv6-uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://[::1]:{d}/ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("ipv6-uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ipv6-uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates permessage-deflate" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{ .enable_permessage_deflate = true });
            defer connection.close();
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(!connection.compression_send_context_takeover);
            try std.testing.expect(!connection.compression_receive_context_takeover);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.http.allocator);
            for (0..3) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.http.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.http.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.http.allocator.free(request);
            try std.testing.expectEqualStrings(
                "compressible \xe2\x82\xac compressible compressible",
                request,
            );

            try connection.sendFragmented(.text, &.{ "deflated response ", "deflated response" });

            const ConcurrentSender = struct {
                connection: *Connection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            const concurrent_a = "h1-concurrent-a-h1-concurrent-a-" ++
                ("a" ** 480);
            const concurrent_b = "h1-concurrent-b-h1-concurrent-b-" ++
                ("b" ** 480);
            var start: std.Io.Event = .unset;
            var senders = [_]ConcurrentSender{
                .{ .connection = &connection, .io = server_ptr.http.io, .start = &start, .payload = concurrent_a },
                .{ .connection = &connection, .io = server_ptr.http.io, .start = &start, .payload = concurrent_b },
            };
            const sender_a = try std.Thread.spawn(.{}, ConcurrentSender.run, .{&senders[0]});
            const sender_b = std.Thread.spawn(.{}, ConcurrentSender.run, .{&senders[1]}) catch |err| {
                start.set(server_ptr.http.io);
                sender_a.join();
                return err;
            };
            start.set(server_ptr.http.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/deflate",
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expect(client.permessage_deflate);
    try std.testing.expect(!client.compression_send_context_takeover);
    try std.testing.expect(!client.compression_receive_context_takeover);

    // Split one UTF-8 scalar across the application slices. Compression must
    // still produce one DEFLATE message, then preserve the requested three
    // WebSocket frames with RSV1 set only on the first frame.
    try client.sendFragmented(.text, &.{
        "compressible \xe2",
        "\x82",
        "\xac compressible compressible",
    });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("deflated response deflated response", response.payload);
    try std.testing.expect(response.was_compressed);

    const concurrent_a = "h1-concurrent-a-h1-concurrent-a-" ++
        ("a" ** 480);
    const concurrent_b = "h1-concurrent-b-h1-concurrent-b-" ++
        ("b" ** 480);
    var concurrent_first = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 context takeover spans runtime API shapes" {
    const allocator = std.testing.allocator;
    const context_payload =
        "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    const fallback_payload = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .client_max_window_bits = 9,
                .server_max_window_bits = 9,
                .compression_threshold = 0,
            });
            defer connection.close();
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                connection.compression_send_max_window_bits,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                connection.compression_receive_max_window_bits,
            );

            // Expansion fallback must discard its preview. If the first
            // plaintext were retained, the identical second payload would
            // become a tiny context-reference frame instead of plain wire.
            for (0..2) |_| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(!frame.header.rsv1);
                try std.testing.expectEqualSlices(u8, &fallback_payload, frame.payload);
            }

            var first_wire: std.ArrayList(u8) = .empty;
            defer first_wire.deinit(server_ptr.http.allocator);
            for (0..3) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try first_wire.appendSlice(
                    server_ptr.http.allocator,
                    frame.payload,
                );
            }
            const first_plain = try websocket.decompressMessage(
                server_ptr.http.allocator,
                first_wire.items,
                context_payload.len,
            );
            defer server_ptr.http.allocator.free(first_plain);
            try std.testing.expectEqualStrings(context_payload, first_plain);

            var dependent = try connection.receiveFrame();
            defer dependent.deinit(server_ptr.http.allocator);
            try std.testing.expect(dependent.header.rsv1);
            try std.testing.expectError(
                error.InvalidFrame,
                websocket.decompressMessage(
                    server_ptr.http.allocator,
                    dependent.payload,
                    context_payload.len,
                ),
            );

            var progress: MessageWriteProgress = .{};
            try connection.sendFragmentedWithDeadline(
                .text,
                &.{
                    context_payload[0..71],
                    context_payload[71..173],
                    context_payload[173..],
                },
                &progress,
                .fromNow(server_ptr.http.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            try std.testing.expect(progress.frame_committed);
            try connection.sendBinarySlices(&.{
                context_payload[0..97],
                "",
                context_payload[97..],
            });

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/context-takeover",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .client_max_window_bits = 9,
        .server_max_window_bits = 9,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_receive_max_window_bits,
    );
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_send_max_window_bits,
    );

    try client.sendBinary(&fallback_payload);
    try client.sendBinary(&fallback_payload);
    var send_progress: MessageWriteProgress = .{};
    try client.sendFragmentedWithDeadline(
        .text,
        &.{
            context_payload[0..83],
            context_payload[83..199],
            context_payload[199..],
        },
        &send_progress,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    try std.testing.expect(send_progress.frame_committed);
    try client.sendBinarySlices(&.{
        context_payload[0..101],
        "",
        context_payload[101..],
    });

    var first_response = try client.receiveMessage();
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first_response.opcode);
    try std.testing.expectEqualStrings(context_payload, first_response.payload);
    var caller_storage: [4096]u8 = undefined;
    const second_response = try client.receiveMessageInto(&caller_storage);
    try std.testing.expectEqual(websocket.Opcode.binary, second_response.opcode);
    try std.testing.expectEqualStrings(context_payload, second_response.payload);
    try std.testing.expect(second_response.was_compressed);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 extended CONNECT exchanges messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();

            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .protocols = &.{"chat.v1"},
                .enable_permessage_deflate = true,
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
            });
            defer ws.close();
            try std.testing.expectEqualStrings("chat.v1", ws.selected_protocol.?);
            try std.testing.expect(ws.permessage_deflate);
            try std.testing.expect(!ws.compression_send_context_takeover);
            try std.testing.expect(!ws.compression_receive_context_takeover);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.allocator);
            for (0..3) |index| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.allocator.free(request);
            try std.testing.expectEqualStrings(
                "hello \xe2\x82\xac over h2 websocket hello over h2 websocket",
                request,
            );

            try ws.sendFragmented(.text, &.{
                "world over h2 websocket ",
                "world over h2 websocket",
            });

            const ConcurrentSender = struct {
                connection: *H2Connection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            const concurrent_a = "h2-concurrent-a-h2-concurrent-a-" ++
                ("a" ** 480);
            const concurrent_b = "h2-concurrent-b-h2-concurrent-b-" ++
                ("b" ** 480);
            var start: std.Io.Event = .unset;
            var senders = [_]ConcurrentSender{
                .{
                    .connection = &ws,
                    .io = server_ptr.io,
                    .start = &start,
                    .payload = concurrent_a,
                },
                .{
                    .connection = &ws,
                    .io = server_ptr.io,
                    .start = &start,
                    .payload = concurrent_b,
                },
            };
            const sender_a = try std.Thread.spawn(
                .{},
                ConcurrentSender.run,
                .{&senders[0]},
            );
            const sender_b = std.Thread.spawn(
                .{},
                ConcurrentSender.run,
                .{&senders[1]},
            ) catch |err| {
                start.set(server_ptr.io);
                sender_a.join();
                return err;
            };
            start.set(server_ptr.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            // The h2 WebSocket adapter still runs the normal RFC 6455 close
            // handshake inside DATA frames and maps the final Close write to
            // END_STREAM on the underlying HTTP/2 tunnel.
            try std.testing.expectError(error.ConnectionClosed, ws.receiveMessage());
            try std.testing.expect(ws.close_received.load(.acquire));
            try std.testing.expect(ws.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();

    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/chat",
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer ws_client.close();
    try std.testing.expectEqualStrings("chat.v1", ws_client.selected_protocol.?);
    try std.testing.expect(ws_client.permessage_deflate);
    try std.testing.expect(!ws_client.compression_send_context_takeover);
    try std.testing.expect(!ws_client.compression_receive_context_takeover);

    try ws_client.sendFragmented(.text, &.{
        "hello \xe2",
        "\x82",
        "\xac over h2 websocket hello over h2 websocket",
    });
    var response_storage: [4096]u8 = undefined;
    const response = try ws_client.receiveMessageIntoWithDeadline(
        &response_storage,
        .fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings(
        "world over h2 websocket world over h2 websocket",
        response.payload,
    );
    const concurrent_a = "h2-concurrent-a-h2-concurrent-a-" ++
        ("a" ** 480);
    const concurrent_b = "h2-concurrent-b-h2-concurrent-b-" ++
        ("b" ** 480);
    var concurrent_first = try ws_client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try ws_client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);

    try ws_client.sendClose(.normal_closure, "bye");
    try std.testing.expectError(error.ConnectionClosed, ws_client.receiveMessage());
    try std.testing.expect(ws_client.close_received.load(.acquire));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 context takeover spans runtime API shapes" {
    const allocator = std.testing.allocator;
    const context_payload =
        "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    const fallback_payload = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .client_max_window_bits = 9,
                .server_max_window_bits = 9,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                },
            });
            defer ws.close();
            try std.testing.expect(ws.permessage_deflate);
            try std.testing.expect(ws.compression_send_context_takeover);
            try std.testing.expect(ws.compression_receive_context_takeover);
            try std.testing.expectEqual(
                @as(u8, 9),
                ws.compression_send_max_window_bits,
            );
            try std.testing.expectEqual(
                @as(u8, 9),
                ws.compression_receive_max_window_bits,
            );

            // Expansion fallback must not enter the compression history.
            for (0..2) |_| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(!frame.header.rsv1);
                try std.testing.expectEqualSlices(u8, &fallback_payload, frame.payload);
            }

            var first_wire: std.ArrayList(u8) = .empty;
            defer first_wire.deinit(server_ptr.allocator);
            for (0..3) |index| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try first_wire.appendSlice(server_ptr.allocator, frame.payload);
            }
            const first_plain = try websocket.decompressMessage(
                server_ptr.allocator,
                first_wire.items,
                context_payload.len,
            );
            defer server_ptr.allocator.free(first_plain);
            try std.testing.expectEqualStrings(context_payload, first_plain);

            var dependent = try ws.receiveFrame();
            defer dependent.deinit(server_ptr.allocator);
            try std.testing.expect(dependent.header.rsv1);
            try std.testing.expectError(
                error.InvalidFrame,
                websocket.decompressMessage(
                    server_ptr.allocator,
                    dependent.payload,
                    context_payload.len,
                ),
            );

            var progress: MessageWriteProgress = .{};
            try ws.sendFragmentedWithDeadline(
                .text,
                &.{
                    context_payload[0..71],
                    context_payload[71..173],
                    context_payload[173..],
                },
                &progress,
                .fromNow(server_ptr.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            try std.testing.expect(progress.frame_committed);
            try ws.sendBinarySlices(&.{
                context_payload[0..97],
                "",
                context_payload[97..],
            });
            try ws.sendText(context_payload);

            var close = try ws.receiveFrame();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/context-takeover",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .client_max_window_bits = 9,
        .server_max_window_bits = 9,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_receive_max_window_bits,
    );
    try std.testing.expectEqual(
        @as(u8, 9),
        client.compression_send_max_window_bits,
    );

    try client.sendBinary(&fallback_payload);
    try client.sendBinary(&fallback_payload);
    var send_progress: MessageWriteProgress = .{};
    try client.sendFragmentedWithDeadline(
        .text,
        &.{
            context_payload[0..83],
            context_payload[83..199],
            context_payload[199..],
        },
        &send_progress,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    try std.testing.expect(send_progress.frame_committed);
    try client.sendBinarySlices(&.{
        context_payload[0..101],
        "",
        context_payload[101..],
    });

    var first_response = try client.receiveMessage();
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first_response.opcode);
    try std.testing.expectEqualStrings(context_payload, first_response.payload);
    var caller_storage: [4096]u8 = undefined;
    const second_response = try client.receiveMessageInto(&caller_storage);
    try std.testing.expectEqual(websocket.Opcode.binary, second_response.opcode);
    try std.testing.expectEqualStrings(context_payload, second_response.payload);
    try std.testing.expect(second_response.was_compressed);
    var third_response = try client.receiveFrame();
    defer third_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, third_response.header.opcode);
    try std.testing.expect(third_response.header.rsv1);
    try std.testing.expect(third_response.header.fin);
    try std.testing.expectError(
        error.InvalidFrame,
        websocket.decompressMessage(
            allocator,
            third_response.payload,
            context_payload.len,
        ),
    );
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 close abandons unfinished stream and permits reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 1,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();

            var first = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            const first_stream_id = first.tunnel.stream_id;
            first.close();
            var reset = try h2.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(first_stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );

            var second = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer second.close();
            var message = try second.receiveMessageWithTimeout(
                .fromSeconds(1),
            );
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("second", message.payload);
            try std.testing.expectError(
                error.ConnectionClosed,
                second.receiveMessageWithTimeout(.fromSeconds(1)),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();

    var first = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/abandoned",
    });
    first.close();

    var second = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/reused",
    });
    var second_live = true;
    defer if (second_live) second.close();
    try second.sendText("second");
    try second.sendClose(.normal_closure, "done");
    var close = try second.receiveFrameWithTimeout(.fromSeconds(1));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqualStrings(
        "done",
        (try websocket.parseClosePayload(close.payload)).?.reason,
    );
    second.close();
    second_live = false;

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(h2_client.isReusable());
}

test "WebSocket HTTP2 abrupt END_STREAM aborts only its tunnel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 2,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        first_stream_id: u31 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var first = try H2Server.accept(self.server.allocator, &h2, .{});
            defer first.close();
            self.first_stream_id = first.tunnel.stream_id;
            try std.testing.expectError(
                error.ConnectionClosed,
                first.receiveMessageWithTimeout(.fromSeconds(2)),
            );
            try std.testing.expect(testing.receiveStorageReleased(&first));
            try std.testing.expect(testing.writeAborted(&first));
            try std.testing.expect(testing.outboundStorageReleased(&first));
            try std.testing.expectError(
                error.ConnectionClosed,
                first.sendText("late"),
            );

            var sibling = try H2Server.accept(self.server.allocator, &h2, .{});
            defer sibling.close();
            var message = try sibling.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("sibling", message.payload);
            try sibling.sendClose(.normal_closure, "done");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 2,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();
    var first = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/abrupt-end",
    });
    defer first.close();
    try testing.writeFrame(&first, .text, "partial", false);
    try first.tunnel.closeWrite();
    var reset = try h2_client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(first.tunnel.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    var sibling = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/sibling",
    });
    defer sibling.close();
    try sibling.sendText("sibling");
    var close = try sibling.receiveFrameWithTimeout(.fromSeconds(2));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try sibling.sendClose(.normal_closure, "done");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(first.tunnel.stream_id, shared.first_stream_id);
    try std.testing.expect(h2_client.isReusable());
}

test "WebSocket HTTP2 handshake timeout bounds CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequestWithTimeout(
                "websocket",
                .fromSeconds(1),
            );
            defer request.deinit(self.server.allocator);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            allocator,
            &h2_client,
            .{
                .authority = "localhost",
                .path = "/slow-response",
            },
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(!h2_client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 server handshake resumes after idle timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        io: std.Io,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            try std.testing.expectError(
                error.Timeout,
                H2Server.acceptWithTimeout(
                    self.server.allocator,
                    &h2,
                    .{},
                    .fromMilliseconds(30),
                ),
            );
            self.timed_out.set(self.io);

            var ws = try H2Server.acceptWithTimeout(
                self.server.allocator,
                &h2,
                .{},
                .fromSeconds(1),
            );
            defer ws.close();
            try ws.sendText("accepted-after-timeout");
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try shared.timed_out.wait(io);
    if (shared.err) |err| return err;
    var ws_client = try H2Client.openWithTimeout(
        allocator,
        &h2_client,
        .{ .authority = "localhost", .path = "/after-timeout" },
        .fromSeconds(1),
    );
    defer ws_client.close();
    var message = try ws_client.receiveMessageWithTimeout(.fromSeconds(1));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings(
        "accepted-after-timeout",
        message.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 timeout APIs reject non-positive budgets" {
    var connection: http2_runtime.Connection = undefined;
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        H2Server.acceptWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
}

test "WebSocket client rejects unoffered subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(
                server_ptr.http.allocator,
                head.head,
                http1HandshakeRequestParseOptions(server_ptr.limits),
            );
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try websocket.writeServerHandshake(&response, server_ptr.http.allocator, key, &.{.{ .name = "Sec-WebSocket-Protocol", .value = "not-offered" }});
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidSubprotocol, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/bad-subprotocol",
        .protocols = &.{"superchat"},
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client rejects HTTP/1.0 upgrade responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(
                server_ptr.http.allocator,
                head.head,
                http1HandshakeRequestParseOptions(server_ptr.limits),
            );
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            const accept = websocket.acceptKey(key);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try response.appendSlice(server_ptr.http.allocator, "HTTP/1.0 101 Switching Protocols\r\n");
            try response.appendSlice(server_ptr.http.allocator, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
            try response.appendSlice(server_ptr.http.allocator, &accept);
            try response.appendSlice(server_ptr.http.allocator, "\r\n\r\n");
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidVersion, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/http10-response",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket server rejects data sent with HTTP upgrade request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                if (err == error.InvalidHandshake) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            connection.close();
            shared.err = error.InvalidHandshake;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try request.appendSlice(
        allocator,
        "GET /early HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try websocket.writeFrame(&request, allocator, .text, "too early", .{ .mask_key = .{ 1, 2, 3, 4 } });
    try writeAllToStream(io, stream, request.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "WebSocket over HTTP/2 receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrameAuto();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("h2-auto?", ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer ws_client.close();

    try ws_client.sendPing("h2-auto?");
    var pong = try ws_client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("h2-auto?", pong.payload);
    try ws_client.sendClose(.normal_closure, "bye");
    var close = try ws_client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 control sends do not retain frame scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/control-stack",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("stack");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("stack", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 application frames avoid retained send scratch" {
    const allocator = std.testing.allocator;
    const payload = "borrowed-rfc8441-payload-" ** 700;
    const trailing_empty_parts = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "",
        "",
    };
    const trailing_empty_payload = "0123456789abcde";
    const h2_limits: http2_runtime.Limits = .{
        // An 8-KiB stream window makes each sender wait for several peer
        // WINDOW_UPDATE frames. It also places the WebSocket header/payload
        // join inside the first DATA frame, while a message larger than the
        // 16-KiB masking buffer verifies continuity across stack chunks.
        .initial_window_size = 8 * 1024,
        .max_body_bytes = payload.len + websocket.max_frame_header_len,
        .enable_connect_protocol = true,
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h2_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload.len,
                    .max_message_bytes = payload.len,
                },
            });
            defer ws.close();

            var empty = try ws.receiveFrame();
            defer empty.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, empty.header.opcode);
            try std.testing.expect(empty.header.fin);
            try std.testing.expectEqual(@as(usize, 0), empty.payload.len);
            var request = try ws.receiveFrame();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.header.opcode);
            try std.testing.expect(request.header.fin);
            try std.testing.expectEqualStrings(payload, request.payload);
            try ws.sendBinarySlices(&.{});
            try ws.sendBinarySlices(&.{
                payload[0..7],
                "",
                payload[7..19],
                payload[19..],
            });
            try ws.sendBinarySlices(&trailing_empty_parts);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        h2_limits,
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/borrowed-frame",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendBinarySlices(&.{});
    try client.sendBinarySlices(&.{
        payload[0..13],
        "",
        payload[13..41],
        payload[41..],
    });
    var empty = try client.receiveFrame();
    defer empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, empty.header.opcode);
    try std.testing.expect(empty.header.fin);
    try std.testing.expectEqual(@as(usize, 0), empty.payload.len);
    var message = try client.receiveFrame();
    defer message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, message.header.opcode);
    try std.testing.expect(message.header.fin);
    try std.testing.expectEqualStrings(payload, message.payload);
    var trailing_empty = try client.receiveFrame();
    defer trailing_empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, trailing_empty.header.opcode);
    try std.testing.expect(trailing_empty.header.fin);
    try std.testing.expectEqualStrings(
        trailing_empty_payload,
        trailing_empty.payload,
    );
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 in-place binary send masks and roundtrips" {
    const allocator = std.testing.allocator;
    const original = "mutable-rfc8441-payload";

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var h2 = try shared.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(shared.server.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(original, request.payload);
            try ws.sendText("in-place-received");
            var close = try ws.receiveFrameAuto();
            defer close.deinit(shared.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/in-place",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();

    var payload = original.*;
    try client.sendBinaryInPlace(&payload);
    try std.testing.expect(!std.mem.eql(u8, original, &payload));
    var confirmation = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer confirmation.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, confirmation.opcode);
    try std.testing.expectEqualStrings("in-place-received", confirmation.payload);
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed binary parts preserve one message" {
    const allocator = std.testing.allocator;
    const first = "h2-compressed-prefix-";
    const second = "compressible-borrowed-payload-" ** 64;
    const expected = first ++ second;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = expected.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = expected.len,
                    .max_message_bytes = expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(expected, request.payload);
            try ws.sendBinarySlices(&.{ first, "", second[0..17], second[17..] });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = expected.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-binary-parts",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = expected.len,
            .max_message_bytes = expected.len,
        },
    });
    defer client.close();

    try client.sendBinarySlices(&.{ first, second[0..17], "", second[17..] });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
    try std.testing.expectEqualStrings(expected, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed fragments reuse bounded send storage" {
    const allocator = std.testing.allocator;
    const payload_len = 64 * 1024;
    var payload: [payload_len]u8 = undefined;
    var random_state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (payload[0 .. payload.len / 2]) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 7;
        random_state ^= random_state << 17;
        byte.* = @truncate(random_state);
    }
    @memcpy(payload[payload.len / 2 ..], payload[0 .. payload.len / 2]);
    const fragments = [_][]const u8{
        payload[0..7000],
        payload[7000..28_000],
        payload[28_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload_len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload_len,
                    .max_message_bytes = payload_len,
                },
            });
            defer ws.close();

            for (0..2) |iteration| {
                var request = try ws.receiveMessage();
                defer request.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    websocket.Opcode.binary,
                    request.opcode,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    shared.expected,
                    request.payload,
                );
                const response_fragments = [_][]const u8{
                    request.payload[0..7000],
                    request.payload[7000..28_000],
                    request.payload[28_000..],
                };
                if (iteration == 0) {
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(
                        ws.compression_send.payload.items.len >
                            masked_write_scratch_len,
                    );
                } else {
                    var failing = std.testing.FailingAllocator.init(
                        server_ptr.allocator,
                        .{},
                    );
                    ws.allocator = failing.allocator();
                    defer ws.allocator = server_ptr.allocator;
                    failing.fail_index = failing.alloc_index;
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(!failing.has_induced_failure);
                }
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload_len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-fragments-no-send-buffer",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();

    for (0..2) |iteration| {
        if (iteration == 0) {
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(
                client.compression_send.payload.items.len >
                    masked_write_scratch_len,
            );
        } else {
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            client.allocator = failing.allocator();
            defer client.allocator = allocator;
            failing.fail_index = failing.alloc_index;
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(!failing.has_induced_failure);
        }
        var response = try client.receiveMessage();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
        try std.testing.expectEqualSlices(u8, &payload, response.payload);
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 uncompressed fragments use bounded send storage" {
    const allocator = std.testing.allocator;
    var payload: [40 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 131);
    const fragments = [_][]const u8{
        payload[0..9000],
        payload[9000..25_000],
        payload[25_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = shared.expected.len,
                    .max_message_bytes = shared.expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                request.payload,
            );
            try ws.sendFragmented(.binary, &.{
                request.payload[0..9000],
                request.payload[9000..25_000],
                request.payload[25_000..],
            });
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/uncompressed-fragments-bounded",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendFragmented(.binary, &fragments);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &payload, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 deadline spans control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var h2 = try shared.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                shared.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var storage: [4096]u8 = undefined;
            _ = ws.receiveMessageIntoWithDeadline(
                &storage,
                .fromNow(
                    shared.server.io,
                    .{ .raw = .fromMilliseconds(300), .clock = .awake },
                ),
            ) catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/deadline",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer ws_client.close();
    for (0..2) |_| {
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
        try ws_client.sendPing("keep-http2-busy");
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
}

test "WebSocket receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrameAuto();
            defer ping.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("auto?", ping.payload);
            var close = try connection.receiveFrameAuto();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("auto?");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("auto?", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket pingWithDeadline preserves an interleaved message" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try connection.sendText("in flight");
            try connection.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-deadline",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    var application = try client.pingWithDeadline("probe", deadline);
    defer application.deinit(allocator);
    switch (application) {
        .application => |frame| {
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expectEqualStrings("in flight", frame.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    var pong = try client.continuePingWithTimeout(
        "probe",
        .fromSeconds(1),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout skips unsolicited Pong before its matching reply" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendPong("wrong");
            try connection.sendPong(ping.payload);
            try connection.sendBinary("after probe");
            try std.testing.expectError(error.Timeout, connection.receiveFrameWithTimeout(.fromMilliseconds(30)));
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/wrong-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    var event = try client.pingWithTimeout("probe", .fromSeconds(1));
    defer event.deinit(allocator);
    try std.testing.expect(event == .pong);
    var following = try client.receiveMessageWithTimeout(.fromSeconds(1));
    defer following.deinit(allocator);
    try std.testing.expectEqualStrings("after probe", following.payload);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout reports peer Close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendClose(.going_away, "maintenance");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    var event = try client.pingWithTimeout("probe", .fromSeconds(1));
    defer event.deinit(allocator);
    switch (event) {
        .closed => |maybe_close| {
            const close = maybe_close orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(websocket.CloseCode.going_away, close.code);
            try std.testing.expectEqualStrings("maintenance", close.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout enforces one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.Io.sleep(self.server.http.io, .fromMilliseconds(80), .awake);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-timeout",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout("probe", .fromMilliseconds(20)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP2 pingWithTimeout validates Pong" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-ping-timeout",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    var event = try client.pingWithTimeout("h2-probe", .fromSeconds(1));
    defer event.deinit(allocator);
    try std.testing.expect(event == .pong);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveFrameAuto does not pong after sending close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x89\x01?");
    var ping = try connection.receiveFrameAuto();
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings("?", ping.payload);

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x89\x01?");
    var h2_ping = try h2.receiveFrameAuto();
    defer h2_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, h2_ping.header.opcode);
    try std.testing.expectEqualStrings("?", h2_ping.payload);
}

test "WebSocket runtime exposes typed close frames" {
    const allocator = std.testing.allocator;

    var backend = try @import("../../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendCloseFrame(.{ .code = .going_away, .reason = "restart" });

            var ack = (try connection.receiveCloseFrame()).?;
            defer ack.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.CloseCode.normal_closure, ack.code);
            try std.testing.expectEqualStrings("ack", ack.reason);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/typed-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var close_frame = (try client.receiveCloseFrame()).?;
    defer close_frame.deinit(allocator);
    try std.testing.expectEqual(websocket.CloseCode.going_away, close_frame.code);
    try std.testing.expectEqualStrings("restart", close_frame.reason);
    try client.sendCloseFrame(.{ .code = .normal_closure, .reason = "ack" });

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage assembles fragments and handles control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("hello fragmented", message.payload);

            try connection.sendFragmented(
                .text,
                &.{ "server ", "", "fragmented" },
            );

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_received.load(.acquire));
            try std.testing.expect(connection.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("?");
    const fragments = [_][]const u8{
        "h", "e", "l", "l", "o", " ", "f", "r",
        "a", "g", "m", "e", "n", "t", "e", "d",
    };
    try client.sendFragmented(.text, &fragments);

    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("?", pong.payload);

    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("server fragmented", response.payload);

    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 abrupt EOF releases receive state and blocks writes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.receiveMessageWithTimeout(.fromSeconds(1)),
            );
            try std.testing.expect(testing.receiveStorageReleased(&connection));
            try std.testing.expect(testing.writeAborted(&connection));
            try std.testing.expect(testing.outboundStorageReleased(&connection));
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.sendText("late"),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/abrupt-eof",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try testing.writeFrame(&client, .text, "partial", false);
    try client.stream.shutdown(io, .send);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage enforces aggregate fragmented message limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 12 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try std.testing.expectError(error.PayloadTooLarge, connection.receiveMessage());
            try std.testing.expect(connection.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message-limit",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();

    const fragments = [_][]const u8{ "12345678", "abcdef" };
    try client.sendFragmented(.text, &fragments);

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqual(
        websocket.CloseCode.message_too_big,
        (try websocket.parseClosePayload(close.payload)).?.code,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage allows in-flight data after initiating close" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendClose(.normal_closure, "draining");

            // Like tungstenite, initiating the close handshake only closes our
            // write side.  Data already sent by the peer is still readable
            // until its close acknowledgement arrives.
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("already in flight", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_sent.load(.acquire));
            try std.testing.expect(connection.close_received.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/close-after-send",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("already in flight");

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try client.sendClose(.normal_closure, "ack");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtimes validate outgoing text and close frames" {
    const allocator = std.testing.allocator;
    const bad_utf8 = "\xc0\x80";
    const too_large_control = "x" ** 126;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, connection.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, connection.sendFragmented(.text, &.{ "\xe2", "(" }));
    try std.testing.expectError(error.InvalidUtf8, connection.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, connection.sendClose(.no_status_received, ""));
    try std.testing.expectError(error.InvalidControlFrame, connection.sendPing(too_large_control));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.text, "bypass"));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.continuation, "bypass"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, h2.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, h2.sendFragmented(.text, &.{ "\xf0\x9f", "\x28" }));
    try std.testing.expectError(error.InvalidUtf8, h2.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, h2.sendClose(.abnormal_closure, ""));
    try std.testing.expectError(error.InvalidControlFrame, h2.sendPong(too_large_control));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.binary, "bypass"));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.continuation, "bypass"));
}

test "WebSocket caller-buffer receive rejects API mixing without failing connection" {
    const allocator = std.testing.allocator;
    var out: [16]u8 = undefined;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_message_bytes = out.len },
        .message_assembler = websocket.MessageAssembler.initLimited(
            allocator,
            out.len,
        ),
    };
    defer if (connection.message_assembler) |*assembler| assembler.deinit();
    try std.testing.expectError(
        error.InvalidFrame,
        connection.receiveMessageInto(&out),
    );
    try std.testing.expect(!connection.receiveFailed());
    try std.testing.expect(!connection.closeSent());
    try std.testing.expect(connection.message_assembler != null);

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .limits = .{ .max_message_bytes = out.len },
        .message_assembler = websocket.MessageAssembler.initLimited(
            allocator,
            out.len,
        ),
    };
    defer if (h2.message_assembler) |*assembler| assembler.deinit();
    try std.testing.expectError(
        error.InvalidFrame,
        h2.receiveMessageInto(&out),
    );
    try std.testing.expect(!h2.receiveFailed());
    try std.testing.expect(!h2.closeSent());
    try std.testing.expect(h2.message_assembler != null);
}

test "WebSocket HTTP1 and HTTP2 sends enforce configured outbound limits" {
    const limits: Limits = .{
        .max_frame_bytes = 4,
        .max_message_bytes = 6,
    };

    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = common.MessageLimits.from(limits),
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendText("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinaryParts("abc", "de"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinarySlices(&.{ "a", "", "bc", "de" }),
    );
    connection.permessage_deflate = false;
    var in_place_payload = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinaryInPlace(&in_place_payload),
    );
    connection.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendPing("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendClose(.normal_closure, "abc"),
    );

    var h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = common.MessageLimits.from(limits),
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinary("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinaryParts("abc", "de"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinarySlices(&.{ "a", "", "bc", "de" }),
    );
    h2.permessage_deflate = false;
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinaryInPlace(&in_place_payload),
    );
    h2.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendPong("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendClose(.normal_closure, "abc"),
    );
}

test "WebSocket runtimes reject duplicate close sends" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, connection.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, "again"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, h2.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, h2.sendClose(.normal_closure, "again"));
}

test "WebSocket writers retain close-state guards inside send lock" {
    // Public writers perform cheap argument/state validation before blocking,
    // then use this post-lock guard to close the race with an earlier writer
    // that committed Close while they waited. Exercise both stream adapters
    // without constructing an unrelated transport.
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expect(!connection.canSendOpcodeLocked(.text));

    var h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expect(!h2.canSendOpcodeLocked(.text));

    var failed = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .receive_failed = .init(true),
    };
    try std.testing.expect(!failed.canSendOpcodeLocked(.text));
    try std.testing.expect(!failed.canSendOpcodeLocked(.close));
    try std.testing.expectError(error.ConnectionClosed, failed.sendText("x"));
    try std.testing.expectError(
        error.ConnectionClosed,
        failed.updateTrafficKeys(false),
    );

    var failed_h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .receive_failed = .init(true),
    };
    try std.testing.expect(!failed_h2.canSendOpcodeLocked(.text));
    try std.testing.expect(!failed_h2.canSendOpcodeLocked(.close));
    try std.testing.expectError(error.ConnectionClosed, failed_h2.sendText("x"));
}

test "WebSocket HTTP2 pending tunnel data uses parent allocator" {
    var parent_gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(parent_gpa.deinit() == .ok) catch
        @panic("parent allocator leak");
    var adapter_gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(adapter_gpa.deinit() == .ok) catch
        @panic("adapter allocator leak");
    const parent_allocator = parent_gpa.allocator();
    const adapter_allocator = adapter_gpa.allocator();

    var parent = http2_runtime.Connection{
        .io = undefined,
        .allocator = parent_allocator,
        .stream = undefined,
        .role = .client,
    };
    const first_bytes = try parent_allocator.dupe(u8, "parent-close");
    var close_connection = H2Connection{
        .allocator = adapter_allocator,
        .tunnel = .{ .connection = &parent, .stream_id = 1 },
        .role = .client,
        .pending_tunnel_data = .{
            .frame = .{
                .bytes = first_bytes,
                .frame = .{
                    .header = .{
                        .length = @intCast(first_bytes.len),
                        .frame_type = .data,
                        .flags = 0,
                        .stream_id = 1,
                    },
                    .payload = first_bytes,
                },
            },
            .data = first_bytes,
            .end_stream = false,
        },
    };
    close_connection.close();

    const second_bytes = try parent_allocator.dupe(u8, "parent-fatal");
    var failed_connection = H2Connection{
        .allocator = adapter_allocator,
        .tunnel = .{ .connection = &parent, .stream_id = 3 },
        .role = .client,
        .pending_tunnel_data = .{
            .frame = .{
                .bytes = second_bytes,
                .frame = .{
                    .header = .{
                        .length = @intCast(second_bytes.len),
                        .frame_type = .data,
                        .flags = 0,
                        .stream_id = 3,
                    },
                    .payload = second_bytes,
                },
            },
            .data = second_bytes,
            .end_stream = false,
        },
    };
    try std.testing.expect(failReceive(&failed_connection));
    try std.testing.expect(testing.receiveStorageReleased(&failed_connection));
    failed_connection.close();
}

test "WebSocket HTTP2 in-place send rejects unsupported modes" {
    var server = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .server,
    };
    var payload = [_]u8{1};
    try std.testing.expectError(
        error.InvalidFrame,
        server.sendBinaryInPlace(&payload),
    );

    var compressed = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .permessage_deflate = true,
    };
    try std.testing.expectError(
        error.InvalidFrame,
        compressed.sendBinaryInPlace(&payload),
    );

    var closed = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(
        error.ConnectionClosed,
        closed.sendBinaryInPlace(&payload),
    );

    var too_small = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .limits = .{ .max_frame_bytes = 0, .max_message_bytes = 0 },
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        too_small.sendBinaryInPlace(&payload),
    );
}

test "WebSocket send state blocks data after receiving close" {
    try std.testing.expect(!canSendOpcode(.text, false, true));
    try std.testing.expect(!canSendOpcode(.binary, false, true));
    try std.testing.expect(!canSendOpcode(.ping, false, true));
    try std.testing.expect(canSendOpcode(.close, false, true));
    try std.testing.expect(!canSendOpcode(.close, true, true));
}

test "WebSocket runtimes reject frames after received close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var close = try connection.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var h2_close = try h2.receiveFrame();
    defer h2_close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, h2_close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
}

test "WebSocket runtimes return closed after close handshake completes" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
        .close_received = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
        .close_received = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, h2.receiveMessage());
}

test "WebSocket async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), connection: *Connection) Error!void {
            var frame = try connection.receiveFrame();
            defer frame.deinit(connection.allocator);
            if (frame.header.opcode != .text) return error.ProtocolFailure;
            if (std.mem.eql(u8, frame.payload, "one")) {
                try connection.sendText("echo-one");
            } else if (std.mem.eql(u8, frame.payload, "two")) {
                try connection.sendText("echo-two");
            } else {
                try connection.sendClose(.unsupported_data, "unexpected");
            }

            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            if (close.header.opcode != .close) return error.ProtocolFailure;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{}) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        payload: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .host = "127.0.0.1",
                .target = "/async",
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer client.close();

            try client.sendText(task.payload);
            var response = try client.receiveFrame();
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
            try std.testing.expectEqualStrings(task.expected, response.payload);
            try client.sendClose(.normal_closure, "bye");
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "one", .expected = "echo-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "two", .expected = "echo-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "WebSocket connection serializes concurrent sends" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn sendOne(connection: *Connection, payload: []const u8, err: *?anyerror) void {
            connection.sendText(payload) catch |e| {
                err.* = e;
            };
        }

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var err_a: ?anyerror = null;
            var err_b: ?anyerror = null;
            const thread_a = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-a", &err_a });
            const thread_b = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-b", &err_b });
            thread_a.join();
            thread_b.join();
            if (err_a) |err| return err;
            if (err_b) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/send-lock",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var first = try client.receiveFrame();
    defer first.deinit(allocator);
    var second = try client.receiveFrame();
    defer second.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first.header.opcode);
    try std.testing.expectEqual(websocket.Opcode.text, second.header.opcode);
    const saw_a = std.mem.eql(u8, first.payload, "from-a") or std.mem.eql(u8, second.payload, "from-a");
    const saw_b = std.mem.eql(u8, first.payload, "from-b") or std.mem.eql(u8, second.payload, "from-b");
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test {
    _ = @import("message/tests/close_ownership.zig");
    _ = @import("message/tests/automatic_preparation.zig");
    _ = @import("control/ping_tests.zig");
    _ = h3;
    _ = @import("message/tests/buffer.zig");
    _ = @import("message/tests/state.zig");
    _ = @import("handshake/capacity_tests.zig");
    _ = @import("handshake/h1_attempt_tests.zig");
    _ = @import("handshake/h2_admission_tests.zig");
    _ = @import("cookie_h2_tests.zig");
    _ = @import("cookie_h3_tests.zig");
    _ = @import("h3_tests.zig");
    _ = @import("h3_recovery_tests.zig");
    _ = @import("unix_tests.zig");
    _ = @import("error_close_tests.zig");
    _ = @import("transport_end_tests.zig");
    _ = @import("transport_end_h2_tests.zig");
    _ = @import("receive_failure_tests.zig");
    _ = @import("receive_failure/deadline_tests.zig");
    _ = @import("receive_failure/writer_lifetime_tests.zig");
    _ = @import("receive_failure/multiplex_tests.zig");
    _ = @import("receive_failure/cleanup_tests.zig");
    _ = @import("receive_failure/diagnostic_tests.zig");
    _ = @import("read_interruption_tests.zig");
    _ = @import("read_interruption_transport_tests.zig");
    _ = @import("write_interruption_tests.zig");
    _ = @import("mutex_deadline_tests.zig");
    _ = @import("control/admission_tests.zig");
    _ = @import("close_timeout_tests.zig");
    _ = @import("handshake_timeout_tests.zig");
    _ = @import("handshake/response_tests.zig");
    _ = @import("handshake/request_tests.zig");
    _ = @import("handshake/receive_tests.zig");
    _ = @import("handshake/body_limit_tests.zig");
    _ = @import("handshake/head_budget_tests.zig");
    _ = handshake_acceptance;
    _ = @import("message_io_tests.zig");
    _ = @import("message/tests/frame_allocation.zig");
    _ = @import("message/tests/assembly_allocation.zig");
    _ = @import("message/tests/caller_completion.zig");
    _ = @import("compression_scratch.zig");
    _ = @import("compression_threshold_tests.zig");
    _ = @import("compression/directional_tests.zig");
    _ = @import("compression/client_hint_tests.zig");
    _ = @import("wss_tests.zig");
    _ = @import("resolver_tests.zig");
    _ = @import("proxy_tests.zig");
    _ = @import("redirect_tests.zig");
    _ = @import("server_lifecycle_tests.zig");
    _ = @import("handshake_header_tests.zig");
}
