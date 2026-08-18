const std = @import("std");
const grpc = @import("mod.zig");
const http2 = @import("../http2/mod.zig");

const Status = grpc.Status;
const Timeout = grpc.Timeout;
const MessageIterator = grpc.MessageIterator;
const writeMessageInto = grpc.writeMessageInto;
const encodeStatusMessageAlloc = grpc.encodeStatusMessageAlloc;
const decodeStatusMessageAlloc = grpc.decodeStatusMessageAlloc;
const parseUnaryRequest = grpc.parseUnaryRequest;
const writeUnaryResponse = grpc.writeUnaryResponse;
const unaryCall = grpc.unaryCall;
const statusFromHttp = grpc.statusFromHttp;

fn findHeader(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

test "gRPC message framing round trips and enforces bounds" {
    var storage: [16]u8 = undefined;
    const encoded = try writeMessageInto(
        &storage,
        "hello",
        false,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 5 },
        encoded[0..5],
    );
    var iterator = MessageIterator.init(encoded, 5);
    const message = (try iterator.next()).?;
    try std.testing.expect(!message.compressed);
    try std.testing.expectEqualStrings("hello", message.payload);
    try std.testing.expect(try iterator.next() == null);

    try std.testing.expectError(
        error.BufferTooSmall,
        writeMessageInto(storage[0..4], "", false),
    );
    var too_small = MessageIterator.init(encoded, 4);
    try std.testing.expectError(
        error.GrpcMessageTooLarge,
        too_small.next(),
    );
    var invalid_flag: [10]u8 = undefined;
    @memcpy(&invalid_flag, encoded);
    invalid_flag[0] = 2;
    var invalid = MessageIterator.init(&invalid_flag, 5);
    try std.testing.expectError(
        error.InvalidCompressedFlag,
        invalid.next(),
    );
    var truncated = MessageIterator.init(encoded[0..8], 5);
    try std.testing.expectError(
        error.BufferTooShort,
        truncated.next(),
    );
}

test "gRPC timeout status and percent-message codecs" {
    const second = try Timeout.parse("1S");
    try std.testing.expectEqual(
        @as(i96, std.time.ns_per_s),
        second.duration().toNanoseconds(),
    );
    var timeout_storage: [9]u8 = undefined;
    try std.testing.expectEqualStrings(
        "1500m",
        try (try Timeout.fromDuration(
            .fromMilliseconds(1500),
        )).formatInto(&timeout_storage),
    );
    try std.testing.expectError(
        error.InvalidTimeout,
        Timeout.parse("123456789S"),
    );
    const rounded = try Timeout.fromDuration(
        .fromNanoseconds(99_999_999 * std.time.ns_per_s + 1),
    );
    try std.testing.expect(
        rounded.duration().toNanoseconds() >=
            99_999_999 * std.time.ns_per_s + 1,
    );
    try std.testing.expectEqual(
        Status.unavailable,
        try Status.parse("14"),
    );
    try std.testing.expectError(
        error.InvalidGrpcStatus,
        Status.parse("014"),
    );

    const allocator = std.testing.allocator;
    const encoded = try encodeStatusMessageAlloc(
        allocator,
        "bad %\n",
    );
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("bad %25%0A", encoded);
    const decoded = try decodeStatusMessageAlloc(
        allocator,
        "bad%20value%XY",
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("bad value%XY", decoded);
}

test "gRPC unary call exchanges opaque protobuf bytes over HTTP/2" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            const call = try parseUnaryRequest(&request, 1024);
            try std.testing.expectEqualStrings(
                "demo.Echo",
                call.service,
            );
            try std.testing.expectEqualStrings("Unary", call.method);
            try std.testing.expectEqualStrings(
                "\x0a\x03zig",
                call.message.payload,
            );
            try std.testing.expectEqual(
                @as(i96, std.time.ns_per_s),
                call.timeout.?.duration().toNanoseconds(),
            );
            try writeUnaryResponse(
                &connection,
                server_ptr.allocator,
                call.stream_id,
                .{
                    .message = "\x0a\x04netz",
                    .trailing_metadata = &.{.{
                        .name = "server-meta",
                        .value = "ok",
                    }},
                },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );

    var client = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try unaryCall(&client, allocator, .{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "\x0a\x03zig",
        .timeout = try Timeout.init(1, .second),
    });
    defer response.deinit();

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings(
        "\x0a\x04netz",
        response.message.?.payload,
    );
    try std.testing.expectEqualStrings(
        "ok",
        findHeader(
            response.transport.trailers,
            "server-meta",
        ).?,
    );
}

test "gRPC unary call accepts trailers-only error and HTTP fallback" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            const call = try parseUnaryRequest(&request, 1024);
            try writeUnaryResponse(
                &connection,
                server_ptr.allocator,
                call.stream_id,
                .{
                    .status = .permission_denied,
                    .status_message = "not allowed %",
                    .trailing_metadata = &.{.{
                        .name = "failure-meta",
                        .value = "present",
                    }},
                    .trailers_only = true,
                },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );
    var client = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try unaryCall(&client, allocator, .{
        .path = "/demo.Auth/Check",
        .authority = "localhost",
        .message = "",
    });
    defer response.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        Status.permission_denied,
        response.status,
    );
    try std.testing.expectEqualStrings(
        "not allowed %",
        response.status_message,
    );
    try std.testing.expect(response.message == null);
    try std.testing.expectEqualStrings(
        "present",
        findHeader(
            response.transport.headers,
            "failure-meta",
        ).?,
    );

    try std.testing.expectEqual(
        Status.unavailable,
        statusFromHttp(503),
    );
}

test "gRPC validates custom metadata and HTTP fallback response" {
    try std.testing.expectError(
        error.CompressionNotNegotiated,
        grpc.validateMessageEncoding(
            .{ .compressed = true, .payload = "compressed" },
            null,
        ),
    );
    try std.testing.expectError(
        error.CompressionNotNegotiated,
        grpc.validateMessageEncoding(
            .{ .compressed = true, .payload = "compressed" },
            "identity",
        ),
    );
    try grpc.validateMessageEncoding(
        .{ .compressed = true, .payload = "compressed" },
        "gzip",
    );

    try std.testing.expectError(
        error.InvalidMetadata,
        grpc.validateCustomMetadata(&.{.{
            .name = "grpc-reserved",
            .value = "value",
        }}),
    );
    try std.testing.expectError(
        error.InvalidMetadata,
        grpc.validateCustomMetadata(&.{.{
            .name = "content-type",
            .value = "text/plain",
        }}),
    );

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            _ = try parseUnaryRequest(&first, 1024);
            try connection.writeResponse(first.stream_id, .{
                .status = 503,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "upstream unavailable",
            });
            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            _ = try parseUnaryRequest(&second, 1024);
            try connection.writeResponse(second.stream_id, .{
                .status = 503,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "application/grpc",
                }},
                // A broken intermediary can preserve the upstream content
                // type while replacing the body with an HTTP error entity.
                .body = "not a length-prefixed message",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );
    var client = try http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var text_response = try unaryCall(&client, allocator, .{
        .path = "/demo.Fallback/Call",
        .authority = "localhost",
        .message = "",
    });
    defer text_response.deinit();
    var grpc_response = try unaryCall(&client, allocator, .{
        .path = "/demo.Fallback/Call",
        .authority = "localhost",
        .message = "",
    });
    defer grpc_response.deinit();
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(Status.unavailable, text_response.status);
    try std.testing.expect(text_response.message == null);
    try std.testing.expectEqualStrings(
        "HTTP status 503 without grpc-status",
        text_response.status_message,
    );
    try std.testing.expectEqual(Status.unavailable, grpc_response.status);
    try std.testing.expect(grpc_response.message == null);
    try std.testing.expectEqualStrings(
        "HTTP status 503 without grpc-status",
        grpc_response.status_message,
    );
}
