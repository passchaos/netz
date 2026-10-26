const std = @import("std");
const web = @import("../web.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC-Web text accepts independently padded chunks inside one frame" {
    // A five-byte prefix flushed separately from its payload. Padding is a
    // text-buffer boundary, not a gRPC message boundary (PROTOCOL-WEB.md).
    const bytes = try web.base64DecodeAlloc(std.testing.allocator, "AAAAAAU=aGVsbG8=");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' }, bytes);
}

test "gRPC-Web body trailers reject reserved names and header injection" {
    const invalid = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "x-test", .value = "ok\r\ngrpc-status:0" },
        .{ .name = "X-Test", .value = "mixed case" },
        .{ .name = "x:invalid", .value = "value" },
        .{ .name = "x-test", .value = "embedded\x00nul" },
    };
    for (invalid) |field| {
        const result = web.buildTrailerBlock(std.testing.allocator, .{
            .status = .permission_denied,
            .trailing_metadata = &.{.{ .name = field.name, .value = field.value }},
        });
        if (result) |bytes| {
            std.testing.allocator.free(bytes);
            return error.TestExpectedError;
        } else |err| try std.testing.expectEqual(error.InvalidMetadata, err);
    }
}

test "gRPC-Web Accept selects response wire independently with HTTP quality rules" {
    const Case = struct { request_text: bool = false, accept: []const u8, response_text: bool };
    const cases = [_]Case{
        .{ .accept = "application/grpc-web-text", .response_text = true },
        .{ .request_text = true, .accept = "application/grpc-web+proto", .response_text = false },
        .{ .accept = "application/grpc-web;q=0.2, application/grpc-web-text;q=0.9", .response_text = true },
        .{ .accept = "*/*;q=1, application/grpc-web;q=0", .response_text = true },
        .{ .request_text = true, .accept = "application/*;q=0.8, application/grpc-web-text;q=0.1", .response_text = false },
        .{ .request_text = true, .accept = "*/*", .response_text = true },
        .{ .accept = "application/grpc-web-text;other=\"a,b;c\"; q=0.500", .response_text = true },
    };
    for (cases) |case| {
        const result = try web.negotiateResponseContentType(.{ .format = .proto, .text = case.request_text }, &.{.{ .name = "accept", .value = case.accept }});
        try std.testing.expectEqual(case.response_text, result.text);
        try std.testing.expectEqual(web.Format.proto, result.format);
    }
    const result = try web.negotiateResponseContentType(.{ .format = .json, .text = false }, &.{
        .{ .name = "Accept", .value = "application/grpc-web+json;q=0.2" },
        .{ .name = "accept", .value = "application/grpc-web-text+json" },
    });
    try std.testing.expect(result.text);
    try std.testing.expectEqual(web.Format.json, result.format);
    try std.testing.expect((try web.negotiateResponseContentType(.{ .format = .proto, .text = true }, &.{})).text);
    for ([_][]const u8{ "application/json", "application/grpc-web+json", "application/grpc-web;q=0, application/grpc-web-text;q=0" }) |accept| {
        try std.testing.expectError(error.NoAcceptableWebContentType, web.negotiateResponseContentType(.{ .format = .proto, .text = false }, &.{.{ .name = "accept", .value = accept }}));
    }
    for ([_][]const u8{ "1.001", "0.1234", ".5", "-1", "2", "garbage", "0.5;q=1" }) |quality| {
        var buffer: [96]u8 = undefined;
        const accept = try std.fmt.bufPrint(&buffer, "application/grpc-web-text;q={s}", .{quality});
        try std.testing.expectError(error.InvalidWebAccept, web.negotiateResponseContentType(.{ .format = .proto, .text = false }, &.{.{ .name = "accept", .value = accept }}));
    }
}

test "gRPC-Web classifies the four binary and text media types" {
    const cases = [_]struct {
        raw: []const u8,
        format: web.Format,
        text: bool,
    }{
        .{ .raw = "application/grpc-web", .format = .proto, .text = false },
        .{ .raw = "application/grpc-web+proto", .format = .proto, .text = false },
        .{ .raw = "application/grpc-web+json", .format = .json, .text = false },
        .{ .raw = "application/grpc-web-text", .format = .proto, .text = true },
        .{ .raw = "application/grpc-web-text+proto", .format = .proto, .text = true },
        .{ .raw = "application/grpc-web-text+json", .format = .json, .text = true },
    };
    for (cases) |case| {
        const parsed = try web.parseContentType(case.raw);
        try std.testing.expectEqual(case.format, parsed.format);
        try std.testing.expectEqual(case.text, parsed.text);
    }
    // Parameters and surrounding OWS follow the HTTP content-type grammar.
    const parametrized = try web.parseContentType("application/grpc-web; charset=utf-8");
    try std.testing.expectEqual(web.Format.proto, parametrized.format);
    try std.testing.expect(!parametrized.text);

    try std.testing.expectError(
        error.InvalidWebContentType,
        web.parseContentType("application/grpc"),
    );
    try std.testing.expectError(
        error.InvalidWebContentType,
        web.parseContentType("application/json"),
    );
    try std.testing.expectError(
        error.InvalidWebContentType,
        web.parseContentType("application/grpc-web-x"),
    );
}

test "gRPC-Web canonical response types round trip" {
    const binary = try web.parseContentType("application/grpc-web+proto");
    try std.testing.expectEqualStrings(
        "application/grpc-web",
        binary.canonical(),
    );
    const json = try web.parseContentType("application/grpc-web+json");
    try std.testing.expectEqualStrings(
        "application/grpc-web+json",
        json.canonical(),
    );
    const text = try web.parseContentType("application/grpc-web-text");
    try std.testing.expectEqualStrings(
        "application/grpc-web-text",
        text.canonical(),
    );
    const text_json = try web.parseContentType("application/grpc-web-text+json");
    try std.testing.expectEqualStrings(
        "application/grpc-web-text+json",
        text_json.canonical(),
    );
}

test "gRPC-Web binary request decodes one framed message" {
    const allocator = std.testing.allocator;
    var entity: [10]u8 = undefined;
    entity[0] = 0;
    std.mem.writeInt(u32, entity[1..5], 5, .big);
    @memcpy(entity[5..10], "hello");
    const headers = [_]http2.Hpack.HeaderField{};
    var request = try web.parseUnaryRequest(
        allocator,
        "POST",
        "/demo.Echo/Unary",
        &headers,
        &entity,
        .{ .format = .proto, .text = false },
        1024,
    );
    defer request.deinit();
    try std.testing.expectEqualStrings("hello", request.message.payload);
    try std.testing.expect(request.owned_message == null);
}

test "gRPC-Web text request base64 decodes and owns its message" {
    const allocator = std.testing.allocator;
    var framed: [10]u8 = undefined;
    framed[0] = 0;
    std.mem.writeInt(u32, framed[1..5], 5, .big);
    @memcpy(framed[5..10], "hello");
    const encoded = try base64EncodeAlloc(allocator, &framed);
    defer allocator.free(encoded);

    const headers = [_]http2.Hpack.HeaderField{};
    var request = try web.parseUnaryRequest(
        allocator,
        "POST",
        "/demo.Echo/Unary",
        &headers,
        encoded,
        .{ .format = .proto, .text = true },
        1024,
    );
    defer request.deinit();
    try std.testing.expectEqualStrings("hello", request.message.payload);
    try std.testing.expect(request.owned_message != null);

    try std.testing.expectError(
        error.InvalidTextEncoding,
        web.parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            "%%%%",
            .{ .format = .proto, .text = true },
            1024,
        ),
    );
}

test "gRPC-Web rejects missing or duplicated request messages" {
    const allocator = std.testing.allocator;
    const headers = [_]http2.Hpack.HeaderField{};
    try std.testing.expectError(
        error.InvalidMessageCount,
        web.parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            "",
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
    var two: [20]u8 = undefined;
    for (0..2) |index| {
        two[index * 10] = 0;
        std.mem.writeInt(u32, two[index * 10 + 1 ..][0..4], 5, .big);
        @memcpy(two[index * 10 + 5 ..][0..5], "hello");
    }
    try std.testing.expectError(
        error.InvalidMessageCount,
        web.parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            &two,
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
    try std.testing.expectError(
        error.InvalidGrpcRequest,
        web.parseUnaryRequest(
            allocator,
            "GET",
            "/demo.Echo/Unary",
            &headers,
            two[0..10],
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
}

test "gRPC-Web response body ends with one trailers frame" {
    const allocator = std.testing.allocator;
    const body = try web.buildResponseBody(allocator, .{
        .status = .ok,
        .message = "pong",
    });
    defer allocator.free(body);

    // One data frame for the four-byte message.
    try std.testing.expect(body[0] == 0);
    try std.testing.expectEqual(
        @as(u32, 4),
        std.mem.readInt(u32, body[1..5], .big),
    );
    try std.testing.expectEqualStrings("pong", body[5..9]);
    // The terminal frame carries the 0x80 marker and status trailer.
    const trailer_offset = 9;
    try std.testing.expectEqual(@as(u8, 0x80), body[trailer_offset]);
    const trailer_len = std.mem.readInt(
        u32,
        body[trailer_offset + 1 ..][0..4],
        .big,
    );
    try std.testing.expectEqual(
        body.len - trailer_offset - 5,
        trailer_len,
    );
    const trailer_block = body[trailer_offset + 5 ..];
    try std.testing.expect(trailer_block.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, trailer_block, "grpc-status:0\r\n"));
    try std.testing.expect(trailer_block[trailer_block.len - 2 ..][0] == '\r' and
        trailer_block[trailer_block.len - 1] == '\n');
}

fn base64EncodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const output = try allocator.alloc(u8, encoder.calcSize(input.len));
    _ = encoder.encode(output, input);
    return output;
}
