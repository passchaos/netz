const std = @import("std");
const netz = @import("netz");

test "HTTP request types expose shared content decoding" {
    const allocator = std.testing.allocator;
    var gzip_hello = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
        0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00,
        0x00,
    };

    var h1_headers = [_]netz.http1.Header{.{
        .name = "Content-Encoding",
        .value = "gzip",
    }};
    const h1 = netz.http1.Request{
        .method = .POST,
        .target = "/upload",
        .version = .http_1_1,
        .headers = &h1_headers,
        .body = &gzip_hello,
        .body_framing = .content_length,
        .consumed = 0,
    };
    var h1_decoded = try h1.decodeContentAlloc(allocator, "hello".len);
    defer h1_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("hello", h1_decoded.bytes);

    const h1_runtime = netz.http1.runtime.OwnedRequest{
        .bytes = &.{},
        .request = h1,
    };
    try std.testing.expectEqual(
        netz.http.ContentCoding.gzip,
        (try h1_runtime.contentEncoding()).items()[0],
    );

    var h2_headers = [_]netz.http2.Hpack.HeaderField{.{
        .name = "content-encoding",
        .value = "gzip",
    }};
    const h2 = netz.http2.runtime.OwnedRequest{
        .stream_id = 1,
        .headers = &h2_headers,
        .method = "POST",
        .path = "/upload",
        .scheme = "https",
        .authority = "example.com",
        .body = &gzip_hello,
    };
    var output: ["hello".len]u8 = undefined;
    try std.testing.expectEqualStrings(
        "hello",
        try h2.decodeContentInto(&output, &.{}),
    );

    var h3_headers = [_]netz.http3.Qpack.HeaderField{.{
        .name = "content-encoding",
        .value = "gzip",
    }};
    const h3 = netz.http3.DecodedRequest{
        .method = "POST",
        .path = "/upload",
        .scheme = "https",
        .authority = "example.com",
        .headers = &h3_headers,
        .body = &gzip_hello,
        .consumed = 0,
    };
    var h3_decoded = try h3.decodeContentAlloc(allocator, "hello".len);
    defer h3_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("hello", h3_decoded.bytes);

    const h3_runtime = netz.http3.runtime.OwnedRequest{
        .from = .{ .ip4 = .loopback(0) },
        .stream_id = 0,
        .datagram = undefined,
        .request = h3,
    };
    try std.testing.expectEqualStrings(
        "hello",
        try h3_runtime.decodeContentInto(&output, &.{}),
    );

    const h3_endpoint = netz.http3.runtime.OwnedEndpointRequest{
        .connection_handle = undefined,
        .from = .{ .ip4 = .loopback(0) },
        .stream_id = 0,
        .method = "POST",
        .path = "/upload",
        .scheme = "https",
        .authority = "example.com",
        .headers = &h3_headers,
        .body = &gzip_hello,
    };
    try std.testing.expectEqualStrings(
        "hello",
        try h3_endpoint.decodeContentInto(&output, &.{}),
    );

    var h1_stream = try (netz.http1.RequestHead{
        .method = .POST,
        .target = "/upload",
        .version = .http_1_1,
        .headers = &h1_headers,
        .body_framing = .content_length,
        .content_length = gzip_hello.len,
        .head_len = 0,
    }).streamContentDecoder(allocator, .{
        .max_encoded_bytes = gzip_hello.len,
        .max_decoded_bytes = "hello".len,
    });
    defer h1_stream.deinit();

    var h1_runtime_stream = try (netz.http1.runtime.StreamingRequestHead{
        .method = .POST,
        .target = "/upload",
        .version = .http_1_1,
        .headers = &h1_headers,
        .body_framing = .content_length,
        .content_length = gzip_hello.len,
    }).streamContentDecoder(allocator, .{
        .max_encoded_bytes = gzip_hello.len,
        .max_decoded_bytes = "hello".len,
    });
    defer h1_runtime_stream.deinit();

    var h2_stream = try (netz.http2.runtime.StreamingRequestHead{
        .stream_id = 1,
        .headers = &h2_headers,
        .method = "POST",
        .path = "/upload",
        .scheme = "https",
        .authority = "example.com",
    }).streamContentDecoder(allocator, .{
        .max_encoded_bytes = gzip_hello.len,
        .max_decoded_bytes = "hello".len,
    });
    defer h2_stream.deinit();

    var h3_stream = try (netz.http3.DecodedRequestHead{
        .method = "POST",
        .path = "/upload",
        .scheme = "https",
        .authority = "example.com",
        .headers = &h3_headers,
        .content_length = gzip_hello.len,
        .body_allowed = true,
        .consumed = 0,
        .qpack_section_acknowledgments = 0,
    }).streamContentDecoder(allocator, .{
        .max_encoded_bytes = gzip_hello.len,
        .max_decoded_bytes = "hello".len,
    });
    defer h3_stream.deinit();
    try std.testing.expectEqualStrings(
        "hello",
        try decodeContentStream(&h3_stream, &gzip_hello, &output),
    );
}

fn decodeContentStream(
    decoder: *netz.http.ContentStreamDecoder,
    input: []const u8,
    output: []u8,
) ![]u8 {
    var input_offset: usize = 0;
    var output_offset: usize = 0;
    while (input_offset < input.len) {
        const result = try decoder.step(
            input[input_offset..],
            output[output_offset..],
        );
        input_offset += result.input_read;
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.input_read == 0 and result.output_written == 0) {
            return error.NoProgress;
        }
    }
    while (!decoder.finished()) {
        const result = try decoder.finish(output[output_offset..]);
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.output_written == 0) return error.NoProgress;
    }
    return output[0..output_offset];
}
