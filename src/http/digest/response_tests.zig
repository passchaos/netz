const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const client = @import("../client/types.zig");
const digest = @import("../digest.zig");
const body = "{\"hello\": \"world\"}";
const value = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";

test "HTTP digest verifies HTTP1 chunked trailers and keeps response reuse metadata" {
    const bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Digest\r\n\r\n12\r\n" ++ body ++ "\r\n0\r\nContent-Digest: " ++ value ++ "\r\n\r\n";
    var response = try http1.parseResponse(std.testing.allocator, bytes, .{});
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqual(digest.Result.sha256, try response.verifyContentDigest(.{}));
    try std.testing.expect(!response.must_close);
    const owned = client.OwnedResponse{ .allocator = std.testing.allocator, .value = .{ .http1 = .{ .response = response, .bytes = undefined } } };
    try std.testing.expectEqual(digest.Result.sha256, try owned.value.http1.verifyContentDigest(.{}));
    try std.testing.expectEqual(digest.Result.sha256, try owned.verifyContentDigest(.{}));
}

test "HTTP digest verifies HTTP2 owned and unified response headers plus trailers" {
    var headers = [_]http2.Hpack.HeaderField{.{ .name = "content-digest", .value = value }};
    var content = body.*;
    const response = http2.runtime.OwnedResponse{ .status = 200, .headers = &headers, .body = &content };
    try std.testing.expectEqual(digest.Result.sha256, try response.verifyContentDigest(.{}));
    const owned = client.OwnedResponse{ .allocator = std.testing.allocator, .value = .{ .http2 = response } };
    try std.testing.expectEqual(digest.Result.sha256, try owned.verifyContentDigest(.{}));
    const redirected = client.RedirectedResponse{ .allocator = std.testing.allocator, .response = owned, .final_uri = undefined, .redirect_count = 1 };
    try std.testing.expectEqual(digest.Result.sha256, try redirected.verifyContentDigest(.{}));
}

test "HTTP digest verifies HTTP3 QPACK DATA and trailer images" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Response{ .status = 200, .body = body, .trailers = &.{.{ .name = "content-digest", .value = value }} }).write(&bytes, std.testing.allocator);
    var response = try http3.decodeResponse(std.testing.allocator, bytes.items);
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqual(digest.Result.sha256, try response.verifyContentDigest(.{}));
    const owned = client.OwnedResponse{ .allocator = std.testing.allocator, .value = .{ .http3 = .{ .response = response, .stream_bytes = undefined } } };
    try std.testing.expectEqual(digest.Result.sha256, try owned.value.http3.verifyContentDigest(.{}));
    const development = http3.runtime.OwnedResponse{ .response = response, .datagram = undefined };
    try std.testing.expectEqual(digest.Result.sha256, try development.verifyContentDigest(.{}));
    try std.testing.expectEqual(digest.Result.sha256, try owned.verifyContentDigest(.{}));
}

test "HTTP digest distinguishes HEAD content from selected representation metadata" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nContent-Encoding: gzip\r\nContent-Digest: sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\r\nRepr-Digest: " ++ value ++ "\r\n\r\n";
    var response = try http1.parseResponseForRequest(std.testing.allocator, raw, .{}, .HEAD);
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqual(digest.Result.sha256, try response.verifyContentDigest(.{}));
    try std.testing.expectEqual(digest.Result.sha256, try digest.verify(.representation, body, response.headers, response.trailers, .{}));
    try std.testing.expectError(error.DigestMismatch, digest.verify(.representation, response.body, response.headers, response.trailers, .{}));
}
