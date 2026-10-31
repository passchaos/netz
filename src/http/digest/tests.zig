const std = @import("std");
const digest = @import("../digest.zig");
const Header = struct { name: []const u8, value: []const u8 };
const body = "{\"hello\": \"world\"}";
const sha256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
const sha512 = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

test "HTTP digest RFC9530 appendix D independent vectors and exact output capacity" {
    const computed = try digest.compute(body, .{});
    var output: [digest.max_value_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(sha256 ++ ", " ++ sha512, try computed.writeInto(&output));
    try std.testing.expectEqual(@as(usize, digest.max_value_bytes), computed.encodedLen());
    const field = try digest.parse(sha256 ++ ", " ++ sha512, .{});
    try std.testing.expectEqual(digest.Result.sha256_and_sha512, try digest.verifyComputed(field, computed, .{}));
    @memset(&output, 0xa5);
    try std.testing.expectError(error.BufferTooShort, computed.writeInto(output[0 .. output.len - 1]));
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** digest.max_value_bytes), &output);
    try std.testing.expectEqualStrings("", try (digest.Set{}).writeInto(&.{}));
}

test "HTTP digest combines fields trailers and duplicate keys in RFC8941 order" {
    const headers = [_]Header{
        .{ .name = "Content-Digest", .value = "future=:YWJj:;x=\"a,b\"" },
        .{ .name = "content-digest", .value = sha256 ++ ";p=?1" },
    };
    const trailers = [_]Header{.{ .name = "CONTENT-DIGEST", .value = sha512 }};
    try std.testing.expectEqual(digest.Result.sha256_and_sha512, try digest.verifyContent(body, &headers, &trailers, .{}));
    const last = [_]Header{.{ .name = "content-digest", .value = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:" }};
    try std.testing.expectError(error.DigestMismatch, digest.verifyContent(body, &headers, &last, .{}));
    const overwritten = try digest.parse("sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:, " ++ sha256, .{});
    try std.testing.expectEqual(digest.Result.sha256, try digest.verifyComputed(overwritten, try digest.compute(body, .{}), .{}));
    const unpadded = try digest.parse("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE:", .{});
    try std.testing.expectEqual(digest.Result.sha256, try digest.verifyComputed(unpadded, try digest.compute(body, .{}), .{}));
    // RFC9530 schema constraints apply to the final RFC8941 Dictionary.
    // Earlier semantic types/lengths disappear when the same key is replaced.
    const final = try digest.parse("sha-256=:AA==:, future=1, future=:AA==:, sha-256, " ++ sha256, .{});
    try std.testing.expectEqual(digest.Result.sha256, try digest.verifyComputed(final, try digest.compute(body, .{}), .{}));
}

test "HTTP digest validates all members and parameters including unsupported algorithms" {
    for ([_][]const u8{
        "sha-256",            "sha-256=?1",                "future=10",      "future=(1 2)",
        "SHA-256=:AA==:",     "sha-256=:AA==:",            "future=:A:",     "future=:AA===:",
        "future=:AA==:;x=@1", "future=:AA==:;x=%\"date\"", "future=:AA==:,", "future =:AA==:",
        "future= :AA==:",     sha256 ++ ", invalid=\"x\"",
    }) |value| try std.testing.expectError(error.InvalidDigestField, digest.parse(value, .{}));
    try std.testing.expectError(error.InvalidDigestField, digest.parseMessage(.content, &[_]Header{
        .{ .name = "content-digest", .value = "" },
        .{ .name = "content-digest", .value = sha256 },
    }, &.{}, .{}));
    try std.testing.expectError(error.DigestFieldTooLarge, digest.parse(sha256, .{ .max_field_bytes = sha256.len - 1 }));
    try std.testing.expectError(error.TooManyDigestMembers, digest.parse("future=:AA==:, " ++ sha256, .{ .max_members = 1 }));
    try std.testing.expectError(error.DigestFieldTooLarge, digest.parseMessage(.content, &[_]Header{.{ .name = "content-digest", .value = sha256 }}, &[_]Header{.{ .name = "content-digest", .value = sha512 }}, .{ .max_field_bytes = sha256.len + sha512.len - 1 }));
}

test "HTTP digest policy distinguishes absent unsupported disabled and mismatching values" {
    try std.testing.expectError(error.MissingContentDigest, digest.verifyContent("", &[_]Header{}, &[_]Header{}, .{}));
    try std.testing.expectEqual(digest.Result.absent, try digest.verifyContent("", &[_]Header{}, &[_]Header{}, .{ .required = false }));
    const old = [_]Header{.{ .name = "content-digest", .value = "md5=:Sd/dVLAcvNLSq16eXua5uQ==:" }};
    try std.testing.expectError(error.NoSupportedDigest, digest.verifyContent(body, &old, &.{}, .{}));
    try std.testing.expectEqual(digest.Result.unsupported, try digest.verifyContent(body, &old, &.{}, .{ .required = false }));
    const only256 = [_]Header{.{ .name = "content-digest", .value = sha256 }};
    try std.testing.expectError(error.NoSupportedDigest, digest.verifyContent(body, &only256, &.{}, .{ .algorithms = .{ .sha256 = false } }));
    try std.testing.expectEqual(digest.Result.unsupported, try digest.verifyContent(body, &only256, &.{}, .{ .required = false, .algorithms = .{ .sha256 = false } }));
    try std.testing.expectError(error.DigestMismatch, digest.verifyContent("modified", &only256, &.{}, .{}));
    const conflicting = [_]Header{.{ .name = "content-digest", .value = "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:, " ++ sha512 }};
    try std.testing.expectError(error.DigestMismatch, digest.verifyContent(body, &conflicting, &.{}, .{}));
    try std.testing.expectEqual(digest.Result.sha512, try digest.verifyContent(body, &conflicting, &.{}, .{ .algorithms = .{ .sha256 = false } }));
    try std.testing.expectError(error.InvalidDigestPolicy, digest.verifyContent(body, &old, &.{}, .{ .algorithms = .{ .sha256 = false, .sha512 = false } }));
}

test "HTTP digest streaming hasher preserves byte quota and finish ownership" {
    var hasher = try digest.Hasher.init(.{ .max_content_bytes = body.len });
    try hasher.update(body[0..5]);
    try std.testing.expectError(error.DigestContentTooLarge, hasher.update(body));
    try std.testing.expectEqual(@as(usize, 5), hasher.bytes);
    for (body[5..]) |byte| try hasher.update(&.{byte});
    const result = try hasher.finish();
    const field = try digest.parse(sha256 ++ ", " ++ sha512, .{});
    try std.testing.expectEqual(digest.Result.sha256_and_sha512, try digest.verifyComputed(field, result, .{}));
    try std.testing.expectError(error.InvalidDigestState, hasher.finish());
    try std.testing.expectError(error.InvalidDigestState, hasher.update(""));
    var empty = try digest.Hasher.init(.{ .algorithms = .{ .sha512 = false }, .max_content_bytes = 0 });
    try std.testing.expectError(error.DigestContentTooLarge, empty.update("x"));
    var output: [54]u8 = undefined;
    try std.testing.expectEqualStrings("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:", try (try empty.finish()).writeInto(&output));
}

test "HTTP digest preferences validate every weight and select active algorithms" {
    const preferences = try digest.parsePreferences("sha-256=3;extension=\"comma,ok\", sha-512=10, unixsum=0", .{});
    try std.testing.expectEqual(@as(?digest.Algorithm, .sha512), try preferences.select(.{}));
    try std.testing.expectEqual(@as(?digest.Algorithm, .sha256), try preferences.select(.{ .sha512 = false }));
    var out: [32]u8 = undefined;
    try std.testing.expectEqualStrings("sha-256=3, sha-512=10", try preferences.writeInto(&out));
    const disabled = try digest.parsePreferences("sha-512=10, sha-512=0", .{});
    try std.testing.expectEqual(@as(?digest.Algorithm, null), try disabled.select(.{}));
    const replaced = try digest.parsePreferences("sha-512=11, sha-512, sha-512=10", .{});
    try std.testing.expectEqual(@as(?digest.Algorithm, .sha512), try replaced.select(.{}));
    for ([_][]const u8{ "sha-256", "sha-256=?1", "sha-256=11", "future=-1", "future=1.0", "future=:AA==:", "sha-256=1," }) |value| {
        try std.testing.expectError(error.InvalidDigestField, digest.parsePreferences(value, .{}));
    }
    const repeated = try digest.parsePreferenceHeaders(.representation, &[_]Header{
        .{ .name = "Want-Repr-Digest", .value = "sha-256=1" },
        .{ .name = "want-repr-digest", .value = "sha-512=9" },
    }, .{});
    try std.testing.expectEqual(@as(?digest.Algorithm, .sha512), try repeated.select(.{}));
    try std.testing.expectError(error.InvalidDigestField, (digest.Preferences{ .sha256 = 11 }).writeInto(&out));
}

test "HTTP digest representation verification requires complete selected data" {
    const headers = [_]Header{.{ .name = "repr-digest", .value = sha256 }};
    try std.testing.expectEqual(digest.Result.sha256, try digest.verify(.representation, body, &headers, &.{}, .{}));
    try std.testing.expectError(error.DigestMismatch, digest.verify(.representation, body[0..5], &headers, &.{}, .{}));
    try std.testing.expectError(error.MissingContentDigest, digest.verifyContent(body, &headers, &.{}, .{}));
    try std.testing.expectError(error.MissingRepresentationDigest, digest.verify(.representation, body, &[_]Header{}, &.{}, .{}));
}

test "HTTP digest accepts the exact dictionary quota and rejects the next unique algorithm" {
    var storage: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    for (0..64) |index| {
        if (index != 0) try writer.writeAll(", ");
        try writer.print("algorithm{d}=::", .{index});
    }
    const field = try digest.parse(writer.buffered(), .{});
    try std.testing.expectEqual(digest.Result.unsupported, try digest.verifyComputed(field, .{}, .{ .required = false }));
    try writer.writeAll(", algorithm64=::");
    try std.testing.expectError(error.TooManyDigestMembers, digest.parse(writer.buffered(), .{}));
    try std.testing.expectError(error.TooManyDigestMembers, digest.parse(writer.buffered(), .{ .max_members = 128 }));
}
