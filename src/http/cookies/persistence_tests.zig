const std = @import("std");
const cookies = @import("mod.zig");

const now: i64 = 1_700_000_000;

test "CookieJar snapshot round trip preserves full persistent metadata" {
    const allocator = std.testing.allocator;
    const config = cookies.Config{ .domain_policy = .unchecked };
    var jar = try cookies.Jar.init(allocator, config);
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "host=p; Max-Age=3600; Secure; HttpOnly; SameSite=Strict; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/docs/start",
        "domain=d; Domain=example.com; Max-Age=3600; " ++
            "SameSite=Lax; Path=/docs",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "__Host-Http-server=p; Max-Age=3600; Secure; HttpOnly; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "session=discarded; Path=/",
        now,
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try jar.encodeSnapshot(now, &encoded);
    var restored = try cookies.Jar.init(allocator, config);
    defer restored.deinit();
    try restored.restoreSnapshot(encoded.items, now);
    try std.testing.expectEqual(@as(usize, 3), restored.count());

    var reencoded: std.ArrayList(u8) = .empty;
    defer reencoded.deinit(allocator);
    try restored.encodeSnapshot(now, &reencoded);
    try std.testing.expectEqualSlices(u8, encoded.items, reencoded.items);

    const value = try restored.cookieHeaderValueAlloc(
        allocator,
        "https://www.example.com/docs/item",
        now,
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(
        "domain=d; host=p; __Host-Http-server=p",
        value,
    );
    try std.testing.expectEqual(@as(usize, 0), restored.endSession());
}

test "CookieJar snapshot restore is transactional and policy bound" {
    const allocator = std.testing.allocator;
    var source = try cookies.Jar.init(allocator, .{
        .domain_policy = .unchecked,
    });
    defer source.deinit();
    _ = try source.storeSetCookie(
        "https://www.example.com/",
        "domain=persistent; Domain=example.com; Max-Age=60",
        now,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try source.encodeSnapshot(now, &encoded);

    var target = try cookies.Jar.init(allocator, .{});
    defer target.deinit();
    _ = try target.storeSetCookie(
        "https://safe.example/",
        "old=unchanged",
        now,
    );
    try std.testing.expectError(
        error.SnapshotPolicyMismatch,
        target.restoreSnapshot(encoded.items, now),
    );
    try expectCookie(&target, "https://safe.example/", "old=unchanged");

    const corrupt = try allocator.dupe(u8, encoded.items);
    defer allocator.free(corrupt);
    corrupt[0] ^= 0xff;
    try std.testing.expectError(
        error.CorruptSnapshot,
        target.restoreSnapshot(corrupt, now),
    );
    try expectCookie(&target, "https://safe.example/", "old=unchanged");
}

test "CookieJar snapshot file is atomic and excludes expired state" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "live=one; Max-Age=60",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "expired=gone; Max-Age=1",
        now,
    );
    try jar.saveSnapshotAtomic(io, tmp.dir, "cookies.bin", now + 2);

    var restored = try cookies.Jar.init(allocator, .{});
    defer restored.deinit();
    try restored.loadSnapshot(io, tmp.dir, "cookies.bin", now + 2);
    try expectCookie(&restored, "https://example.com/", "live=one");
    try std.testing.expectError(
        error.SnapshotNotFound,
        restored.loadSnapshot(io, tmp.dir, "missing.bin", now),
    );
}

test "CookieJar snapshot allocation failures roll back and do not leak" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        snapshotAllocationScenario,
        .{},
    );
}

test "CookieJar Netscape compatibility is explicit and metadata-lossy" {
    const allocator = std.testing.allocator;
    const config = cookies.Config{ .domain_policy = .unchecked };
    var jar = try cookies.Jar.init(allocator, config);
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "host=one; Max-Age=60; Secure; HttpOnly; SameSite=Strict; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/docs/start",
        "domain=two; Domain=example.com; Max-Age=60; Path=/docs",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "session=three; Path=/",
        now,
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(
        error.MetadataLossNotAcknowledged,
        jar.encodeNetscapeLossy(now, .{}, &encoded),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try jar.encodeNetscapeLossy(now, .{
        .acknowledge_metadata_loss = true,
    }, &encoded);
    try std.testing.expect(std.mem.startsWith(
        u8,
        encoded.items,
        "# Netscape HTTP Cookie File\n",
    ));
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        "#HttpOnly_www.example.com\tFALSE\t/\tTRUE\t",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded.items,
        ".example.com\tTRUE\t/docs\tFALSE\t",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded.items, "session") == null);

    var restored = try cookies.Jar.init(allocator, config);
    defer restored.deinit();
    try restored.restoreNetscapeLossy(encoded.items, now, .{
        .acknowledge_metadata_loss = true,
    });
    try std.testing.expectEqual(@as(usize, 2), restored.count());
    const value = try restored.cookieHeaderValueAlloc(
        allocator,
        "https://www.example.com/docs/item",
        now,
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings("domain=two; host=one", value);

    var with_session: std.ArrayList(u8) = .empty;
    defer with_session.deinit(allocator);
    try jar.encodeNetscapeLossy(now, .{
        .acknowledge_metadata_loss = true,
        .include_session = true,
    }, &with_session);
    try restored.restoreNetscapeLossy(with_session.items, now, .{
        .acknowledge_metadata_loss = true,
        .include_session = true,
    });
    try std.testing.expectEqual(@as(usize, 3), restored.count());
    try std.testing.expectEqual(@as(usize, 1), restored.endSession());
}

test "CookieJar Netscape restore is transactional and file-backed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "persistent=one; Max-Age=60",
        now,
    );
    try jar.saveNetscapeAtomicLossy(
        io,
        tmp.dir,
        "cookies.txt",
        now,
        .{ .acknowledge_metadata_loss = true },
    );
    var restored = try cookies.Jar.init(allocator, .{});
    defer restored.deinit();
    try restored.loadNetscapeLossy(
        io,
        tmp.dir,
        "cookies.txt",
        now,
        .{ .acknowledge_metadata_loss = true },
    );
    try expectCookie(&restored, "https://example.com/", "persistent=one");

    try std.testing.expectError(
        error.InvalidNetscapeFile,
        restored.restoreNetscapeLossy("not a cookie file", now, .{
            .acknowledge_metadata_loss = true,
        }),
    );
    try expectCookie(&restored, "https://example.com/", "persistent=one");

    _ = try jar.storeSetCookie(
        "https://example.com/",
        "tab=a\tb; Max-Age=60",
        now,
    );
    var prefix: std.ArrayList(u8) = .empty;
    defer prefix.deinit(allocator);
    try prefix.appendSlice(allocator, "unchanged");
    try std.testing.expectError(
        error.UnrepresentableCookie,
        jar.encodeNetscapeLossy(now, .{
            .acknowledge_metadata_loss = true,
        }, &prefix),
    );
    try std.testing.expectEqualStrings("unchanged", prefix.items);
}

test "CookieJar Netscape restore enforces layered cookie prefixes" {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    const valid =
        "# Netscape HTTP Cookie File\n" ++
        "#HttpOnly_example.com\tFALSE\t/\tTRUE\t1700003600\t" ++
        "__Host-Http-token\tone\n";
    try jar.restoreNetscapeLossy(valid, now, .{
        .acknowledge_metadata_loss = true,
    });
    try expectCookie(
        &jar,
        "https://example.com/",
        "__Host-Http-token=one",
    );

    const missing_http_only =
        "# Netscape HTTP Cookie File\n" ++
        "example.com\tFALSE\t/\tTRUE\t1700003600\t" ++
        "__Http-token\ttwo\n";
    try std.testing.expectError(
        error.CorruptSnapshot,
        jar.restoreNetscapeLossy(missing_http_only, now, .{
            .acknowledge_metadata_loss = true,
        }),
    );
    try expectCookie(
        &jar,
        "https://example.com/",
        "__Host-Http-token=one",
    );

    const value_only =
        "# Netscape HTTP Cookie File\n" ++
        "#HttpOnly_example.com\tFALSE\t/\tTRUE\t1700003600\t\t" ++
        "__Http-value-only\n";
    try std.testing.expectError(
        error.CorruptSnapshot,
        jar.restoreNetscapeLossy(value_only, now, .{
            .acknowledge_metadata_loss = true,
        }),
    );
    try expectCookie(
        &jar,
        "https://example.com/",
        "__Host-Http-token=one",
    );
}

fn snapshotAllocationScenario(allocator: std.mem.Allocator) !void {
    var source = try cookies.Jar.init(allocator, .{});
    defer source.deinit();
    _ = try source.storeSetCookie(
        "https://example.com/",
        "persistent=value; Max-Age=60; Path=/",
        now,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try source.encodeSnapshot(now, &encoded);
    var restored = try cookies.Jar.init(allocator, .{});
    defer restored.deinit();
    try restored.restoreSnapshot(encoded.items, now);
    try std.testing.expectEqual(@as(usize, 1), restored.count());
}

fn expectCookie(
    jar: *cookies.Jar,
    uri: []const u8,
    expected: []const u8,
) !void {
    const value = try jar.cookieHeaderValueAlloc(
        std.testing.allocator,
        uri,
        now,
        .{},
    );
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings(expected, value);
}
