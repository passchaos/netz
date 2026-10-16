const std = @import("std");
const cookies = @import("mod.zig");
const client_types = @import("../client/types.zig");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");

const now: i64 = 1_700_000_000;

test "CookieJar owns path-ordered state and applies replacement expiry deletion" {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();

    try std.testing.expectEqual(
        cookies.StoreResult.stored,
        try jar.storeSetCookie(
            "https://Example.COM/docs/page",
            "root=one; Path=/",
            now,
        ),
    );
    _ = try jar.storeSetCookie(
        "https://example.com/docs/page",
        "default=two",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/docs/page",
        "deep=three; Path=/docs/deep",
        now,
    );
    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/docs/deep/item",
        now,
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(
        "deep=three; default=two; root=one",
        value,
    );

    try std.testing.expectEqual(
        cookies.StoreResult.replaced,
        try jar.storeSetCookie(
            "https://example.com/docs/next",
            "default=updated",
            now + 1,
        ),
    );
    const replaced = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/docs/item",
        now + 1,
        .{},
    );
    defer allocator.free(replaced);
    try std.testing.expectEqualStrings(
        "default=updated; root=one",
        replaced,
    );

    try std.testing.expectEqual(
        cookies.StoreResult.deleted,
        try jar.storeSetCookie(
            "https://example.com/docs/item",
            "default=gone; Max-Age=0",
            now + 2,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://example.com/",
            "expired=x; Expires=Sun, 06 Nov 1994 08:49:37 GMT",
            now,
        ),
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "quoted=\"a:b\"; Max-Age=10; " ++
            "Expires=Sun, 06 Nov 1994 08:49:37 GMT",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "value-only; Path=/",
        now,
    );
    const root = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/",
        now + 9,
        .{},
    );
    defer allocator.free(root);
    try std.testing.expectEqualStrings(
        "root=one; quoted=\"a:b\"; value-only",
        root,
    );
    try std.testing.expectEqual(@as(usize, 1), jar.removeExpired(now + 10));

    var short = [_]u8{0xaa} ** 3;
    try std.testing.expectError(
        error.BufferTooShort,
        jar.cookieHeaderValueInto(
            "https://example.com/",
            now,
            .{},
            &short,
        ),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 3), &short);
}

test "CookieJar domain security and prefixes fail closed" {
    const allocator = std.testing.allocator;
    var default_jar = try cookies.Jar.init(allocator, .{});
    defer default_jar.deinit();
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try default_jar.storeSetCookie(
            "https://www.example.com/",
            "shared=one; Domain=example.com",
            now,
        ),
    );

    var jar = try cookies.Jar.init(allocator, .{
        .domain_policy = .unchecked,
    });
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "shared=one; Domain=.Example.COM; Path=/",
        now,
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://www.example.com/",
            "bad=one; Domain=evil.example",
            now,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "http://www.example.com/",
            "secure=bad; Secure",
            now,
        ),
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "secure=good; Secure",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "__Secure-token=good; Secure",
        now,
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://www.example.com/",
            "__Secure-bad=x",
            now,
        ),
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/child",
        "__Host-token=good; Secure; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "__secure-lower=good; Secure",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "__HOST-lower=good; Secure; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/",
        "__Secure-value-only; Secure",
        now,
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://www.example.com/",
            "__Host-missing-secure",
            now,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://www.example.com/",
            "__Host-bad=x; Secure; Domain=example.com; Path=/",
            now,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://127.0.0.1/",
            "ip=x; Domain=127.0.0.1",
            now,
        ),
    );

    const sibling = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://api.example.com/",
        now,
        .{},
    );
    defer allocator.free(sibling);
    try std.testing.expectEqualStrings("shared=one", sibling);
    const secure = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://www.example.com/",
        now,
        .{},
    );
    defer allocator.free(secure);
    try std.testing.expectEqualStrings(
        "shared=one; secure=good; __Secure-token=good; __Host-token=good; " ++
            "__secure-lower=good; __HOST-lower=good; __Secure-value-only",
        secure,
    );
    const clear = try jar.cookieHeaderValueAlloc(
        allocator,
        "http://www.example.com/",
        now,
        .{},
    );
    defer allocator.free(clear);
    try std.testing.expectEqualStrings("shared=one", clear);

    var checked = try cookies.Jar.init(allocator, .{
        .domain_policy = .{ .checked = .{
            .is_public_suffix = publicSuffix,
        } },
    });
    defer checked.deinit();
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try checked.storeSetCookie(
            "https://www.example.com/",
            "suffix=x; Domain=com",
            now,
        ),
    );
    _ = try checked.storeSetCookie(
        "https://www.example.com/",
        "registrable=x; Domain=example.com",
        now,
    );
    _ = try checked.storeSetCookie(
        "http://com/",
        "exact=x; Domain=com",
        now,
    );
    const exact = try checked.cookieHeaderValueAlloc(
        allocator,
        "http://com/",
        now,
        .{},
    );
    defer allocator.free(exact);
    try std.testing.expectEqualStrings("exact=x", exact);
    const sub = try checked.cookieHeaderValueAlloc(
        allocator,
        "http://sub.com/",
        now,
        .{},
    );
    defer allocator.free(sub);
    try std.testing.expectEqualStrings("", sub);

    var coexist = try cookies.Jar.init(allocator, .{
        .domain_policy = .unchecked,
    });
    defer coexist.deinit();
    _ = try coexist.storeSetCookie(
        "https://example.com/",
        "same=host",
        now,
    );
    _ = try coexist.storeSetCookie(
        "https://example.com/",
        "same=domain; Domain=example.com",
        now,
    );
    try std.testing.expectEqual(@as(usize, 2), coexist.count());
    const coexist_value = try coexist.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/",
        now,
        .{},
    );
    defer allocator.free(coexist_value);
    try std.testing.expectEqualStrings(
        "same=host; same=domain",
        coexist_value,
    );

    var overlay = try cookies.Jar.init(allocator, .{
        .domain_policy = .unchecked,
    });
    defer overlay.deinit();
    _ = try overlay.storeSetCookie(
        "https://example.com/login",
        "sid=secure; Secure; Domain=example.com; Path=/login",
        now,
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try overlay.storeSetCookie(
            "http://example.com/login/en",
            "sid=overlay; Domain=example.com; Path=/login/en",
            now,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.stored,
        try overlay.storeSetCookie(
            "http://example.com/",
            "sid=broad; Domain=example.com; Path=/",
            now,
        ),
    );
}

fn publicSuffix(_: ?*anyopaque, domain: []const u8) bool {
    return std.mem.eql(u8, domain, "com") or
        std.mem.eql(u8, domain, "co.uk");
}

test "CookieJar enforces SameSite and HttpOnly request contexts" {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "strict=1; SameSite=Strict",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "lax=1; SameSite=Lax",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "none=1; SameSite=None; Secure",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "default=1",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "hidden=1; HttpOnly",
        now,
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookieWithContext(
            "https://example.com/",
            "hidden=overwritten",
            now,
            .{ .http_api = false },
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookie(
            "https://example.com/",
            "bad-none=1; SameSite=None",
            now,
        ),
    );
    try std.testing.expectEqual(
        cookies.StoreResult.ignored,
        try jar.storeSetCookieWithContext(
            "https://example.com/",
            "cross-set=1; SameSite=Lax",
            now,
            .{ .site = .cross_site },
        ),
    );

    try expectHeader(
        allocator,
        &jar,
        now,
        .{ .site = .cross_site },
        "none=1",
    );
    try expectHeader(
        allocator,
        &jar,
        now,
        .{
            .site = .cross_site,
            .top_level_navigation = true,
            .method = "GET",
        },
        "lax=1; none=1; default=1; hidden=1",
    );
    try expectHeader(
        allocator,
        &jar,
        now + 60,
        .{
            .site = .cross_site,
            .top_level_navigation = true,
            .method = "POST",
        },
        "none=1; default=1; hidden=1",
    );
    try expectHeader(
        allocator,
        &jar,
        now + 121,
        .{
            .site = .cross_site,
            .top_level_navigation = true,
            .method = "POST",
        },
        "none=1",
    );
    try expectHeader(
        allocator,
        &jar,
        now,
        .{ .http_api = false },
        "strict=1; lax=1; none=1; default=1",
    );
}

fn expectHeader(
    allocator: std.mem.Allocator,
    jar: *cookies.Jar,
    current: i64,
    context: cookies.RequestContext,
    expected: []const u8,
) !void {
    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/",
        current,
        context,
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(expected, value);
}

test "CookieJar evicts per-domain and global least-recently-used state" {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{
        .max_cookies = 3,
        .max_cookies_per_domain = 2,
    });
    defer jar.deinit();
    _ = try jar.storeSetCookie("https://example.com/", "a=1", now);
    _ = try jar.storeSetCookie("https://example.com/", "b=1", now);
    _ = try jar.storeSetCookie("https://example.com/", "c=1", now);
    try expectHeader(allocator, &jar, now, .{}, "b=1; c=1");

    _ = try jar.storeSetCookie("https://old.example/", "old=1", now);
    const touch = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/",
        now,
        .{},
    );
    allocator.free(touch);
    _ = try jar.storeSetCookie("https://new.example/", "new=1", now);
    try std.testing.expectEqual(@as(usize, 3), jar.count());
    const old = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://old.example/",
        now,
        .{},
    );
    defer allocator.free(old);
    try std.testing.expectEqualStrings("", old);
    const newest = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://new.example/",
        now,
        .{},
    );
    defer allocator.free(newest);
    try std.testing.expectEqualStrings("new=1", newest);

    var secure_priority = try cookies.Jar.init(allocator, .{
        .max_cookies = 3,
        .max_cookies_per_domain = 2,
    });
    defer secure_priority.deinit();
    _ = try secure_priority.storeSetCookie(
        "https://secure.example/",
        "secure=1; Secure",
        now,
    );
    _ = try secure_priority.storeSetCookie(
        "http://secure.example/",
        "first=1",
        now,
    );
    _ = try secure_priority.storeSetCookie(
        "http://secure.example/",
        "second=1",
        now,
    );
    const secure_values = try secure_priority.cookieHeaderValueAlloc(
        allocator,
        "https://secure.example/",
        now,
        .{},
    );
    defer allocator.free(secure_values);
    try std.testing.expectEqualStrings(
        "secure=1; second=1",
        secure_values,
    );
}

test "CookieJar caps persistent lifetime and clears session state" {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{
        .max_lifetime_seconds = 10,
    });
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "session=one",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://example.com/",
        "persistent=two; Max-Age=999999999999999999999999",
        now,
    );
    try std.testing.expectEqual(@as(usize, 1), jar.endSession());
    try std.testing.expectEqual(@as(usize, 1), jar.count());
    try std.testing.expectEqual(@as(usize, 0), jar.removeExpired(now + 9));
    try std.testing.expectEqual(@as(usize, 1), jar.removeExpired(now + 10));
}

test "CookieJar consumes repeated Set-Cookie from every unified protocol" {
    const allocator = std.testing.allocator;
    var empty: [0]u8 = .{};

    var h1_headers = [_]http1.Header{
        .{ .name = "Set-Cookie", .value = "a=1; Path=/" },
        .{ .name = "set-cookie", .value = "b=2; Path=/" },
    };
    try expectResponseCookies(.{
        .allocator = allocator,
        .value = .{ .http1 = .{
            .bytes = &empty,
            .response = .{
                .version = .http_1_1,
                .status = 200,
                .reason = "OK",
                .headers = &h1_headers,
                .body = &.{},
                .consumed = 0,
            },
        } },
    });

    var h2_headers = [_]http2.Hpack.HeaderField{
        .{ .name = "set-cookie", .value = "a=1; Path=/" },
        .{ .name = "set-cookie", .value = "b=2; Path=/" },
    };
    try expectResponseCookies(.{
        .allocator = allocator,
        .value = .{ .http2 = .{
            .headers = &h2_headers,
            .status = 200,
            .body = &empty,
        } },
    });

    var h3_headers = [_]http3.Qpack.HeaderField{
        .{ .name = "set-cookie", .value = "a=1; Path=/" },
        .{ .name = "set-cookie", .value = "b=2; Path=/" },
    };
    const h3_response = client_types.OwnedResponse{
        .allocator = allocator,
        .value = .{ .http3 = .{
            .stream_bytes = &empty,
            .response = .{
                .status = 200,
                .headers = &h3_headers,
                .body = &.{},
                .consumed = 0,
            },
        } },
    };
    try expectResponseCookies(h3_response);

    var final_uri = "https://final.example/docs/page".*;
    const redirected = client_types.RedirectedResponse{
        .allocator = allocator,
        .response = h3_response,
        .final_uri = &final_uri,
        .redirect_count = 1,
    };
    var redirected_jar = try cookies.Jar.init(allocator, .{});
    defer redirected_jar.deinit();
    const summary = try redirected_jar.storeRedirectedResponse(
        redirected,
        now,
        .{},
    );
    try std.testing.expectEqual(@as(usize, 2), summary.stored);
    const final_value = try redirected_jar.cookieHeaderValueAlloc(
        allocator,
        "https://final.example/",
        now,
        .{},
    );
    defer allocator.free(final_value);
    try std.testing.expectEqualStrings("a=1; b=2", final_value);
    const initial_value = try redirected_jar.cookieHeaderValueAlloc(
        allocator,
        "https://example.com/",
        now,
        .{},
    );
    defer allocator.free(initial_value);
    try std.testing.expectEqualStrings("", initial_value);
}

fn expectResponseCookies(response: client_types.OwnedResponse) !void {
    const allocator = std.testing.allocator;
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    const summary = try jar.storeResponse(
        response,
        "https://example.com/",
        now,
        .{},
    );
    try std.testing.expectEqual(@as(usize, 2), summary.stored);
    try std.testing.expectEqual(@as(usize, 0), summary.ignored);
    try expectHeader(allocator, &jar, now, .{}, "a=1; b=2");
}

test "CookieJar rolls back allocation failures without leaks" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationScenario,
        .{},
    );
}

fn allocationScenario(allocator: std.mem.Allocator) !void {
    var jar = try cookies.Jar.init(allocator, .{
        .domain_policy = .unchecked,
    });
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://www.example.com/docs/page",
        "a=one; Domain=example.com; Path=/docs; Secure; HttpOnly",
        now,
    );
    _ = try jar.storeSetCookie(
        "https://www.example.com/docs/page",
        "a=two; Domain=example.com; Path=/docs; Secure; HttpOnly",
        now + 1,
    );
    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://www.example.com/docs/next",
        now + 1,
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings("a=two", value);
}

test "CookieJar validates finite configuration" {
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{ .max_cookies = 0 }),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{
            .max_cookies_per_domain = 0,
        }),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{ .max_cookie_bytes = 0 }),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{
            .max_cookie_bytes = cookies.maximum_cookie_bytes + 1,
        }),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{
            .max_lifetime_seconds = 0,
        }),
    );
    try std.testing.expectError(
        error.InvalidConfig,
        cookies.Jar.init(std.testing.allocator, .{ .max_header_bytes = 0 }),
    );

    var bounded = try cookies.Jar.init(std.testing.allocator, .{
        .max_header_bytes = 5,
    });
    defer bounded.deinit();
    _ = try bounded.storeSetCookie("https://example.com/", "a=123", now);
    _ = try bounded.storeSetCookie("https://example.com/", "b=1", now);
    var out: [32]u8 = undefined;
    try std.testing.expectError(
        error.HeaderTooLarge,
        bounded.cookieHeaderValueInto(
            "https://example.com/",
            now,
            .{},
            &out,
        ),
    );
}
