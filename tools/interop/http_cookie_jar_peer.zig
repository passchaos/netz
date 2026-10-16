//! Deterministic Netz CookieJar arm for the independent curl comparison.

const std = @import("std");
const netz = @import("netz");

const now: i64 = 1_700_000_000;

pub fn main(_: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    var jar = try netz.http.CookieJar.init(allocator, .{});
    defer jar.deinit();

    _ = try jar.storeSetCookie(
        "http://127.0.0.1/docs/seed",
        "root=one; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "http://127.0.0.1/docs/seed",
        "docs=two",
        now,
    );
    _ = try jar.storeSetCookie(
        "http://127.0.0.1/docs/seed",
        "deep=three; Path=/docs/deep",
        now,
    );

    const ordinary = try jar.cookieHeaderValueAlloc(
        allocator,
        "http://127.0.0.1/docs/item",
        now,
        .{},
    );
    defer allocator.free(ordinary);
    const deep = try jar.cookieHeaderValueAlloc(
        allocator,
        "http://127.0.0.1/docs/deep/item",
        now,
        .{},
    );
    defer allocator.free(deep);
    std.debug.print(
        "ordinary={s}\ndeep={s}\nclient_io=netz-cookie-jar\n",
        .{ ordinary, deep },
    );
}
