//! Deterministic Netz CookieJar arm for the independent curl comparison.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 1 and args.len != 3) return error.InvalidArgument;
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const now = std.Io.Clock.real.now(io).toSeconds();
    var jar = try netz.http.CookieJar.init(allocator, .{});
    defer jar.deinit();
    if (args.len == 3 and std.mem.eql(u8, args[1], "--import")) {
        try jar.loadNetscapeLossy(
            io,
            std.Io.Dir.cwd(),
            args[2],
            now,
            .{
                .acknowledge_metadata_loss = true,
                .include_session = true,
            },
        );
    } else {
        if (args.len == 3 and !std.mem.eql(u8, args[1], "--export")) {
            return error.InvalidArgument;
        }
        _ = try jar.storeSetCookie(
            "http://127.0.0.1/docs/seed",
            "root=one; Path=/; Max-Age=3600",
            now,
        );
        _ = try jar.storeSetCookie(
            "http://127.0.0.1/docs/seed",
            "docs=two; Max-Age=3600",
            now,
        );
        _ = try jar.storeSetCookie(
            "http://127.0.0.1/docs/seed",
            "deep=three; Path=/docs/deep; Max-Age=3600",
            now,
        );
        if (args.len == 3) try jar.saveNetscapeAtomicLossy(
            io,
            std.Io.Dir.cwd(),
            args[2],
            now,
            .{ .acknowledge_metadata_loss = true },
        );
    }

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
