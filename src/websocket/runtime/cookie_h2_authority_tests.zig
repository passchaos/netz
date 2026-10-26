const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const cookies = @import("../../http/cookies/mod.zig");
const runtime = @import("../runtime.zig");

test "WebSocket HTTP2 CookieJar follows Host over an implicit IP authority" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var jar = try cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    const now = std.Io.Clock.real.now(io).toSeconds();
    _ = try jar.storeSetCookie("ws://virtual.test/cookie", "virtual=one; HttpOnly; Path=/", now);
    _ = try jar.storeSetCookie("ws://127.0.0.1/cookie", "numeric=two; HttpOnly; Path=/", now);
    var server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .enable_connect_protocol = true });
    defer server.deinit();
    const Shared = struct {
        server: *http2.runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var pending = try runtime.H2Server.receiveUpgradeRequestWithTimeout(self.server.allocator, &connection, .{}, .fromSeconds(3));
            var live = true;
            defer if (live) pending.deinit();
            var seen_authority = false;
            var seen_cookie = false;
            for (pending.headers()) |header| {
                if (std.mem.eql(u8, header.name, ":authority")) {
                    try std.testing.expectEqualStrings("virtual.test", header.value);
                    seen_authority = true;
                }
                if (std.mem.eql(u8, header.name, "cookie")) {
                    try std.testing.expectEqualStrings("virtual=one", header.value);
                    try std.testing.expect(header.never_index);
                    seen_cookie = true;
                }
            }
            try std.testing.expect(seen_authority and seen_cookie);
            var websocket = try pending.accept();
            live = false;
            websocket.close();
        }
    };
    var shared: Shared = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var connection = try http2.runtime.Client.connect(allocator, io, server.address(), .{});
    defer connection.close();
    var attempt = try runtime.H2Client.openAttempt(allocator, &connection, .{ .path = "/cookie", .extra_headers = &.{.{ .name = "host", .value = "virtual.test" }}, .cookies = .{ .jar = &jar } });
    defer attempt.deinit();
    try std.testing.expect(attempt.accepted());
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
