const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http_cookies = @import("../../http/cookies/mod.zig");
const runtime = @import("../runtime.zig");

fn requiredCookie(
    headers: []const http2.Hpack.HeaderField,
) !http2.Hpack.HeaderField {
    var result: ?http2.Hpack.HeaderField = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        if (result != null) return error.TestUnexpectedResult;
        result = header;
    }
    return result orelse error.TestUnexpectedResult;
}

test "WebSocket HTTP2 CookieJar covers accepted and rejected attempts" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var jar = try http_cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    const now = std.Io.Clock.real.now(io).toSeconds();
    _ = try jar.storeSetCookie(
        "ws://localhost/accepted",
        "seed=one; HttpOnly; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "ws://localhost/accepted",
        "deep=accepted; Path=/accepted",
        now,
    );
    _ = try jar.storeSetCookie(
        "wss://localhost/accepted",
        "secure=secret; Secure; Path=/",
        now,
    );
    _ = try jar.storeSetCookie(
        "ws://victim.example/accepted",
        "victim=secret; Path=/",
        now,
    );

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();

            {
                var pending = try runtime.H2Server
                    .receiveUpgradeRequestWithTimeout(
                    self.server.allocator,
                    &h2,
                    .{},
                    .fromSeconds(3),
                );
                var pending_owned = true;
                defer if (pending_owned) pending.deinit();
                try std.testing.expectEqualStrings(
                    "/accepted?token=a%2Fb",
                    pending.target(),
                );
                const cookie = try requiredCookie(pending.headers());
                try std.testing.expectEqualStrings(
                    "deep=accepted; seed=one",
                    cookie.value,
                );
                try std.testing.expect(cookie.never_index);
                var ws = try pending.acceptWithHeaders(&.{.{
                    .name = "set-cookie",
                    .value = "accepted=two; Path=/",
                }});
                pending_owned = false;
                ws.close();
            }

            {
                var pending = try runtime.H2Server
                    .receiveUpgradeRequestWithTimeout(
                    self.server.allocator,
                    &h2,
                    .{},
                    .fromSeconds(3),
                );
                var pending_owned = true;
                defer if (pending_owned) pending.deinit();
                try std.testing.expectEqualStrings(
                    "/rejected",
                    pending.target(),
                );
                const cookie = try requiredCookie(pending.headers());
                try std.testing.expectEqualStrings(
                    "seed=one; accepted=two",
                    cookie.value,
                );
                try std.testing.expect(cookie.never_index);
                try pending.reject(401, &.{.{
                    .name = "set-cookie",
                    .value = "rejected=three; Path=/",
                }});
                pending_owned = false;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2 = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2.close();

    try std.testing.expectError(
        error.InvalidUri,
        runtime.H2Client.openAttempt(allocator, &h2, .{
            .authority = "localhost",
            .path = "missing-leading-slash",
            .cookies = .{ .jar = &jar },
        }),
    );
    try std.testing.expectError(
        error.CookieHeaderConflict,
        runtime.H2Client.openAttempt(allocator, &h2, .{
            .authority = "localhost",
            .path = "/caller-cookie",
            .extra_headers = &.{.{
                .name = "Cookie",
                .value = "caller=ambiguous",
            }},
            .cookies = .{ .jar = &jar },
        }),
    );

    var accepted = try runtime.H2Client.openAttempt(allocator, &h2, .{
        .authority = "localhost",
        .path = "/accepted?token=a%2Fb",
        .cookies = .{ .jar = &jar },
    });
    try std.testing.expect(accepted.accepted());
    accepted.deinit();

    var rejected = try runtime.H2Client.openAttempt(allocator, &h2, .{
        .authority = "localhost",
        .path = "/rejected",
        .cookies = .{ .jar = &jar },
    });
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 401), rejected.status());

    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        "ws://localhost/final",
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(
        "seed=one; accepted=two; rejected=three",
        value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
