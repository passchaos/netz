const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const http_cookies = @import("../../http/cookies/mod.zig");
const h3 = @import("h3.zig");

fn requiredCookie(
    headers: []const http3.Qpack.HeaderField,
) !http3.Qpack.HeaderField {
    var result: ?http3.Qpack.HeaderField = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        if (result != null) return error.TestUnexpectedResult;
        result = header;
    }
    return result orelse error.TestUnexpectedResult;
}

test "WebSocket HTTP3 URI CookieJar stores accepted response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x85} ** 32,
            .x25519_secret_key = [_]u8{0x86} ** 32,
        } },
    );
    defer server.deinit();

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/accepted",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);
    var jar = try http_cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        uri,
        "__Host-Http-seed=one; Secure; HttpOnly; Path=/",
        std.Io.Clock.real.now(io).toSeconds(),
    );

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/accepted",
                pending.target(),
            );
            const cookie = try requiredCookie(pending.headers());
            try std.testing.expectEqualStrings(
                "__Host-Http-seed=one",
                cookie.value,
            );
            try std.testing.expect(cookie.never_indexed);
            var connection = try pending.acceptWithHeaders(&.{.{
                .name = "set-cookie",
                .value = "__Http-accepted=two; Secure; HttpOnly; Path=/",
            }});
            pending_owned = false;
            defer connection.deinit();
            try connection.h3.waitForRecoveryIdleWithTimeout(
                .fromSeconds(2),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectUriAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .cookies = .{ .jar = &jar },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0x87} ** 32,
                .x25519_secret_key = [_]u8{0x88} ** 32,
            } },
        },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expect(attempt.accepted());

    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(
        "__Host-Http-seed=one; __Http-accepted=two",
        value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP3 CookieJar preflights and stores rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const client_handshake: http3.runtime.HandshakeClientOptions =
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb5} ** 32,
            .x25519_secret_key = [_]u8{0xb6} ** 32,
        } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb7} ** 32,
            .x25519_secret_key = [_]u8{0xb8} ** 32,
        } },
    );
    defer server.deinit();

    var jar = try http_cookies.Jar.init(allocator, .{});
    defer jar.deinit();
    const request_uri = "https://localhost/rejected?code=expired";
    _ = try jar.storeSetCookie(
        request_uri,
        "__Http-seed=one; Secure; HttpOnly; Path=/",
        std.Io.Clock.real.now(io).toSeconds(),
    );
    _ = try jar.storeSetCookie(
        request_uri,
        "deep=rejected; Secure; Path=/rejected",
        std.Io.Clock.real.now(io).toSeconds(),
    );
    _ = try jar.storeSetCookie(
        "https://victim.example/rejected",
        "victim=secret; Secure; Path=/",
        std.Io.Clock.real.now(io).toSeconds(),
    );

    // All three errors must precede socket creation and the QUIC handshake.
    // The one-shot server below therefore still observes exactly the later,
    // valid request rather than a stray preflight connection.
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            client_handshake,
            .{
                .authority = "localhost",
                .path = "missing-leading-slash",
                .cookies = .{ .jar = &jar },
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.CookieHeaderConflict,
        h3.Client.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            client_handshake,
            .{
                .authority = "localhost",
                .path = "/caller-cookie",
                .extra_headers = &.{.{
                    .name = "Cookie2",
                    .value = "caller=ambiguous",
                }},
                .cookies = .{ .jar = &jar },
            },
            .fromSeconds(3),
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        h3.Client.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{},
            client_handshake,
            .{
                .authority = "user@localhost",
                .path = "/invalid-authority",
                .cookies = .{ .jar = &jar },
            },
            .fromSeconds(3),
        ),
    );

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/rejected?code=expired",
                pending.target(),
            );
            const cookie = try requiredCookie(pending.headers());
            try std.testing.expectEqualStrings(
                "deep=rejected; __Http-seed=one",
                cookie.value,
            );
            try std.testing.expect(cookie.never_indexed);
            try pending.rejectWithBody(
                401,
                &.{.{
                    .name = "set-cookie",
                    .value = "__Host-Http-rejected=two; Secure; HttpOnly; Path=/",
                }},
                "denied",
                &.{},
            );
            pending_owned = false;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try h3.Client.connectAttemptWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        client_handshake,
        .{
            .authority = "localhost",
            .path = "/rejected?code=expired",
            .cookies = .{ .jar = &jar },
        },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings("denied", attempt.body());

    const value = try jar.cookieHeaderValueAlloc(
        allocator,
        "https://localhost/final",
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(value);
    try std.testing.expectEqualStrings(
        "__Http-seed=one; __Host-Http-rejected=two",
        value,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
