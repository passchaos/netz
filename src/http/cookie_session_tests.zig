const std = @import("std");
const http = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = @import("../http1/runtime.zig");
const http2 = @import("../http2/mod.zig");
const http2_runtime = @import("../http2/runtime.zig");

test "CookieSession applies intermediate redirect cookies before next hop" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Worker = struct {
        server: *http1_runtime.Server,
        release: std.Io.Event = .unset,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for (0..3) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                const expected_target = switch (index) {
                    0 => "/start",
                    1 => "/next",
                    else => "/check",
                };
                try std.testing.expectEqualStrings(
                    expected_target,
                    request.request.target,
                );
                const cookie = request.request.header("cookie");
                switch (index) {
                    0 => {
                        try std.testing.expectEqual(
                            http1.Method.POST,
                            request.request.method,
                        );
                        try std.testing.expect(cookie == null);
                    },
                    1 => try std.testing.expectEqualStrings(
                        "preexisting=blocked; step=one",
                        cookie.?,
                    ),
                    else => try std.testing.expectEqualStrings(
                        "preexisting=blocked; step=one; final=two",
                        cookie.?,
                    ),
                }
                if (index == 0) {
                    try connection.writeResponse(.{
                        .status = 302,
                        .reason = "Found",
                        .headers = &.{
                            .{ .name = "location", .value = "/next" },
                            .{
                                .name = "set-cookie",
                                .value = "step=one; Path=/; SameSite=Lax",
                            },
                        },
                        .request_method = request.request.method,
                    });
                } else if (index == 1) {
                    try connection.writeResponse(.{
                        .headers = &.{.{
                            .name = "set-cookie",
                            .value = "final=two; Path=/",
                        }},
                        .body = "redirect-complete",
                        .request_method = request.request.method,
                    });
                } else {
                    try connection.writeResponse(.{
                        .body = "cookie-reused",
                        .request_method = request.request.method,
                    });
                }
                self.requests += 1;
            }
            try self.release.wait(self.server.io);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        worker.release.set(io);
        thread.join();
    };

    var session = try http.CookieSession.init(allocator, io, .{}, .{});
    defer session.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const start_uri = try std.fmt.allocPrint(allocator, "{s}/start", .{base});
    defer allocator.free(start_uri);
    const check_uri = try std.fmt.allocPrint(allocator, "{s}/check", .{base});
    defer allocator.free(check_uri);

    _ = try session.jar.storeSetCookie(
        start_uri,
        "preexisting=blocked; Path=/; SameSite=Lax",
        std.Io.Clock.real.now(io).toSeconds(),
    );

    try std.testing.expectError(
        error.CookieHeaderConflict,
        session.requestUri(start_uri, .{ .headers = &.{.{
            .name = "Cookie",
            .value = "caller=forbidden",
        }} }, .{}),
    );
    var redirected = try session.requestUriFollowingRedirectsDetailedWithTimeout(
        start_uri,
        .{ .method = "POST" },
        .{},
        .{ .request_context = .{
            .site = .cross_site,
            .top_level_navigation = true,
        } },
        .fromSeconds(5),
    );
    defer redirected.deinit();
    try std.testing.expectEqual(@as(usize, 1), redirected.redirect_count);
    try std.testing.expectEqualStrings(
        "redirect-complete",
        redirected.response.body(),
    );
    try std.testing.expect(std.mem.endsWith(
        u8,
        redirected.final_uri,
        "/next",
    ));
    var reused = try session.requestUriWithTimeout(
        check_uri,
        .{},
        .{},
        .fromSeconds(5),
    );
    defer reused.deinit();
    try std.testing.expectEqualStrings("cookie-reused", reused.body());
    try std.testing.expectEqual(@as(usize, 3), session.jar.count());
    try std.testing.expectEqual(@as(usize, 1), session.pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), session.pool.idleCount());

    worker.release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), worker.requests);
}

test "CookieSession marks HTTP2 Cookie fields Never Indexed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Worker = struct {
        server: *http2_runtime.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for (0..2) |index| {
                var request = try connection.readRequest();
                defer request.deinit(self.server.allocator);
                const cookie = findH2Header(request.headers, "cookie");
                if (index == 0) {
                    try std.testing.expect(cookie == null);
                    try connection.writeResponse(request.stream_id, .{
                        .headers = &.{.{
                            .name = "set-cookie",
                            .value = "h2=state; Path=/",
                        }},
                        .body = "seeded",
                        .request_method = request.method,
                    });
                } else {
                    try std.testing.expectEqualStrings("h2=state", cookie.?.value);
                    try std.testing.expect(cookie.?.never_index);
                    try connection.writeResponse(request.stream_id, .{
                        .body = "observed",
                        .request_method = request.method,
                    });
                }
            }
            try self.release.wait(self.server.io);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        worker.release.set(io);
        thread.join();
    };

    var session = try http.CookieSession.init(allocator, io, .{
        .client = .{ .cleartext_protocol = .http2_prior_knowledge },
    }, .{});
    defer session.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    var first = try session.requestUriWithTimeout(
        base,
        .{},
        .{},
        .fromSeconds(5),
    );
    defer first.deinit();
    try std.testing.expectEqualStrings("seeded", first.body());
    var second = try session.requestUriWithTimeout(
        base,
        .{},
        .{},
        .fromSeconds(5),
    );
    defer second.deinit();
    try std.testing.expectEqualStrings("observed", second.body());

    worker.release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "CookieSession isolates cookies and credentials across redirect origins" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer first_server.deinit();
    var second_server = try http1_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer second_server.deinit();
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "http://localhost:{d}/landing",
        .{second_server.address().ip4.port},
    );
    defer allocator.free(second_uri);

    const FirstWorker = struct {
        server: *http1_runtime.Server,
        location: []const u8,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/start", request.request.target);
            try std.testing.expectEqualStrings(
                "Bearer origin-a",
                request.request.header("authorization").?,
            );
            try std.testing.expect(request.request.header("cookie") == null);
            try connection.writeResponse(.{
                .status = 302,
                .reason = "Found",
                .headers = &.{
                    .{ .name = "location", .value = self.location },
                    .{
                        .name = "set-cookie",
                        .value = "origin_a=one; Path=/",
                    },
                },
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    const SecondWorker = struct {
        server: *http1_runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/landing",
                request.request.target,
            );
            try std.testing.expect(request.request.header("authorization") == null);
            try std.testing.expect(request.request.header("cookie") == null);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "set-cookie",
                    .value = "origin_b=two; Path=/",
                }},
                .body = "second-origin",
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var first_worker = FirstWorker{
        .server = &first_server,
        .location = second_uri,
        .release = &release,
    };
    var second_worker = SecondWorker{
        .server = &second_server,
        .release = &release,
    };
    const first_thread = try std.Thread.spawn(
        .{},
        FirstWorker.run,
        .{&first_worker},
    );
    var first_joined = false;
    defer if (!first_joined) {
        release.set(io);
        first_thread.join();
    };
    const second_thread = try std.Thread.spawn(
        .{},
        SecondWorker.run,
        .{&second_worker},
    );
    var second_joined = false;
    defer if (!second_joined) {
        release.set(io);
        second_thread.join();
    };

    var session = try http.CookieSession.init(allocator, io, .{}, .{});
    defer session.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/start",
        .{first_server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    var response = try session.requestUriFollowingRedirectsDetailedWithTimeout(
        first_uri,
        .{ .headers = &.{.{
            .name = "authorization",
            .value = "Bearer origin-a",
            .never_indexed = true,
        }} },
        .{},
        .{
            .request_context = .{ .top_level_navigation = true },
            .store_context = .{ .top_level_navigation = true },
        },
        .fromSeconds(5),
    );
    defer response.deinit();
    try std.testing.expectEqualStrings("second-origin", response.response.body());
    try std.testing.expectEqual(@as(usize, 1), response.redirect_count);

    const first_cookie = try session.jar.cookieHeaderValueAlloc(
        allocator,
        first_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(first_cookie);
    try std.testing.expectEqualStrings("origin_a=one", first_cookie);
    const second_cookie = try session.jar.cookieHeaderValueAlloc(
        allocator,
        second_uri,
        std.Io.Clock.real.now(io).toSeconds(),
        .{},
    );
    defer allocator.free(second_cookie);
    try std.testing.expectEqualStrings("origin_b=two", second_cookie);

    release.set(io);
    first_thread.join();
    first_joined = true;
    second_thread.join();
    second_joined = true;
    if (first_worker.err) |err| return err;
    if (second_worker.err) |err| return err;
}

fn findH2Header(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?http2.Hpack.HeaderField {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header;
    }
    return null;
}
