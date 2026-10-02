const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const runtime_write = @import("write.zig");

const test_limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 4096,
};

fn expectImfFixdate(value: []const u8) !void {
    try std.testing.expectEqual(@as(usize, 29), value.len);
    try std.testing.expectEqual(@as(u8, ','), value[3]);
    try std.testing.expectEqual(@as(u8, ' '), value[4]);
    try std.testing.expectEqual(@as(u8, ' '), value[7]);
    try std.testing.expectEqual(@as(u8, ' '), value[11]);
    try std.testing.expectEqual(@as(u8, ' '), value[16]);
    try std.testing.expectEqual(@as(u8, ':'), value[19]);
    try std.testing.expectEqual(@as(u8, ':'), value[22]);
    try std.testing.expectEqualStrings(" GMT", value[25..29]);
}

test "HTTP/1 server adds Date to ordinary and streaming final responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        test_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var ordinary = try connection.readRequest(.{});
            defer ordinary.deinit(allocator);
            try connection.writeResponse(.{
                .body = "ordinary",
                .request_method = ordinary.request.method,
            });

            var streaming = try connection.readRequest(.{});
            defer streaming.deinit(allocator);
            var writer = try connection.startResponse(.{
                .body_length = "stream".len,
                .request_method = streaming.request.method,
            });
            try writer.write("stream");
            try writer.finish();

            var explicit = try connection.readRequest(.{});
            defer explicit.deinit(allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "dAtE",
                    .value = "Sun, 06 Nov 1994 08:49:37 GMT",
                }},
                .body = "explicit",
                .request_method = explicit.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        test_limits,
    );
    defer client.close();

    var ordinary = try client.request(.{
        .target = "/ordinary",
        .host = "localhost",
    });
    defer ordinary.deinit(allocator);
    try expectImfFixdate(ordinary.response.header("date").?);

    var streaming = try client.request(.{
        .target = "/streaming",
        .host = "localhost",
    });
    defer streaming.deinit(allocator);
    try expectImfFixdate(streaming.response.header("date").?);

    var explicit = try client.request(.{
        .target = "/explicit",
        .host = "localhost",
    });
    defer explicit.deinit(allocator);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        explicit.response.header("date").?,
    );
    try std.testing.expectEqual(@as(usize, 1), countHeaders(
        explicit.response.headers,
        "date",
    ));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 server Date can be disabled" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var limits = test_limits;
    limits.auto_date_header = false;
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
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
            defer request.deinit(allocator);
            try connection.writeResponse(.{
                .body = "disabled",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        test_limits,
    );
    defer client.close();
    var response = try client.request(.{
        .target = "/disabled",
        .host = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expect(response.response.header("date") == null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 server batch adds one Date per final response" {
    const allocator = std.testing.allocator;
    var scratch: runtime_write.Scratch = .{};
    defer scratch.deinit(allocator);

    var default_date = "Sun, 06 Nov 1994 08:49:37 GMT".*;
    const responses = [_]runtime.ResponseOptions{
        .{ .body = "one" },
        .{ .body = "two" },
    };
    const parts = try runtime_write.prepareServerResponseParts(
        allocator,
        &responses,
        &default_date,
        &scratch,
    );
    // Every head owns the encoded Date bytes; the caller's borrowed cache may
    // be refreshed immediately after this synchronous preparation returns.
    @memset(&default_date, 'x');
    var date_count: usize = 0;
    for (parts) |part| {
        var remaining = part;
        while (std.mem.indexOf(u8, remaining, "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n")) |index| {
            date_count += 1;
            remaining = remaining[index + "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n".len ..];
        }
    }
    try std.testing.expectEqual(@as(usize, 2), date_count);
}

test "HTTP/1 pure response codec does not add Date" {
    const allocator = std.testing.allocator;
    var scratch: runtime_write.Scratch = .{};
    defer scratch.deinit(allocator);

    const response = try runtime_write.prepareResponse(
        allocator,
        .{ .body = "codec" },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, response.header, "Date:") == null,
    );
    const streaming = try runtime_write.streaming.prepareResponse(
        allocator,
        .{ .body_length = 0 },
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, streaming.head, "Date:") == null,
    );
}

test "HTTP/1 server Date is final-response only" {
    const allocator = std.testing.allocator;
    var scratch: runtime_write.Scratch = .{};
    defer scratch.deinit(allocator);
    const default_date = "Sun, 06 Nov 1994 08:49:37 GMT";

    const informational = try runtime_write.prepareServerResponse(
        allocator,
        .{ .status = 103, .reason = "Early Hints" },
        default_date,
        &scratch,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, informational.header, "Date:") == null,
    );

    const switching = try runtime_write.prepareServerResponse(
        allocator,
        .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = &.{
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Upgrade", .value = "netz-test" },
            },
        },
        default_date,
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        switching.header,
        "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
    ) != null);
}

test "HTTP/1 server Date reuses warmed response scratch without allocation" {
    const allocator = std.testing.allocator;
    var scratch: runtime_write.Scratch = .{};
    defer scratch.deinit(allocator);
    const options: runtime.ResponseOptions = .{ .body = "warm" };
    const default_date = "Sun, 06 Nov 1994 08:49:37 GMT";

    _ = try runtime_write.prepareServerResponse(
        allocator,
        options,
        default_date,
        &scratch,
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const hot = try runtime_write.prepareServerResponse(
        no_alloc.allocator(),
        options,
        default_date,
        &scratch,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expect(std.mem.indexOf(
        u8,
        hot.header,
        "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
    ) != null);
}

test "HTTP/1 server Date follows response header casing" {
    const allocator = std.testing.allocator;
    var scratch: runtime_write.Scratch = .{};
    defer scratch.deinit(allocator);

    const response = try runtime_write.prepareServerResponse(
        allocator,
        .{
            .body = "title",
            .header_name_casing = .title_case,
        },
        "Sun, 06 Nov 1994 08:49:37 GMT",
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.header,
        "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
    ) != null);
}

fn countHeaders(headers: []const http1.Header, name: []const u8) usize {
    var count: usize = 0;
    for (headers) |header| {
        if (header.eqlName(name)) count += 1;
    }
    return count;
}
