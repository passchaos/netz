const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const http2 = @import("../../../http2/mod.zig");
const http2_runtime = @import("../../../http2/runtime.zig");
const runtime = @import("../../runtime.zig");

const large_header_count: usize = 80;
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn countHttp1Headers(
    headers: []const http1.Header,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, name));
    }
    return count;
}

fn countHttp2Headers(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(header.name, name));
    }
    return count;
}

test "WebSocket HTTP1 carries 80 request and response headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var request_headers: [large_header_count]http1.Header = undefined;
    var response_headers: [large_header_count]http1.Header = undefined;
    for (&request_headers) |*header| {
        header.* = .{ .name = "X-Many-Request", .value = large_header_value };
    }
    for (&response_headers) |*header| {
        header.* = .{ .name = "X-Many-Response", .value = large_header_value };
    }
    const limits: runtime.Limits = .{
        .max_head_bytes = 16 * 1024,
        .max_request_headers = 100,
        .max_response_headers = 100,
    };
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        response_headers: []const http1.Header,
        client_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.client_done.set(self.server.http.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveUpgradeRequestWithTimeout(
                .{},
                .fromSeconds(3),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqual(
                large_header_count,
                countHttp1Headers(pending.headers(), "x-many-request"),
            );
            var connection = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer connection.close();
            try self.client_done.wait(self.server.http.io);
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.client_done.set(io);
        thread.join();
    };

    var client = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        server.address(),
        .{
            .host = "localhost",
            .target = "/many-headers",
            .extra_headers = &request_headers,
            .limits = limits,
        },
        .fromSeconds(3),
    );
    client.close();
    shared.client_done.set(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 carries 80 request and response headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var request_headers: [large_header_count]http2.Hpack.HeaderField =
        undefined;
    var response_headers: [large_header_count]http2.Hpack.HeaderField =
        undefined;
    for (&request_headers) |*header| {
        header.* = .{
            .name = "x-many-request",
            .value = large_header_value,
            .never_index = true,
        };
    }
    for (&response_headers) |*header| {
        header.* = .{
            .name = "x-many-response",
            .value = large_header_value,
            .never_index = true,
        };
    }
    const h2_limits: http2_runtime.Limits = .{
        .max_header_fields = 256,
        .max_header_list_size = 16 * 1024,
        .enable_connect_protocol = true,
    };
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h2_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        response_headers: []const http2.Hpack.HeaderField,
        client_done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.client_done.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection
                .readExtendedConnectRequestWithTimeout(
                "websocket",
                .fromSeconds(3),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqual(
                large_header_count,
                countHttp2Headers(request.headers, "x-many-request"),
            );
            _ = try connection.acceptExtendedConnect(
                request,
                self.response_headers,
            );
            try self.client_done.wait(self.server.io);
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.client_done.set(io);
        thread.join();
    };

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        h2_limits,
    );
    defer h2_client.close();
    var websocket_client = try runtime.H2Client.openWithTimeout(
        allocator,
        &h2_client,
        .{
            .authority = "localhost",
            .path = "/many-headers",
            .extra_headers = &request_headers,
        },
        .fromSeconds(3),
    );
    websocket_client.close();
    shared.client_done.set(io);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
