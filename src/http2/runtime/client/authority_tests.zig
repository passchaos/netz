const std = @import("std");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const net = std.Io.net;

test "HTTP/2 IP authority validates budgets before allocation or network" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = failing.allocator();
    try std.testing.expectError(error.InvalidSetting, runtime.Client.connect(allocator, undefined, .{ .ip4 = .loopback(9) }, .{ .max_frame_size = 0 }));
    try std.testing.expectError(error.Timeout, runtime.Client.connect(allocator, undefined, .{ .ip4 = .loopback(9) }, .{ .connect_timeout = .zero }));
    try std.testing.expectError(error.Timeout, runtime.Client.connectWithTimeout(allocator, undefined, .{ .ip4 = .loopback(9) }, .{}, .zero));
    try std.testing.expectError(error.Timeout, runtime.Client.connectWithDeadline(allocator, undefined, .{ .ip4 = .loopback(9) }, .{}, .{ .clock = .real, .raw = .zero }));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectError(error.OutOfMemory, runtime.Client.connect(allocator, undefined, .{ .ip4 = .loopback(9) }, .{ .connect_timeout = null }));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "HTTP/2 IP authority rejects conflicting Host without output or stream admission" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const authority = try allocator.dupe(u8, "127.0.0.1:80");
    defer allocator.free(authority);
    var connection: runtime.Connection = .{ .allocator = failing.allocator(), .io = undefined, .stream = undefined, .role = .client, .default_authority = authority, .default_authority_is_ip = true, .default_scheme = "http" };
    const headers = [_]http2.Hpack.HeaderField{.{ .name = "host", .value = "virtual.test" }};
    try std.testing.expectEqualStrings("virtual.test", connection.resolveRequestAuthorityFromHeaders(null, &headers).?);
    try std.testing.expectEqualStrings("explicit.test", connection.resolveRequestAuthorityFromHeaders("explicit.test", &headers).?);
    try std.testing.expectError(error.InvalidHeader, connection.request(.{ .path = "/conflict", .authority = "explicit.test", .headers = &headers }));
    try std.testing.expectError(error.InvalidHeader, connection.request(.{ .path = "/duplicate", .headers = &.{ headers[0], headers[0] } }));
    connection.default_authority_is_ip = false;
    try std.testing.expectEqualStrings("127.0.0.1:80", connection.resolveRequestAuthorityFromHeaders(null, &headers).?);
    try std.testing.expectError(error.InvalidHeader, connection.request(.{ .path = "/bound-origin", .headers = &headers }));
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(!failing.has_induced_failure);
}

test "HTTP/2 IP authority survives later handshake allocation failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const FailureAfterConnect = struct {
        var parent: std.Io = undefined;
        var target: *std.testing.FailingAllocator = undefined;
        var connected: bool = false;
        fn connect(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
            const socket = try parent.vtable.netConnectIp(userdata, address, options);
            connected = true;
            target.fail_index = target.alloc_index;
            return socket;
        }
    };
    FailureAfterConnect.parent = io;
    FailureAfterConnect.target = &failing;
    FailureAfterConnect.connected = false;
    var vtable = io.vtable.*;
    vtable.netConnectIp = FailureAfterConnect.connect;
    const client_io: std.Io = .{ .userdata = io.userdata, .vtable = &vtable };
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(.fromSeconds(3)) catch |err| {
                if (err != error.ConnectionClosed and err != error.SocketUnconnected and err != error.ConnectionResetByPeer) self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequestWithTimeout(.fromSeconds(3)) catch |err| {
                if (err != error.ConnectionClosed and err != error.ConnectionResetByPeer) self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared: Shared = .{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(error.OutOfMemory, runtime.Client.connect(failing.allocator(), client_io, server.address(), .{}));
    thread.join();
    joined = true;
    if (shared.err) |err| {
        std.debug.print("HTTP/2 failed-setup peer: {s}\n", .{@errorName(err)});
        return err;
    }
    try std.testing.expect(FailureAfterConnect.connected);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(failing.allocated_bytes != 0);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

const Kind = enum { plain, timeout, deadline };

test "HTTP/2 IP authority covers IPv4 and IPv6 across every TCP constructor" {
    for ([_]Kind{ .plain, .timeout, .deadline }) |kind| {
        try roundTrip(.{ .ip4 = .loopback(0) }, kind);
        try roundTrip(.{ .ip6 = .loopback(0) }, kind);
    }
}

fn headerValue(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |field| if (std.mem.eql(u8, field.name, name)) return field.value;
    return null;
}

fn roundTrip(bind: net.IpAddress, kind: Kind) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, bind, .{ .max_concurrent_streams = 2 });
    defer server.deinit();
    var expected_buffer: [64]u8 = undefined;
    const address = server.address();
    const expected = switch (address) {
        .ip4 => |ip| try std.fmt.bufPrint(&expected_buffer, "127.0.0.1:{d}", .{ip.port}),
        .ip6 => |ip| try std.fmt.bufPrint(&expected_buffer, "[::1]:{d}", .{ip.port}),
    };
    const Shared = struct {
        server: *runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            const authorities = [_][]const u8{ self.expected, "virtual.test:8443", "host.test:8080", "stream.test", self.expected, "batch.test", self.expected };
            for (authorities, 0..) |authority, index| {
                var request = try connection.readRequestWithTimeout(.fromSeconds(3));
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(authority, headerValue(request.headers, ":authority").?);
                try std.testing.expectEqualStrings(if (index == 1) "https" else "http", headerValue(request.headers, ":scheme").?);
                try connection.writeResponse(request.stream_id, .{ .body = "ok" });
            }
        }
    };
    var shared: Shared = .{ .server = &server, .expected = expected };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = switch (kind) {
        .plain => try runtime.Client.connect(allocator, io, address, .{}),
        .timeout => try runtime.Client.connectWithTimeout(allocator, io, address, .{}, .fromSeconds(3)),
        .deadline => try runtime.Client.connectWithDeadline(allocator, io, address, .{}, .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake })),
    };
    defer client.close();
    try std.testing.expectEqualStrings(expected, client.resolveRequestAuthority(null).?);
    const requests = [_]runtime.RequestOptions{
        .{ .path = "/default" },
        .{ .path = "/explicit", .authority = "virtual.test:8443", .scheme = "https" },
        .{ .path = "/host", .headers = &.{.{ .name = "host", .value = "host.test:8080" }} },
    };
    for (requests) |request| {
        var response = try client.request(request);
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("ok", response.body);
    }
    var writer = try client.startRequest(.{ .method = "POST", .path = "/stream", .headers = &.{.{ .name = "host", .value = "stream.test" }} });
    defer writer.deinit();
    try writer.write("payload");
    try writer.finish();
    var streamed = try writer.readResponse();
    defer streamed.deinit(allocator);
    var responses: [2]runtime.OwnedResponse = undefined;
    try client.requestBatchIntoWithTimeout(&.{ .{ .path = "/batch/default" }, .{ .path = "/batch/host", .headers = &.{.{ .name = "host", .value = "batch.test" }} } }, &responses, .fromSeconds(3));
    defer for (&responses) |*response| response.deinit(allocator);
    for (responses) |response| try std.testing.expectEqualStrings("ok", response.body);
    var final = try client.request(.{ .path = "/after" });
    defer final.deinit(allocator);
    try std.testing.expectEqualStrings(expected, client.resolveRequestAuthority(null).?);
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
