const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");
const headers = @import("headers.zig");

const operation_timeout: std.Io.Duration = .fromSeconds(3);
const large_header_count: usize = 80;
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn fillHeaders(
    fields: []http3.Qpack.HeaderField,
    name: []const u8,
) void {
    for (fields) |*field| {
        field.* = .{
            .name = name,
            .value = large_header_value,
            .never_indexed = true,
        };
    }
}

fn countHeaders(
    fields: []const http3.Qpack.HeaderField,
    name: []const u8,
) usize {
    var count: usize = 0;
    for (fields) |field| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(field.name, name));
    }
    return count;
}

test "WebTransport development CONNECT carries 80 request and response headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_headers: [large_header_count]http3.Qpack.HeaderField =
        undefined;
    var response_headers: [large_header_count]http3.Qpack.HeaderField =
        undefined;
    fillHeaders(&request_headers, "x-many-request");
    fillHeaders(&response_headers, "x-many-response");

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{
            .quic = .{ .max_datagram_size = 1200 },
            .max_stream_frame_data = 1200,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequestWithTimeout(
                operation_timeout,
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqual(
                large_header_count,
                countHeaders(pending.headers(), "x-many-request"),
            );
            var accepted = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer accepted.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.ClientSession.connectWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/many-development",
            .headers = &request_headers,
            .limits = .{ .http3 = .{
                .quic = .{ .max_datagram_size = 1200 },
                .max_stream_frame_data = 1200,
            } },
        },
        operation_timeout,
    );
    defer client.deinit();
    try std.testing.expectEqual(
        large_header_count,
        countHeaders(client.response.headers, "x-many-response"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected CONNECT carries 80 request and response headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x89} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8a} ** quic.protection.secret_len,
    );
    var request_headers: [large_header_count]http3.Qpack.HeaderField =
        undefined;
    var response_headers: [large_header_count]http3.Qpack.HeaderField =
        undefined;
    fillHeaders(&request_headers, "x-many-request");
    fillHeaders(&response_headers, "x-many-response");

    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 1200,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_frame_data = 1200,
            .max_frames_per_packet = 4,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        response_headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequestWithTimeout(
                operation_timeout,
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqual(
                large_header_count,
                countHeaders(pending.headers(), "x-many-request"),
            );
            var accepted = try pending.acceptWithHeaders(
                self.response_headers,
            );
            pending_owned = false;
            defer accepted.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .response_headers = &response_headers,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.ProtectedClientSession.connectWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/many-protected",
            .headers = &request_headers,
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 1200,
                .max_frames_per_datagram = 8,
            } } },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_stream_frame_data = 1200,
                .max_frames_per_packet = 4,
            },
        },
        operation_timeout,
    );
    defer client.deinit();
    try std.testing.expectEqual(
        large_header_count,
        countHeaders(client.response.headers, "x-many-response"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport CONNECT capacity is governed by field section bytes" {
    const allocator = std.testing.allocator;
    var additional: [large_header_count]http3.Qpack.HeaderField = undefined;
    fillHeaders(&additional, "x-many");
    var stack: [headers.stack_capacity]http3.Qpack.HeaderField = undefined;
    var prepared = try headers.prepareRequest(
        allocator,
        "https://example.test",
        &additional,
        &stack,
    );
    defer prepared.deinit(allocator);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(
        error.ExcessiveLoad,
        (http3.Request{
            .method = "CONNECT",
            .path = "/limited",
            .authority = "example.test",
            .headers = prepared.fields,
        }).writeWithSettings(&encoded, allocator, .{
            .max_field_section_size = 256,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
}
