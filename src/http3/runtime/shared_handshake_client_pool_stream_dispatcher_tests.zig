//! Streaming command channel through the shared request dispatcher.

const std = @import("std");
const runtime = @import("../runtime.zig");
const http3 = @import("../mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared dispatcher streams a request and response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    var request_body: [700]u8 = undefined;
    for (&request_body, 0..) |*byte, index| byte.* = @truncate(index);
    var response_body: [4000]u8 = undefined;
    for (&response_body, 0..) |*byte, index| byte.* = @truncate(index *% 7);

    const Worker = struct {
        server: *runtime.HandshakeServer,
        request_body: []const u8,
        response_body: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/stream", request.request.path);
            try std.testing.expectEqualStrings(
                self.request_body,
                request.request.body,
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                request.request.trailers.len,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200, .request_method = "POST" },
                self.response_body.len,
            );
            var offset: usize = 0;
            while (offset < self.response_body.len) {
                const end = @min(offset + 512, self.response_body.len);
                try session.sendResponseBodyPaced(
                    request.stream_id,
                    self.response_body[offset..end],
                    false,
                );
                offset = end;
            }
            try session.finishResponseTrailersPaced(
                request.stream_id,
                &.{.{ .name = "x-response", .value = "complete" }},
            );
        }
    };

    var worker = Worker{
        .server = &server,
        .request_body = &request_body,
        .response_body = &response_body,
    };
    const server_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 4096,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    var dispatcher = try runtime.SharedHandshakeClientPoolRequestDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_active_connections = 1 },
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();
    var driver = try std.Io.concurrent(
        io,
        runtime.SharedHandshakeClientPoolRequestDispatcher.run,
        .{&dispatcher},
    );
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
        driver.await(io) catch {};
    };

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/stream",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    const authority = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(authority);

    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(5),
    });
    var handle = try sender.startStream(
        uri,
        null,
        .{
            .method = "POST",
            .path = "/stream",
            .scheme = "https",
            .authority = authority,
        },
        request_body.len,
        deadline,
    );
    var handle_active = true;
    defer if (handle_active) handle.deinit();

    var sink = CollectSink{ .allocator = allocator };
    defer sink.deinit();
    var written: usize = 0;
    while (written < request_body.len) {
        const end = @min(written + 128, request_body.len);
        try handle.writeBody(request_body[written..end], false);
        written = end;
    }
    try handle.writeTrailers(&.{
        .{ .name = "x-upload", .value = "complete" },
    });
    const head = try handle.readResponse(sink.sink(), deadline);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqualSlices(
        u8,
        &response_body,
        sink.body.items,
    );
    try std.testing.expectEqualStrings("x-response", sink.trailer_name.items);
    try std.testing.expectEqualStrings("complete", sink.trailer_value.items);

    handle_active = false;
    handle.deinit();
    dispatcher.close();
    driver.cancel(io) catch {};
    driver.await(io) catch {};
    driver_active = false;
    dispatcher_active = false;
    dispatcher.deinit();
    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
}

const CollectSink = struct {
    allocator: std.mem.Allocator,
    body: std.ArrayList(u8) = .empty,
    trailer_name: std.ArrayList(u8) = .empty,
    trailer_value: std.ArrayList(u8) = .empty,

    fn sink(
        self: *CollectSink,
    ) runtime.SharedHandshakeClientPoolRequestDispatcher.StreamHandle.Sink {
        return .{
            .context = self,
            .begin = begin,
            .data = data,
            .end = end,
        };
    }

    fn begin(
        _: *anyopaque,
        _: http3.DecodedResponseHead,
    ) !void {}

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *CollectSink = @ptrCast(@alignCast(context));
        try self.body.appendSlice(self.allocator, bytes);
    }

    fn end(
        context: *anyopaque,
        trailers: []const http3.Qpack.HeaderField,
    ) !void {
        const self: *CollectSink = @ptrCast(@alignCast(context));
        if (trailers.len == 0) return;
        try self.trailer_name.appendSlice(
            self.allocator,
            trailers[0].name,
        );
        try self.trailer_value.appendSlice(
            self.allocator,
            trailers[0].value,
        );
    }

    fn deinit(self: *CollectSink) void {
        self.body.deinit(self.allocator);
        self.trailer_name.deinit(self.allocator);
        self.trailer_value.deinit(self.allocator);
    }
};
