//! Duplex streaming request/response handle tests for HTTP/1, HTTP/2, and
//! HTTP/3.

const std = @import("std");
const http = @import("../mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");

const DuplexSink = struct {
    allocator: std.mem.Allocator,
    status: u16 = 0,
    header_count: usize = 0,
    body: std.ArrayList(u8) = .empty,
    trailer_count: usize = 0,
    trailer_name: std.ArrayList(u8) = .empty,
    trailer_value: std.ArrayList(u8) = .empty,
    informational_count: usize = 0,
    informational_status: u16 = 0,

    fn sink(self: *DuplexSink) http.ResponseSink {
        return .{
            .context = self,
            .begin = begin,
            .data = data,
            .end = end,
            .informational = observeInformational,
        };
    }

    fn observeInformational(
        context: *anyopaque,
        head: http.ResponseHead,
    ) void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        self.informational_count += 1;
        self.informational_status = head.status;
    }

    fn begin(context: *anyopaque, head: http.ResponseHead) !void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        self.status = head.status;
        self.header_count = head.headers.len;
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        try self.body.appendSlice(self.allocator, bytes);
    }

    fn end(context: *anyopaque, trailers: []const http.DuplexHeader) !void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        self.trailer_count = trailers.len;
        if (trailers.len != 0) {
            try self.trailer_name.appendSlice(
                self.allocator,
                trailers[0].name,
            );
            try self.trailer_value.appendSlice(
                self.allocator,
                trailers[0].value,
            );
        }
    }

    fn deinit(self: *DuplexSink) void {
        self.body.deinit(self.allocator);
        self.trailer_name.deinit(self.allocator);
        self.trailer_value.deinit(self.allocator);
    }
};

test "HTTP/1 duplex handle streams request and response" {
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
        const Self = @This();
        server: *http1_runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *Self) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *Self) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "hello world",
                request.request.body,
            );
            try connection.writeResponse(.{
                .status = 103,
                .reason = "Early Hints",
                .headers = &.{.{
                    .name = "link",
                    .value = "</style.css>; rel=preload",
                }},
            });
            var response = try connection.startResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body_length = null,
                .trailer_names = &.{"x-checksum"},
                .request_accepts_trailers = true,
                .request_method = .POST,
            });
            try response.write("resp-1");
            try response.write("resp-2");
            try response.finishTrailers(&.{.{
                .name = "x-checksum",
                .value = "1",
            }});
            try self.release.wait(self.server.io);
        }
    };

    var release: std.Io.Event = .unset;
    var worker = Worker{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        thread.join();
    };

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);

    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();
    var handle = try connection.startRequest("/upload", .{
        .method = "POST",
        .headers = &.{.{ .name = "te", .value = "trailers" }},
        .body_length = .unknown,
    });
    defer handle.deinit();

    try handle.writeBody("hello ");
    var body_reader = std.Io.Reader.fixed("world");
    try handle.writeBodyFromReader(&body_reader);
    try handle.finishBody();

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponseWithDeadline(
        sink.sink(),
        .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake }),
    );
    try std.testing.expectEqual(http.Protocol.http1, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqualStrings("resp-1resp-2", sink.body.items);
    try std.testing.expectEqual(@as(usize, 1), sink.trailer_count);
    try std.testing.expectEqualStrings("x-checksum", sink.trailer_name.items);
    try std.testing.expectEqualStrings("1", sink.trailer_value.items);
    try std.testing.expectEqual(@as(usize, 1), sink.informational_count);
    try std.testing.expectEqual(@as(u16, 103), sink.informational_status);

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/2 duplex handle streams request and response" {
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
        const Self = @This();
        server: *http2_runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *Self) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *Self) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("hello world", request.body);
            try connection.writeInformationalResponse(
                request.stream_id,
                103,
                &.{.{
                    .name = "link",
                    .value = "</style.css>; rel=preload",
                }},
            );
            var response = try connection.startResponse(
                request.stream_id,
                .{
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .request_method = "POST",
                },
            );
            try response.write("resp-1");
            try response.write("resp-2");
            try response.finishTrailers(&.{.{
                .name = "x-checksum",
                .value = "1",
            }});
            try self.release.wait(self.server.io);
        }
    };

    var release: std.Io.Event = .unset;
    var worker = Worker{ .server = &server, .release = &release };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        thread.join();
    };

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);

    var client = try http.Client.init(allocator, io, .{
        .cleartext_protocol = .http2_prior_knowledge,
    });
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();
    var handle = try connection.startRequest("/upload", .{
        .method = "POST",
        .body_length = .{ .exact = "hello world".len },
    });
    defer handle.deinit();

    try handle.writeBody("hello ");
    try handle.writeBody("world");
    try handle.finishBody();

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponse(sink.sink());
    try std.testing.expectEqual(http.Protocol.http2, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqualStrings("resp-1resp-2", sink.body.items);
    try std.testing.expectEqual(@as(usize, 1), sink.trailer_count);
    try std.testing.expectEqualStrings("x-checksum", sink.trailer_name.items);
    try std.testing.expectEqualStrings("1", sink.trailer_value.items);
    try std.testing.expectEqual(@as(usize, 1), sink.informational_count);
    try std.testing.expectEqual(@as(u16, 103), sink.informational_status);

    release.set(io);
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/3 duplex handle streams request and response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };
    var server = try http3_runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
        } },
    );
    defer server.deinit();

    const Worker = struct {
        const Self = @This();
        server: *http3_runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *Self) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *Self) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "hello world",
                request.request.body,
            );
            try session.startResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
            }, null);
            try session.sendResponseBodyPaced(
                request.stream_id,
                "resp-1",
                false,
            );
            try session.sendResponseBodyPaced(
                request.stream_id,
                "resp-2",
                false,
            );
            try session.finishResponseTrailersPaced(
                request.stream_id,
                &.{.{ .name = "x-checksum", .value = "1" }},
            );
        }
    };

    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3_runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xd3} ** 32,
            .x25519_secret_key = [_]u8{0xd4} ** 32,
        } },
    );
    defer client.deinit();

    var handle = try http.startHttp3Request(
        allocator,
        &client,
        .{
            .method = "POST",
            .path = "/upload",
            .authority = "localhost",
        },
        "hello world".len,
    );
    defer handle.deinit();

    try handle.writeBody("hello ");
    try handle.writeBody("world");
    try handle.finishBody();

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponseWithDeadline(
        sink.sink(),
        .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake }),
    );
    try std.testing.expectEqual(http.Protocol.http3, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    try std.testing.expectEqualStrings("resp-1resp-2", sink.body.items);
    try std.testing.expectEqual(@as(usize, 1), sink.trailer_count);
    try std.testing.expectEqualStrings("x-checksum", sink.trailer_name.items);
    try std.testing.expectEqualStrings("1", sink.trailer_value.items);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
