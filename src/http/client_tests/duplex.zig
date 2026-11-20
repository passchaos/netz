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
    header_never_indexed: bool = false,
    trailer_never_indexed: bool = false,
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
        for (head.headers) |header| if (std.mem.eql(u8, header.name, "content-type")) {
            self.header_never_indexed = header.never_indexed;
        };
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        try self.body.appendSlice(self.allocator, bytes);
    }

    fn end(context: *anyopaque, trailers: []const http.DuplexHeader) !void {
        const self: *DuplexSink = @ptrCast(@alignCast(context));
        self.trailer_count = trailers.len;
        if (trailers.len != 0) {
            self.trailer_never_indexed = trailers[0].never_indexed;
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
    try exercise1(false);
}

fn exercise1(comptime timed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(10) });
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
    var connection = if (timed) try client.connectUriWithDeadline(uri, until) else try client.connectUri(uri);
    defer connection.close();
    const request_options: http.RequestOptions = .{
        .method = "POST",
        .headers = &.{.{ .name = "te", .value = "trailers" }},
        .body_length = .unknown,
    };
    var handle = if (timed) try connection.startRequestWithDeadline("/upload", request_options, until) else try connection.startRequest("/upload", request_options);
    defer handle.deinit();

    if (timed) {
        var progress = http.UploadProgress{ .accepted_bytes = 999, .end_accepted = true };
        try std.testing.expectError(error.Timeout, handle.writeBodyWithDeadline("ignored", &progress, .{ .clock = .awake, .raw = .zero }));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
        try std.testing.expect(!progress.end_accepted);
        try handle.writeBodyWithDeadline("hello ", &progress, until);
        try std.testing.expectEqual(@as(usize, 6), progress.accepted_bytes);
        var source = @import("reader_gate.zig").Gate{ .io = io, .bytes = "world", .prefix_len = 2 };
        try std.testing.expectError(error.Timeout, handle.writeBodyFromReaderWithTimeout(&source.reader, &progress, .fromMilliseconds(30)));
        try std.testing.expect(source.canceled and source.finished);
        try std.testing.expectEqual(source.prefix_len, progress.accepted_bytes);
        source.release.set(io);
        try handle.writeBodyFromReaderWithDeadline(&source.reader, &progress, until);
        try std.testing.expectEqual(source.bytes.len - source.prefix_len, progress.accepted_bytes);
        try handle.finishBodyWithDeadline(&progress, until);
        try std.testing.expect(progress.end_accepted);
        try std.testing.expectError(error.RequestBodyFinished, handle.writeBodyWithDeadline("later", &progress, until));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
    } else {
        try handle.writeBody("hello ");
        var body_reader = std.Io.Reader.fixed("world");
        try handle.writeBodyFromReader(&body_reader);
        try handle.finishBody();
    }

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponseWithDeadline(
        sink.sink(),
        .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake }),
    );
    try std.testing.expectEqual(http.Protocol.http1, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    _ = try handle.readResponse(sink.sink());
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
    try exercise2(false);
}

fn exercise2(comptime timed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(10) });
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
            try std.testing.expect(request.trailers[0].never_index);
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
                        .never_index = true,
                    }},
                    .request_method = "POST",
                },
            );
            try response.write("resp-1");
            try response.write("resp-2");
            try response.finishTrailers(&.{.{
                .name = "x-checksum",
                .value = "1",
                .never_index = true,
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
    var connection = if (timed) try client.connectUriWithDeadline(uri, until) else try client.connectUri(uri);
    defer connection.close();
    const request_options: http.RequestOptions = .{
        .method = "POST",
        .body_length = .{ .exact = "hello world".len },
    };
    var handle = if (timed) try connection.startRequestWithDeadline("/upload", request_options, until) else try connection.startRequest("/upload", request_options);
    defer handle.deinit();

    if (timed) {
        var progress = http.UploadProgress{ .accepted_bytes = 999, .end_accepted = true };
        try std.testing.expectError(error.Timeout, handle.writeBodyWithDeadline("ignored", &progress, .{ .clock = .awake, .raw = .zero }));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
        try std.testing.expect(!progress.end_accepted);
        try handle.writeBodyWithDeadline("hello ", &progress, until);
        try std.testing.expectEqual(@as(usize, 6), progress.accepted_bytes);
        var source = @import("reader_gate.zig").Gate{ .io = io, .bytes = "world", .prefix_len = 2 };
        try std.testing.expectError(error.Timeout, handle.writeBodyFromReaderWithTimeout(&source.reader, &progress, .fromMilliseconds(30)));
        try std.testing.expect(source.canceled and source.finished);
        try std.testing.expectEqual(source.prefix_len, progress.accepted_bytes);
        source.release.set(io);
        try handle.writeBodyFromReaderWithDeadline(&source.reader, &progress, until);
        try std.testing.expectEqual(source.bytes.len - source.prefix_len, progress.accepted_bytes);
        try handle.finishTrailersWithDeadline(&.{.{ .name = "x-upload", .value = "done", .never_indexed = true }}, &progress, until);
        try std.testing.expect(progress.end_accepted);
        try std.testing.expectError(error.RequestBodyFinished, handle.writeBodyWithDeadline("later", &progress, until));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
    } else {
        try handle.writeBody("hello ");
        try handle.writeBody("world");
        try handle.finishTrailers(&.{.{ .name = "x-upload", .value = "done", .never_indexed = true }});
    }

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponse(sink.sink());
    try std.testing.expectEqual(http.Protocol.http2, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    _ = try handle.readResponse(sink.sink());
    try std.testing.expectEqualStrings("resp-1resp-2", sink.body.items);
    try std.testing.expectEqual(@as(usize, 1), sink.trailer_count);
    try std.testing.expect(sink.header_never_indexed);
    try std.testing.expect(sink.trailer_never_indexed);
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
    try exercise3(false);
}

fn exercise3(comptime timed: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(10) });

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
            try std.testing.expect(request.request.trailers[0].never_indexed);
            try session.startResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                    .never_indexed = true,
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
                &.{.{ .name = "x-checksum", .value = "1", .never_indexed = true }},
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

    const request_options: @import("../../http3/mod.zig").Request = .{ .method = "POST", .path = "/upload", .authority = "localhost" };
    var handle = if (timed)
        try http.startHttp3RequestWithDeadline(allocator, &client, request_options, "hello world".len, until)
    else
        try http.startHttp3Request(allocator, &client, request_options, "hello world".len);
    defer handle.deinit();

    if (timed) {
        var progress = http.UploadProgress{ .accepted_bytes = 999, .end_accepted = true };
        try std.testing.expectError(error.Timeout, handle.writeBodyWithDeadline("ignored", &progress, .{ .clock = .awake, .raw = .zero }));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
        try std.testing.expect(!progress.end_accepted);
        try handle.writeBodyWithDeadline("hello ", &progress, until);
        try std.testing.expectEqual(@as(usize, 6), progress.accepted_bytes);
        try handle.writeBodyWithTimeout("world", &progress, .fromSeconds(10));
        try std.testing.expectEqual(@as(usize, 5), progress.accepted_bytes);
        try handle.finishTrailersWithDeadline(&.{.{ .name = "x-upload", .value = "done", .never_indexed = true }}, &progress, until);
        try std.testing.expect(progress.end_accepted);
        try std.testing.expectError(error.RequestBodyFinished, handle.writeBodyWithDeadline("later", &progress, until));
        try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
    } else {
        try handle.writeBody("hello ");
        try handle.writeBody("world");
        try handle.finishTrailers(&.{.{ .name = "x-upload", .value = "done", .never_indexed = true }});
    }

    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    const head = try handle.readResponseWithDeadline(
        sink.sink(),
        .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake }),
    );
    try std.testing.expectEqual(http.Protocol.http3, head.protocol);
    try std.testing.expectEqual(@as(u16, 200), head.status);
    _ = try handle.readResponse(sink.sink());
    try std.testing.expectEqualStrings("resp-1resp-2", sink.body.items);
    try std.testing.expectEqual(@as(usize, 1), sink.trailer_count);
    try std.testing.expect(sink.header_never_indexed);
    try std.testing.expect(sink.trailer_never_indexed);
    try std.testing.expectEqualStrings("x-checksum", sink.trailer_name.items);
    try std.testing.expectEqualStrings("1", sink.trailer_value.items);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "unified HTTP streaming deadlines cover H1 H2 and exclusive H3 with progress" {
    try exercise1(true);
    try exercise2(true);
    try exercise3(true);
}

test "unified HTTP streaming deadlines preserve H1 Continue after an expired body call" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http1_runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *http1_runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var request = try connection.readRequestWithDeadline(.{}, .fromNow(listener.io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
            defer request.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("body", request.request.body);
            try connection.writeResponseWithTimeout(.{ .body = "ok" }, .fromSeconds(5));
        }
    };
    var peer = try io.concurrent(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/continue", .{server.address().getPort()});
    defer allocator.free(uri);
    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    var handle = try connection.startRequestWithDeadline("/continue", .{ .method = "POST", .body_length = .{ .exact = 4 }, .headers = &.{.{ .name = "expect", .value = "100-continue" }} }, until);
    defer handle.deinit();
    var progress: http.UploadProgress = .{};
    try std.testing.expectError(error.Timeout, handle.writeBodyWithDeadline("body", &progress, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expect(handle.h1_continue_pending);
    try std.testing.expectEqual(@as(usize, 0), progress.accepted_bytes);
    try handle.writeBodyWithDeadline("body", &progress, until);
    try std.testing.expect(!handle.h1_continue_pending);
    try std.testing.expectEqual(@as(usize, 4), progress.accepted_bytes);
    try handle.finishBodyWithDeadline(&progress, until);
    var sink = DuplexSink{ .allocator = allocator };
    defer sink.deinit();
    _ = try handle.readResponseWithDeadline(sink.sink(), until);
    try std.testing.expectEqualStrings("ok", sink.body.items);
    try peer.await(io);
}

fn pooledTcpDeadlines(comptime h2: bool, comptime discard: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = if (h2)
        try http2_runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{})
    else
        try http1_runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *@TypeOf(server), done: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            for (0..2) |index| {
                if (discard and index == 1) {
                    connection.close();
                    connection = try listener.acceptWithTimeout(.fromSeconds(5));
                }
                const until = std.Io.Clock.Timestamp.fromNow(listener.io, .{ .clock = .awake, .raw = .fromSeconds(5) });
                var request = if (h2) try connection.readRequestWithDeadline(until) else try connection.readRequestWithDeadline(.{}, until);
                defer request.deinit(std.testing.allocator);
                const body = if (h2) request.body else request.request.body;
                try std.testing.expectEqualStrings(if (index == 0) "upload" else "", body);
                if (h2) try connection.writeResponseWithDeadline(request.stream_id, .{ .body = "ok" }, until) else try connection.writeResponseWithDeadline(.{ .body = "ok" }, until);
            }
            try done.wait(listener.io);
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, &release });
    defer _ = peer.cancel(io) catch {};
    defer release.set(io);
    var pool = try http.Pool.init(allocator, io, .{ .max_connections = 1, .client = .{ .cleartext_protocol = if (h2) .http2_prior_knowledge else .http1 } });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/pooled", .{server.address().getPort()});
    defer allocator.free(uri);
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    {
        var handle = try pool.startRequestWithDeadline(uri, .{ .method = "POST", .body_length = .{ .exact = 6 } }, until);
        defer if (discard) handle.discard() else handle.deinit();
        var progress: http.UploadProgress = .{};
        var source = @import("reader_gate.zig").Gate{ .io = io, .bytes = "upload", .prefix_len = 2 };
        try std.testing.expectError(error.Timeout, handle.writeBodyFromReaderWithTimeout(&source.reader, &progress, .fromMilliseconds(30)));
        try std.testing.expect(source.canceled and source.finished);
        try std.testing.expectEqual(source.prefix_len, progress.accepted_bytes);
        source.release.set(io);
        try handle.writeBodyFromReaderWithDeadline(&source.reader, &progress, until);
        try std.testing.expectEqual(source.bytes.len - source.prefix_len, progress.accepted_bytes);
        try handle.finishBodyWithTimeout(&progress, .fromSeconds(5));
        try std.testing.expect(progress.end_accepted);
        var sink = DuplexSink{ .allocator = allocator };
        defer sink.deinit();
        _ = try handle.readResponseWithTimeout(sink.sink(), .fromSeconds(5));
        try std.testing.expectEqualStrings("ok", sink.body.items);
    }
    try std.testing.expectEqual(@as(usize, if (discard) 0 else 1), pool.connectionCount());
    var response = try pool.requestUriWithDeadline(uri, .{}, until);
    defer response.deinit();
    try std.testing.expectEqualStrings("ok", response.body());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    release.set(io);
    try peer.await(io);
}

test "unified HTTP streaming deadlines return H1 H2 pool leases for same connection reuse" {
    try pooledTcpDeadlines(false, false);
    try pooledTcpDeadlines(true, false);
}

test "unified HTTP streaming deadlines discard completed H1 H2 pool leases" {
    try pooledTcpDeadlines(false, true);
    try pooledTcpDeadlines(true, true);
}
