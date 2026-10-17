const std = @import("std");
const http = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "unified HTTP pool multiplexes concurrent H3 requests through one driver" {
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
    const identity: @FieldType(http1_runtime.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    var tcp_server = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_server.deinit();
    const limits: http3_runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8 };
    var h3_server = try http3_runtime.HandshakeServer.bind(
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
    defer h3_server.deinit();
    const alt_svc = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{h3_server.address().ip4.port},
    );
    defer allocator.free(alt_svc);

    const TcpWorker = struct {
        server: *http2_runtime.TlsServer,
        alt_svc: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(10));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/discover", request.path);
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = "discover",
                .request_method = request.method,
            });
        }
    };
    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        accepts: usize = 0,
        stream_ids: [2]u62 = .{ 0, 0 },
        cancellation_paths: [2][16]u8 = .{.{0} ** 16} ** 2,
        cancellation_path_lengths: [2]usize = .{ 0, 0 },
        cancellation_stream_ids: [2]u62 = .{ 0, 0 },
        timed_stream_id: ?u62 = null,
        sibling_stream_id: ?u62 = null,
        sibling_status_sent: ?u16 = null,
        cancellation_code: ?u64 = null,
        err: ?anyerror = null,

        fn recordPath(self: *@This(), index: usize, path: []const u8) !void {
            if (path.len > self.cancellation_paths[index].len) {
                return error.TestPathTooLong;
            }
            @memcpy(self.cancellation_paths[index][0..path.len], path);
            self.cancellation_path_lengths[index] = path.len;
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();
            var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(self.server.allocator);
            var second = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer second.deinit(self.server.allocator);
            self.stream_ids = .{ first.stream_id, second.stream_id };
            try session.sendResponse(second.stream_id, .{
                .status = 200,
                .request_method = second.request.method,
                .body = second.request.path,
            });
            try session.sendResponse(first.stream_id, .{
                .status = 200,
                .request_method = first.request.method,
                .body = first.request.path,
            });
            var timed = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer timed.deinit(self.server.allocator);
            var sibling = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer sibling.deinit(self.server.allocator);
            try self.recordPath(0, timed.request.path);
            try self.recordPath(1, sibling.request.path);
            self.cancellation_stream_ids = .{
                timed.stream_id,
                sibling.stream_id,
            };
            const timed_stream_id, const sibling_stream_id, const sibling_method =
                if (std.mem.eql(u8, timed.request.path, "/timeout") and
                std.mem.eql(u8, sibling.request.path, "/sibling"))
                    .{ timed.stream_id, sibling.stream_id, sibling.request.method }
                else if (std.mem.eql(u8, sibling.request.path, "/timeout") and
                std.mem.eql(u8, timed.request.path, "/sibling"))
                    .{ sibling.stream_id, timed.stream_id, timed.request.method }
                else
                    return error.TestUnexpectedResult;
            self.timed_stream_id = timed_stream_id;
            self.sibling_stream_id = sibling_stream_id;
            const canceled = try session.receivePeerResponseCancellationWithTimeout(
                timed_stream_id,
                .fromSeconds(5),
            );
            self.cancellation_code = canceled.application_error_code;
            self.sibling_status_sent = 202;
            try session.sendResponse(sibling_stream_id, .{
                .status = 202,
                .request_method = sibling_method,
                .body = "sibling",
            });
        }
    };
    var tcp_worker = TcpWorker{
        .server = &tcp_server,
        .alt_svc = alt_svc,
    };
    var h3_worker = H3Worker{ .server = &h3_server };
    const tcp_thread = try std.Thread.spawn(.{}, TcpWorker.run, .{&tcp_worker});
    var tcp_joined = false;
    defer if (!tcp_joined) tcp_thread.join();
    const h3_thread = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker});
    var h3_joined = false;
    defer if (!h3_joined) h3_thread.join();

    var pool = try http.Pool.init(allocator, io, .{
        .max_total_connections = 3,
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
        .http3 = .{
            .limits = limits,
            .handshake = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            } },
            .idle = .{
                .max_idle_per_origin = 1,
                .max_idle_total = 1,
            },
            .max_connections = 1,
            .fallback = .never,
        },
    });
    defer pool.deinit();
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_server.address().ip4.port},
    );
    defer allocator.free(base);
    const discover = try std.fmt.allocPrint(allocator, "{s}/discover", .{base});
    defer allocator.free(discover);
    var discovered = try pool.requestUriWithTimeout(
        discover,
        .{},
        .fromSeconds(5),
    );
    discovered.deinit();

    var start: std.Io.Event = .unset;
    const Producer = struct {
        pool: *http.Pool,
        start: *std.Io.Event,
        uri: []const u8,
        expected: []const u8,

        fn run(self: *@This()) !void {
            try self.start.wait(self.pool.io);
            var response = try self.pool.requestUriWithTimeout(
                self.uri,
                .{},
                .fromSeconds(5),
            );
            defer response.deinit();
            try std.testing.expectEqual(http.Protocol.http3, response.protocol());
            try std.testing.expectEqualStrings(self.expected, response.body());
        }
    };
    const uri_a = try std.fmt.allocPrint(allocator, "{s}/a", .{base});
    defer allocator.free(uri_a);
    const uri_b = try std.fmt.allocPrint(allocator, "{s}/b", .{base});
    defer allocator.free(uri_b);
    var producer_a = Producer{
        .pool = &pool,
        .start = &start,
        .uri = uri_a,
        .expected = "/a",
    };
    var producer_b = Producer{
        .pool = &pool,
        .start = &start,
        .uri = uri_b,
        .expected = "/b",
    };
    var future_a = try std.Io.concurrent(io, Producer.run, .{&producer_a});
    var future_b = try std.Io.concurrent(io, Producer.run, .{&producer_b});
    start.set(io);
    var producer_error: ?anyerror = null;
    future_a.await(io) catch |err| {
        producer_error = err;
    };
    future_b.await(io) catch |err| if (producer_error == null) {
        producer_error = err;
    };

    var cancel_start: std.Io.Event = .unset;
    const CancelProducer = struct {
        pool: *http.Pool,
        start: *std.Io.Event,
        uri: []const u8,
        err: ?anyerror = null,
        protocol: ?http.Protocol = null,
        status: ?u16 = null,
        body: [16]u8 = .{0} ** 16,
        body_len: usize = 0,

        fn recordResponse(
            self: *@This(),
            response: *http.OwnedResponse,
        ) void {
            self.protocol = response.protocol();
            self.status = response.status();
            const body = response.body();
            self.body_len = @min(body.len, self.body.len);
            @memcpy(self.body[0..self.body_len], body[0..self.body_len]);
        }

        fn timed(self: *@This()) void {
            self.start.wait(self.pool.io) catch |err| {
                self.err = err;
                return;
            };
            var response = self.pool.requestUriWithTimeout(
                self.uri,
                .{},
                .fromMilliseconds(500),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit();
            self.recordResponse(&response);
        }

        fn sibling(self: *@This()) void {
            self.start.wait(self.pool.io) catch |err| {
                self.err = err;
                return;
            };
            var response = self.pool.requestUriWithTimeout(
                self.uri,
                .{},
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit();
            self.recordResponse(&response);
        }
    };
    const timeout_uri = try std.fmt.allocPrint(allocator, "{s}/timeout", .{base});
    defer allocator.free(timeout_uri);
    const sibling_uri = try std.fmt.allocPrint(allocator, "{s}/sibling", .{base});
    defer allocator.free(sibling_uri);
    var timed_producer = CancelProducer{
        .pool = &pool,
        .start = &cancel_start,
        .uri = timeout_uri,
    };
    var sibling_producer = CancelProducer{
        .pool = &pool,
        .start = &cancel_start,
        .uri = sibling_uri,
    };
    var timed_future = try std.Io.concurrent(
        io,
        CancelProducer.timed,
        .{&timed_producer},
    );
    var sibling_future = try std.Io.concurrent(
        io,
        CancelProducer.sibling,
        .{&sibling_producer},
    );
    cancel_start.set(io);
    timed_future.await(io);
    sibling_future.await(io);

    tcp_thread.join();
    tcp_joined = true;
    h3_thread.join();
    h3_joined = true;
    if (tcp_worker.err) |err| return err;
    if (producer_error) |err| return err;
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), timed_producer.err);
    try std.testing.expectEqual(@as(?http.Protocol, null), timed_producer.protocol);
    try std.testing.expectEqual(@as(?u16, null), timed_producer.status);
    try std.testing.expectEqual(@as(?anyerror, null), sibling_producer.err);
    try std.testing.expectEqual(
        @as(?http.Protocol, .http3),
        sibling_producer.protocol,
    );
    try std.testing.expectEqual(@as(?u16, 202), sibling_producer.status);
    try std.testing.expectEqualStrings(
        "sibling",
        sibling_producer.body[0..sibling_producer.body_len],
    );
    const first_cancel_path = h3_worker.cancellation_paths[0][0..h3_worker.cancellation_path_lengths[0]];
    const second_cancel_path = h3_worker.cancellation_paths[1][0..h3_worker.cancellation_path_lengths[1]];
    const timeout_arrived_first = std.mem.eql(
        u8,
        first_cancel_path,
        "/timeout",
    );
    try std.testing.expect(if (timeout_arrived_first)
        std.mem.eql(u8, second_cancel_path, "/sibling")
    else
        std.mem.eql(u8, first_cancel_path, "/sibling") and
            std.mem.eql(u8, second_cancel_path, "/timeout"));
    try std.testing.expectEqual(
        [2]u62{ 8, 12 },
        h3_worker.cancellation_stream_ids,
    );
    try std.testing.expectEqual(
        @as(?u62, if (timeout_arrived_first) 8 else 12),
        h3_worker.timed_stream_id,
    );
    try std.testing.expectEqual(
        @as(?u62, if (timeout_arrived_first) 12 else 8),
        h3_worker.sibling_stream_id,
    );
    try std.testing.expectEqual(@as(?u16, 202), h3_worker.sibling_status_sent);
    if (h3_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), h3_worker.accepts);
    try std.testing.expectEqual([2]u62{ 0, 4 }, h3_worker.stream_ids);
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.request_cancelled),
        h3_worker.cancellation_code,
    );
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
}
