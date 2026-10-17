const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared endpoint transactions multiplex one lease" {
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
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
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

    var request_body: [900]u8 = undefined;
    for (&request_body, 0..) |*byte, index| byte.* = @truncate(index);
    var response_body: [5000]u8 = undefined;
    for (&response_body, 0..) |*byte, index| byte.* = @truncate(index *% 3);
    const Worker = struct {
        server: *runtime.HandshakeServer,
        request_body: []const u8,
        response_body: []const u8,
        accepts: usize = 0,
        stream_ids: [2]u62 = .{ 0, 0 },
        err: ?anyerror = null,

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
            const upload, const simple = if (std.mem.eql(
                u8,
                first.request.path,
                "/upload",
            ) and std.mem.eql(u8, second.request.path, "/simple"))
                .{ &first, &second }
            else if (std.mem.eql(u8, first.request.path, "/simple") and
                std.mem.eql(u8, second.request.path, "/upload"))
                .{ &second, &first }
            else
                return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings("POST", upload.request.method);
            try std.testing.expectEqualSlices(
                u8,
                self.request_body,
                upload.request.body,
            );
            try std.testing.expectEqual(@as(usize, 1), upload.request.trailers.len);
            try std.testing.expectEqualStrings(
                "x-upload",
                upload.request.trailers[0].name,
            );
            try std.testing.expectEqualStrings(
                "complete",
                upload.request.trailers[0].value,
            );

            // Reverse response order to prove stream correlation is not tied
            // to transaction creation order.
            try session.sendResponse(simple.stream_id, .{
                .status = 202,
                .request_method = simple.request.method,
                .body = "simple",
            });
            try session.startResponse(
                upload.stream_id,
                .{ .status = 201, .request_method = upload.request.method },
                self.response_body.len,
            );
            var offset: usize = 0;
            while (offset < self.response_body.len) {
                const end = @min(offset + 700, self.response_body.len);
                try session.sendResponseBodyPaced(
                    upload.stream_id,
                    self.response_body[offset..end],
                    false,
                );
                offset = end;
            }
            try session.finishResponseTrailersPaced(
                upload.stream_id,
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
    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const upload_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/upload",
        .{base},
    );
    defer allocator.free(upload_uri);
    const simple_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/simple",
        .{base},
    );
    defer allocator.free(simple_uri);

    var lease = try pool.acquireUri(upload_uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();
    try std.testing.expectError(
        error.InvalidOrigin,
        runtime.SharedHandshakeClientPool.RequestTransaction.init(
            &pool,
            &lease,
            "https://unauthorized.invalid/rejected",
            .{},
        ),
    );
    var upload = try runtime.SharedHandshakeClientPool.RequestTransaction.init(
        &pool,
        &lease,
        upload_uri,
        .{
            .method = "POST",
            .body = &request_body,
            .trailers = &.{.{ .name = "x-upload", .value = "complete" }},
        },
    );
    var upload_active = true;
    defer if (upload_active) upload.deinit();
    var simple = try runtime.SharedHandshakeClientPool.RequestTransaction.init(
        &pool,
        &lease,
        simple_uri,
        .{},
    );
    var simple_active = true;
    defer if (simple_active) simple.deinit();
    try std.testing.expectEqual(@as(?u62, 0), upload.requestStreamId());
    try std.testing.expectEqual(@as(?u62, 4), simple.requestStreamId());

    var upload_response: ?runtime.SharedHandshakeClientPool.OwnedResponse = null;
    var simple_response: ?runtime.SharedHandshakeClientPool.OwnedResponse = null;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(5),
    });
    while (upload_response == null or simple_response == null) {
        var event = try pool.receiveWithDeadline(deadline);
        defer event.deinit(allocator);
        if (upload_response == null) {
            upload_response = try upload.processEvent(&event);
        }
        if (simple_response == null) {
            simple_response = try simple.processEvent(&event);
        }
    }
    upload_active = false;
    simple_active = false;
    var owned_upload = upload_response.?;
    defer owned_upload.deinit();
    var owned_simple = simple_response.?;
    defer owned_simple.deinit();
    try std.testing.expectEqual(@as(u16, 201), owned_upload.response.status);
    try std.testing.expectEqualSlices(
        u8,
        &response_body,
        owned_upload.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        owned_upload.response.trailers.len,
    );
    try std.testing.expectEqualStrings(
        "x-response",
        owned_upload.response.trailers[0].name,
    );
    try std.testing.expectEqualStrings(
        "complete",
        owned_upload.response.trailers[0].value,
    );
    try std.testing.expectEqual(@as(u16, 202), owned_simple.response.status);
    try std.testing.expectEqualStrings("simple", owned_simple.response.body);

    lease.release();
    lease_active = false;
    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual([2]u62{ 0, 4 }, worker.stream_ids);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}
