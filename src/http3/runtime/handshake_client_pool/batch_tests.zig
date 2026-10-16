const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "HTTP/3 exclusive pool batches direct and Alt-Svc URI requests on one connection" {
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

    const Worker = struct {
        server: *runtime.HandshakeServer,
        accepts: usize = 0,
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
            for (0..2) |batch_index| {
                var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
                defer first.deinit(self.server.allocator);
                var second = try session.receiveRequestWithTimeout(.fromSeconds(5));
                defer second.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    if (batch_index == 0) "/one" else "/three",
                    first.request.path,
                );
                try std.testing.expectEqualStrings(
                    if (batch_index == 0) "/two" else "/four",
                    second.request.path,
                );
                try session.sendResponse(second.stream_id, .{
                    .status = if (batch_index == 0) 202 else 204,
                    .request_method = second.request.method,
                });
                try session.sendResponse(first.stream_id, .{
                    .status = if (batch_index == 0) 201 else 203,
                    .request_method = first.request.method,
                });
            }
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();

    const base = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base);
    const uris = [_][]u8{
        try std.fmt.allocPrint(allocator, "{s}/one", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/two", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/three", .{base}),
        try std.fmt.allocPrint(allocator, "{s}/four", .{base}),
    };
    defer for (uris) |uri| allocator.free(uri);

    const Results = struct {
        allocator: std.mem.Allocator,
        expected: [2]u16,
        order: [2]usize = undefined,
        count: usize = 0,
        err: ?anyerror = null,

        fn observe(
            raw: *anyopaque,
            index: usize,
            result: runtime.BatchOwnedHandshakeResponseResult,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.order[self.count] = index;
            self.count += 1;
            switch (result) {
                .response => |response_value| {
                    var response = response_value;
                    defer response.deinit(self.allocator);
                    std.testing.expectEqual(
                        self.expected[index],
                        response.response.status,
                    ) catch |err| {
                        self.err = err;
                    };
                },
                .err => |err| self.err = err,
            }
        }
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var direct = Results{
        .allocator = allocator,
        .expected = .{ 201, 202 },
    };
    try pool.requestUriBatchWithPerStreamDeadlines(
        &.{ .{ .uri = uris[0] }, .{ .uri = uris[1] } },
        &.{ deadline, deadline },
        .{ .context = &direct, .on_result = Results.observe },
    );
    if (direct.err) |err| return err;
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, &direct.order);

    var routed = Results{
        .allocator = allocator,
        .expected = .{ 203, 204 },
    };
    try pool.requestUriAltSvcBatchWithPerStreamDeadlines(
        &.{ .{ .uri = uris[2] }, .{ .uri = uris[3] } },
        .{
            .alpn = "h3",
            .connect_host = "127.0.0.1",
            .origin_host = "localhost",
            .port = server.address().ip4.port,
        },
        &.{ deadline, deadline },
        .{ .context = &routed, .on_result = Results.observe },
    );
    if (routed.err) |err| return err;
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, &routed.order);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);
}
