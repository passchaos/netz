const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const quic = @import("../../../quic/mod.zig");
const tls_testing = @import("../../../tls/testing.zig");

fn receiveStatus(
    pool: *runtime.SharedHandshakeClientPool,
    lease: *runtime.SharedHandshakeClientPool.Lease,
    stream_id: u62,
) !u16 {
    const deadline = std.Io.Clock.Timestamp.fromNow(pool.io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var status: ?u16 = null;
    while (true) {
        var event = try pool.receiveWithDeadline(deadline);
        defer event.deinit(pool.allocator);
        switch (event) {
            .response => |*response| {
                if (response.connection_handle != lease.connectionHandle()) {
                    return error.TestUnexpectedResult;
                }
                const message = switch (response.response) {
                    .message => |*value| value,
                    .reset => return error.TestUnexpectedResult,
                };
                if (message.stream_id != stream_id) {
                    return error.TestUnexpectedResult;
                }
                switch (message.value) {
                    .head => |head| switch (head) {
                        .response => |final| status = final.status,
                        .request => return error.TestUnexpectedResult,
                    },
                    .data_available => {
                        var discard: [64]u8 = undefined;
                        while ((try pool.readResponseDataOnce(
                            response.connection_handle,
                            stream_id,
                            &discard,
                        )) orelse 0 != 0) {}
                    },
                    .finished => return status orelse
                        error.TestUnexpectedResult,
                    .push_promise, .trailers => {},
                }
            },
            .progress, .timer, .consumed => {},
            .push, .closed, .unrouted => return error.TestUnexpectedResult,
        }
    }
}

test "HTTP/3 shared pool scopes Alt-Svc tickets coalesces ORIGIN and applies 421" {
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
    var ticket_store = try quic.resumption.ticket.ServerStore.init(
        allocator,
        io,
        4,
    );
    defer ticket_store.deinit();

    const origin_b = "https://localhost:9444";
    const origin_without_certificate = "https://other.example:9445";
    const Worker = struct {
        server: *runtime.HandshakeServer,
        ticket_store: *quic.resumption.ticket.ServerStore,
        accepts: usize = 0,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn receive(
            self: *@This(),
            session: *runtime.HandshakeServerSession,
            authority: []const u8,
            path: []const u8,
        ) !runtime.OwnedHandshakeRequest {
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            errdefer request.deinit(self.server.allocator);
            try std.testing.expect(std.ascii.eqlIgnoreCase(
                authority,
                request.request.authority.?,
            ));
            try std.testing.expectEqualStrings(path, request.request.path);
            try std.testing.expect(!request.was_early_data);
            self.requests += 1;
            return request;
        }

        fn respond(
            _: *@This(),
            session: *runtime.HandshakeServerSession,
            request: runtime.OwnedHandshakeRequest,
            status: u16,
        ) !void {
            try session.sendResponse(request.stream_id, .{
                .status = status,
                .request_method = request.request.method,
            });
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer first.deinit();

            var initial = try self.receive(
                &first,
                "localhost:9443",
                "/initial",
            );
            defer initial.deinit(self.server.allocator);
            _ = try first.established.issueSessionTicket(
                self.server.quic_server.endpoint.io,
                .{
                    .store = self.ticket_store,
                    .now_ms = 1_000,
                    .lifetime_seconds = 3_600,
                    .nonce = [_]u8{0x41} ** 16,
                    .identity = [_]u8{0x51} ** 32,
                    .age_add = 61,
                },
            );
            try first.sendOrigins(&.{ origin_b, origin_without_certificate });
            try self.respond(&first, initial, 200);

            var coalesced = try self.receive(
                &first,
                "localhost:9444",
                "/coalesced",
            );
            defer coalesced.deinit(self.server.allocator);
            try self.respond(&first, coalesced, 421);

            var original_again = try self.receive(
                &first,
                "localhost:9443",
                "/original-again",
            );
            defer original_again.deinit(self.server.allocator);
            try self.respond(&first, original_again, 200);

            var second = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer second.deinit();
            var certificate_miss = try self.receive(
                &second,
                "other.example:9445",
                "/certificate-miss",
            );
            defer certificate_miss.deinit(self.server.allocator);
            try self.respond(&second, certificate_miss, 200);

            var third = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer third.deinit();
            var after_421 = try self.receive(
                &third,
                "localhost:9444",
                "/after-421",
            );
            defer after_421.deinit(self.server.allocator);
            try self.respond(&third, after_421, 200);
        }
    };
    var worker = Worker{
        .server = &server,
        .ticket_store = &ticket_store,
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var ticket_cache = try quic.resumption.Cache.init(allocator, 4);
    defer ticket_cache.deinit();
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
            .auto_resumption = .{
                .cache = &ticket_cache,
                .server_id = "must-be-replaced-by-origin",
                .now_ms = 1_500,
            },
        } },
    });
    defer pool.deinit();

    const target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "localhost",
        .port = server.address().ip4.port,
    };
    var invalid_target = target;
    invalid_target.origin_host = "other.example";
    try std.testing.expectError(
        error.InvalidHeader,
        pool.acquireUriAltSvc(
            "https://localhost:9443/invalid-origin",
            invalid_target,
        ),
    );
    invalid_target = target;
    invalid_target.alpn = "h2";
    try std.testing.expectError(
        error.InvalidHeader,
        pool.acquireUriAltSvc(
            "https://localhost:9443/invalid-alpn",
            invalid_target,
        ),
    );
    const requests = [_]struct {
        uri: []const u8,
        authority: []const u8,
        target_origin_host: []const u8,
        path: []const u8,
        expected_status: u16,
        expect_reuse: bool,
        expect_same_handle: bool,
    }{
        .{
            .uri = "https://localhost:9443/initial",
            .authority = "localhost:9443",
            .target_origin_host = "localhost",
            .path = "/initial",
            .expected_status = 200,
            .expect_reuse = false,
            .expect_same_handle = true,
        },
        .{
            .uri = "https://localhost:9444/coalesced",
            .authority = "localhost:9444",
            .target_origin_host = "localhost",
            .path = "/coalesced",
            .expected_status = 421,
            .expect_reuse = true,
            .expect_same_handle = true,
        },
        .{
            .uri = "https://LOCALHOST:9443/original-again",
            .authority = "LOCALHOST:9443",
            .target_origin_host = "LOCALHOST",
            .path = "/original-again",
            .expected_status = 200,
            .expect_reuse = true,
            .expect_same_handle = true,
        },
        .{
            .uri = "https://other.example:9445/certificate-miss",
            .authority = "other.example:9445",
            .target_origin_host = "other.example",
            .path = "/certificate-miss",
            .expected_status = 200,
            .expect_reuse = false,
            .expect_same_handle = false,
        },
        .{
            .uri = "https://localhost:9444/after-421",
            .authority = "localhost:9444",
            .target_origin_host = "localhost",
            .path = "/after-421",
            .expected_status = 200,
            .expect_reuse = false,
            .expect_same_handle = false,
        },
    };
    var initial_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    for (requests, 0..) |spec, index| {
        var routed_target = target;
        routed_target.origin_host = spec.target_origin_host;
        var lease = try pool.acquireUriAltSvcWithTimeout(
            spec.uri,
            routed_target,
            .fromSeconds(5),
        );
        defer if (lease.active) lease.discard();
        try std.testing.expectEqual(spec.expect_reuse, lease.was_reused);
        if (initial_handle) |handle| {
            try std.testing.expectEqual(
                spec.expect_same_handle,
                handle == lease.connectionHandle(),
            );
        } else {
            initial_handle = lease.connectionHandle();
        }
        const stream_id = try lease.sendRequest(.{
            .method = "GET",
            .path = spec.path,
            .authority = spec.authority,
        });
        const status = try receiveStatus(&pool, &lease, stream_id);
        try std.testing.expectEqual(spec.expected_status, status);
        try lease.observeResponseStatus(status);
        lease.release();

        if (index == 0) {
            var scoped = (try ticket_cache.acquire(
                "localhost:9443",
                "h3",
                1_500,
            )) orelse return error.TestUnexpectedResult;
            scoped.deinit();
            try std.testing.expect((try ticket_cache.acquire(
                "must-be-replaced-by-origin",
                "h3",
                1_500,
            )) == null);
        }
    }

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), worker.accepts);
    try std.testing.expectEqual(@as(usize, 5), worker.requests);
    try std.testing.expectEqual(@as(u64, 2), pool.stats().total_reused);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}
