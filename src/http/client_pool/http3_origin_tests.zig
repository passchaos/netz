const std = @import("std");
const http = @import("../mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "unified HTTP pool coalesces Alt-Svc H3 only after peer ORIGIN authorization" {
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
    var tcp_a = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_a.deinit();
    var tcp_b = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_b.deinit();

    const h3_limits: http3_runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    var h3_server = try http3_runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h3_limits,
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
        expected_path: []const u8,
        body: []const u8,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(
                .fromSeconds(10),
            );
            defer connection.close();
            var request = try connection.readRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                self.expected_path,
                request.path,
            );
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = self.body,
                .request_method = request.method,
            });
            self.requests += 1;
        }
    };

    const authority_a = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{tcp_a.address().ip4.port},
    );
    defer allocator.free(authority_a);
    const authority_b = try std.fmt.allocPrint(
        allocator,
        "localhost:{d}",
        .{tcp_b.address().ip4.port},
    );
    defer allocator.free(authority_b);
    const serialized_b = try std.fmt.allocPrint(
        allocator,
        "https://{s}",
        .{authority_b},
    );
    defer allocator.free(serialized_b);

    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        authority_a: []const u8,
        authority_b: []const u8,
        serialized_b: []const u8,
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
            session: *http3_runtime.HandshakeServerSession,
            authority: []const u8,
            path: []const u8,
        ) !http3_runtime.OwnedHandshakeRequest {
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

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();

            var request_a = try self.receive(
                &session,
                self.authority_a,
                "/h3-a",
            );
            defer request_a.deinit(self.server.allocator);
            try session.sendOrigins(&.{self.serialized_b});
            try session.sendResponse(request_a.stream_id, .{
                .status = 200,
                .request_method = request_a.request.method,
                .body = "h3-a",
            });

            var request_b = try self.receive(
                &session,
                self.authority_b,
                "/h3-b",
            );
            defer request_b.deinit(self.server.allocator);
            try session.sendResponse(request_b.stream_id, .{
                .status = 200,
                .request_method = request_b.request.method,
                .body = "h3-b",
            });
        }
    };

    var tcp_a_worker = TcpWorker{
        .server = &tcp_a,
        .alt_svc = alt_svc,
        .expected_path = "/discover-a",
        .body = "discover-a",
    };
    var tcp_b_worker = TcpWorker{
        .server = &tcp_b,
        .alt_svc = alt_svc,
        .expected_path = "/discover-b",
        .body = "discover-b",
    };
    var h3_worker = H3Worker{
        .server = &h3_server,
        .authority_a = authority_a,
        .authority_b = authority_b,
        .serialized_b = serialized_b,
    };
    const tcp_a_thread = try std.Thread.spawn(
        .{},
        TcpWorker.run,
        .{&tcp_a_worker},
    );
    var tcp_a_joined = false;
    defer if (!tcp_a_joined) tcp_a_thread.join();
    const tcp_b_thread = try std.Thread.spawn(
        .{},
        TcpWorker.run,
        .{&tcp_b_worker},
    );
    var tcp_b_joined = false;
    defer if (!tcp_b_joined) tcp_b_thread.join();
    const h3_thread = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker});
    var h3_joined = false;
    defer if (!h3_joined) h3_thread.join();

    var pool = try http.Pool.init(allocator, io, .{
        .max_total_connections = 4,
        .client = .{ .tls = .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } } },
        .http3 = .{
            .limits = h3_limits,
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
            .early_data = .{},
        },
    });
    defer pool.deinit();

    const base_a = try std.fmt.allocPrint(
        allocator,
        "https://{s}",
        .{authority_a},
    );
    defer allocator.free(base_a);
    const base_b = try std.fmt.allocPrint(
        allocator,
        "https://{s}",
        .{authority_b},
    );
    defer allocator.free(base_b);
    const paths = [_][]const u8{
        "/discover-a",
        "/h3-a",
        "/discover-b",
        "/h3-b",
    };
    const bases = [_][]const u8{ base_a, base_a, base_b, base_b };
    const protocols = [_]http.Protocol{ .http2, .http3, .http2, .http3 };
    const bodies = [_][]const u8{
        "discover-a",
        "h3-a",
        "discover-b",
        "h3-b",
    };
    for (bases, paths, protocols, bodies) |base, path, protocol, body| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ base, path },
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{},
            .fromSeconds(5),
        );
        defer response.deinit();
        try std.testing.expectEqual(protocol, response.protocol());
        try std.testing.expectEqualStrings(body, response.body());
        try std.testing.expect(response.early_data == null);
    }

    tcp_a_thread.join();
    tcp_a_joined = true;
    tcp_b_thread.join();
    tcp_b_joined = true;
    h3_thread.join();
    h3_joined = true;
    if (tcp_a_worker.err) |err| return err;
    if (tcp_b_worker.err) |err| return err;
    if (h3_worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), tcp_a_worker.requests);
    try std.testing.expectEqual(@as(usize, 1), tcp_b_worker.requests);
    try std.testing.expectEqual(@as(usize, 1), h3_worker.accepts);
    try std.testing.expectEqual(@as(usize, 2), h3_worker.requests);
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.http3IdleCount());
}
