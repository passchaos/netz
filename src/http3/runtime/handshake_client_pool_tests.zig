const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 handshake client pool replaces idle capacity across origins" {
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

    const server_a_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const server_b_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_a_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_b_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_b.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_paths: []const []const u8,
        response_bodies: []const []const u8,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            for (self.expected_paths, self.response_bodies) |expected_path, body| {
                var request = session.receiveRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                if (!std.mem.eql(u8, expected_path, request.request.path)) {
                    self.err = error.InvalidUri;
                    return;
                }
                session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .request_method = request.request.method,
                    .body = body,
                }) catch |err| {
                    self.err = err;
                    return;
                };
                self.requests += 1;
            }
        }
    };
    var worker_a = ServerWorker{
        .server = &server_a,
        .expected_paths = &.{"/origin-a"},
        .response_bodies = &.{"a"},
    };
    var worker_b = ServerWorker{
        .server = &server_b,
        .expected_paths = &.{ "/origin-b/one", "/origin-b/two" },
        .response_bodies = &.{ "b-one", "b-two" },
    };
    const thread_a = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    const CountingConnector = struct {
        inner: runtime.HandshakeClientPoolDefaultConnector,
        connects: usize = 0,

        fn connect(
            context: *anyopaque,
            allocator_value: std.mem.Allocator,
            io_value: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            client_limits: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connects += 1;
            return self.inner.connector().connect(
                &self.inner,
                allocator_value,
                io_value,
                local_address,
                uri,
                client_limits,
            );
        }
    };
    var connector = CountingConnector{ .inner = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = .{
            .context = &connector,
            .connect = CountingConnector.connect,
        },
    });
    defer pool.deinit();

    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b_one = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-b/one",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_one);
    const uri_b_two = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/origin-b/two",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_two);

    var response_a = try pool.requestUri(uri_a, .{});
    defer response_a.deinit(allocator);
    // The only connection slot is idle for origin A here. Acquiring origin B
    // must retire A before dialing B rather than rejecting the request or
    // temporarily exceeding the configured total.
    var response_b_one = try pool.requestUri(uri_b_one, .{});
    defer response_b_one.deinit(allocator);
    var response_b_two = try pool.requestUri(uri_b_two, .{});
    defer response_b_two.deinit(allocator);

    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;

    try std.testing.expectEqualStrings("a", response_a.response.body);
    try std.testing.expectEqualStrings("b-one", response_b_one.response.body);
    try std.testing.expectEqualStrings("b-two", response_b_two.response.body);
    try std.testing.expectEqual(@as(usize, 1), worker_a.requests);
    try std.testing.expectEqual(@as(usize, 2), worker_b.requests);
    try std.testing.expectEqual(@as(usize, 2), connector.connects);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);
}
