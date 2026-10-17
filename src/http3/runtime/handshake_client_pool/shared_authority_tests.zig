const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "HTTP/3 active route coalesces authorized ORIGIN and honors 421" {
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
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
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

    const authority_a = "localhost:4443";
    const authority_b = "localhost:4444";
    const origin_b = "https://localhost:4444";
    const origin_c = "https://unauthorized.invalid:4445";
    const Worker = struct {
        server: *runtime.HandshakeServer,
        accepts: usize = 0,
        requests: usize = 0,
        first_streams: [2]u62 = .{ 0, 0 },
        coalesced_stream: ?u62 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn receive(
            self: *@This(),
            session: *runtime.HandshakeServerSession,
        ) !runtime.OwnedHandshakeRequest {
            const request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            self.requests += 1;
            return request;
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();

            var first = try self.receive(&session);
            defer first.deinit(self.server.allocator);
            var second = try self.receive(&session);
            defer second.deinit(self.server.allocator);
            self.first_streams = .{ first.stream_id, second.stream_id };
            const prime, const hold = if (std.mem.eql(
                u8,
                first.request.path,
                "/prime",
            ) and std.mem.eql(u8, second.request.path, "/hold"))
                .{ &first, &second }
            else if (std.mem.eql(u8, first.request.path, "/hold") and
                std.mem.eql(u8, second.request.path, "/prime"))
                .{ &second, &first }
            else
                return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings(
                authority_a,
                prime.request.authority.?,
            );
            try std.testing.expectEqualStrings(
                authority_a,
                hold.request.authority.?,
            );
            try session.sendOrigins(&.{ origin_b, origin_c });
            try session.sendResponse(prime.stream_id, .{
                .status = 200,
                .request_method = prime.request.method,
                .body = "prime",
            });

            var coalesced = try self.receive(&session);
            defer coalesced.deinit(self.server.allocator);
            self.coalesced_stream = coalesced.stream_id;
            try std.testing.expectEqualStrings(
                authority_b,
                coalesced.request.authority.?,
            );
            try std.testing.expectEqualStrings(
                "/coalesced",
                coalesced.request.path,
            );
            try session.sendResponse(coalesced.stream_id, .{
                .status = 421,
                .request_method = coalesced.request.method,
                .body = "misdirected",
            });

            const unexpected = session.receiveRequestWithTimeout(
                .fromMilliseconds(700),
            );
            if (unexpected) |request_value| {
                var request = request_value;
                request.deinit(self.server.allocator);
                return error.TestUnexpectedResult;
            } else |err| switch (err) {
                error.Timeout => {},
                else => return err,
            }
            try session.sendResponse(hold.stream_id, .{
                .status = 203,
                .request_method = hold.request.method,
                .body = "hold",
            });
        }
    };
    var worker = Worker{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

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
    var dispatcher = try runtime.HandshakeClientPoolSharedDispatcher.init(
        allocator,
        io,
        &pool,
        .{ .max_connection_drivers = 4 },
    );
    var dispatcher_active = true;
    defer if (dispatcher_active) dispatcher.deinit();
    const sender = dispatcher.sender();
    var driver = try std.Io.concurrent(
        io,
        runtime.HandshakeClientPoolSharedDispatcher.run,
        .{&dispatcher},
    );
    var driver_active = true;
    defer if (driver_active) {
        dispatcher.close();
        driver.cancel(io) catch {};
        driver.await(io) catch {};
    };

    const uri_a_prime = "https://localhost:4443/prime";
    const uri_a_hold = "https://localhost:4443/hold";
    const uri_b = "https://localhost:4444/coalesced";
    const uri_b_again = "https://localhost:4444/after-421";
    const uri_c = "https://unauthorized.invalid:4445/no-certificate";
    const uri_d = "https://localhost:4446/not-advertised";
    const target_a: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "localhost",
        .port = server.address().ip4.port,
    };
    const target_b = target_a;
    const target_c: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "unauthorized.invalid",
        .port = server.address().ip4.port,
    };
    const target_d = target_a;

    const Producer = struct {
        fn response(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
            target: http3.AltSvcTarget,
            status: u16,
            body: []const u8,
            request_timeout: std.Io.Duration,
        ) !void {
            var value = try request_sender.requestAltSvcWithTimeout(
                uri,
                target,
                .{},
                request_timeout,
            );
            defer value.deinit(std.testing.allocator);
            try std.testing.expectEqual(status, value.response.status);
            try std.testing.expectEqualStrings(body, value.response.body);
        }

        fn timeout(
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
            target: http3.AltSvcTarget,
        ) !void {
            var value = request_sender.requestAltSvcWithTimeout(
                uri,
                target,
                .{},
                .fromMilliseconds(400),
            ) catch |err| {
                try std.testing.expectEqual(error.Timeout, err);
                return;
            };
            value.deinit(std.testing.allocator);
            return error.TestUnexpectedResult;
        }
    };

    var start_a: std.Io.Event = .unset;
    const StartedProducer = struct {
        fn response(
            start: *std.Io.Event,
            io_value: std.Io,
            request_sender: runtime.HandshakeClientPoolSharedSender,
            uri: []const u8,
            target: http3.AltSvcTarget,
            status: u16,
            body: []const u8,
        ) !void {
            try start.wait(io_value);
            return Producer.response(
                request_sender,
                uri,
                target,
                status,
                body,
                .fromSeconds(5),
            );
        }
    };
    var prime = try std.Io.concurrent(
        io,
        StartedProducer.response,
        .{ &start_a, io, sender.clone(), uri_a_prime, target_a, @as(u16, 200), "prime" },
    );
    var hold = try std.Io.concurrent(
        io,
        StartedProducer.response,
        .{ &start_a, io, sender.clone(), uri_a_hold, target_a, @as(u16, 203), "hold" },
    );
    var hold_active = true;
    defer if (hold_active) hold.cancel(io) catch {};
    start_a.set(io);
    try prime.await(io);

    var coalesced = try std.Io.concurrent(
        io,
        Producer.response,
        .{ sender.clone(), uri_b, target_b, @as(u16, 421), "misdirected", .fromSeconds(2) },
    );
    try coalesced.await(io);

    var after_421 = try std.Io.concurrent(
        io,
        Producer.timeout,
        .{ sender.clone(), uri_b_again, target_b },
    );
    var after_421_active = true;
    defer if (after_421_active) after_421.cancel(io) catch {};
    var no_certificate = try std.Io.concurrent(
        io,
        Producer.timeout,
        .{ sender.clone(), uri_c, target_c },
    );
    var no_certificate_active = true;
    defer if (no_certificate_active) no_certificate.cancel(io) catch {};
    var not_advertised = try std.Io.concurrent(
        io,
        Producer.timeout,
        .{ sender.clone(), uri_d, target_d },
    );
    var not_advertised_active = true;
    defer if (not_advertised_active) not_advertised.cancel(io) catch {};
    try after_421.await(io);
    after_421_active = false;
    try no_certificate.await(io);
    no_certificate_active = false;
    try not_advertised.await(io);
    not_advertised_active = false;
    try hold.await(io);
    hold_active = false;

    dispatcher.close();
    try driver.await(io);
    driver_active = false;
    dispatcher.deinit();
    dispatcher_active = false;
    server_thread.join();
    server_joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual(@as(usize, 3), worker.requests);
    try std.testing.expectEqual([2]u62{ 0, 4 }, worker.first_streams);
    try std.testing.expectEqual(@as(?u62, 8), worker.coalesced_stream);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}
