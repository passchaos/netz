const std = @import("std");
const grpc = @import("mod.zig");
const tls_testing = @import("../tls/testing.zig");

test "gRPC h2c runtime reuses one channel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.deinit();
            for (0..2) |index| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                const expected = if (index == 0) "one" else "two";
                if (!std.mem.eql(
                    u8,
                    request.request.message.payload,
                    expected,
                )) {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnary(request.request.stream_id, .{
                    .message = if (index == 0) "first" else "second",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var first = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "one",
    });
    defer first.deinit();
    var second = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .authority = "localhost",
        .message = "two",
    });
    defer second.deinit();
    try std.testing.expectEqualStrings("first", first.message.?.payload);
    try std.testing.expectEqualStrings("second", second.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "gRPC h2c runtime composes sequential message streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 64, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        received: usize = 0,
        err: ?anyerror = null,

        fn consume(
            self: *@This(),
            message: grpc.StreamingMessage,
        ) !void {
            const expected = switch (self.received) {
                0 => "one",
                1 => "two",
                else => return error.UnexpectedMessage,
            };
            if (!std.mem.eql(u8, message.payload, expected)) {
                return error.InvalidGrpcRequest;
            }
            self.received += 1;
        }

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var request = try connection.readStreaming(self, consume);
            defer request.deinit();
            if (!std.mem.eql(u8, request.service, "demo.Echo") or
                !std.mem.eql(u8, request.method, "Stream") or
                request.message_count != 2)
            {
                return error.InvalidGrpcRequest;
            }
            var response = try connection.startStreamingResponse(
                request.transport.stream_id,
                .{
                    .request_accepted_encodings = request.accepted_encodings,
                },
            );
            defer response.deinit();
            try response.writeMessage("first");
            try response.writeMessage("second");
            try response.finishOk();
        }
    };

    const Collector = struct {
        count: usize = 0,

        fn consume(
            self: *@This(),
            message: grpc.StreamingMessage,
        ) !void {
            const expected = switch (self.count) {
                0 => "first",
                1 => "second",
                else => return error.UnexpectedMessage,
            };
            if (!std.mem.eql(u8, message.payload, expected)) {
                return error.UnexpectedMessage;
            }
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 64, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var stream = try client.startStreaming(.{
        .path = "/demo.Echo/Stream",
        .authority = "localhost",
    });
    defer stream.deinit();
    try stream.writeMessage("one");
    try stream.writeMessage("two");
    var collector: Collector = .{};
    var response = try stream.finishAndRead(
        &collector,
        Collector.consume,
    );
    defer response.deinit();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.received);
    try std.testing.expectEqual(@as(usize, 2), collector.count);
    try std.testing.expectEqual(grpc.Status.ok, response.status);
}

test "gRPC TLS runtime verifies ALPN and reuses one channel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try grpc.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .transport = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.TlsServer,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            self.accepts += 1;
            defer connection.deinit();
            if (!std.mem.eql(
                u8,
                connection.negotiatedAlpn() orelse {
                    self.err = error.InvalidAlpn;
                    return;
                },
                "h2",
            )) {
                self.err = error.InvalidAlpn;
                return;
            }
            for (0..2) |index| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                const expected = if (index == 0) "one" else "two";
                if (!std.mem.eql(
                    u8,
                    request.request.message.payload,
                    expected,
                )) {
                    self.err = error.InvalidGrpcRequest;
                    return;
                }
                connection.writeUnary(request.request.stream_id, .{
                    .message = if (index == 0) "first" else "second",
                }) catch |err| {
                    self.err = err;
                    return;
                };
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{
            .limits = .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "h2",
        client.negotiatedAlpn().?,
    );
    var first = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "one",
    });
    defer first.deinit();
    var second = try client.unary(.{
        .path = "/demo.Echo/Unary",
        .message = "two",
    });
    defer second.deinit();
    try std.testing.expectEqual(grpc.Status.ok, first.status);
    try std.testing.expectEqualStrings("first", first.message.?.payload);
    try std.testing.expectEqualStrings("second", second.message.?.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}
