const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const Api = enum {
    accept_stream,
    serve_one,
    serve_connection,
};

test "HTTP/1 TLS listener accept deadline expires without a client" {
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
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.acceptWithTimeout(.fromMilliseconds(20)),
    );
}

fn exerciseTlsServerApi(api: Api) !void {
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
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        api: Api,
        handled: usize = 0,
        served: usize = 0,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            request: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            const expected = if (self.handled == 0) "/one" else "/two";
            if (!std.mem.eql(u8, request.target, expected)) {
                return error.InvalidResponse;
            }
            self.handled += 1;
            return .{ .body = if (self.handled == 1) "first" else "second" };
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            switch (self.api) {
                .accept_stream => {
                    const stream = try self.server.listener.accept(
                        self.server.io,
                    );
                    var connection = try self.server.acceptStream(stream);
                    defer connection.close();
                    self.served = try connection.serve(
                        self,
                        @This().handle,
                        1,
                    );
                },
                .serve_one => {
                    try self.server.serveOne(self, @This().handle);
                    self.served = 1;
                },
                .serve_connection => {
                    self.served = try self.server.serveConnection(
                        self,
                        @This().handle,
                        2,
                    );
                },
            }
        }
    };

    var shared = Shared{ .server = &server, .api = api };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();

    var first = try client.request(.{ .target = "/one" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    if (api == .serve_connection) {
        var second = try client.request(.{ .target = "/two" });
        defer second.deinit(allocator);
        try std.testing.expectEqualStrings("second", second.response.body);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const expected: usize = if (api == .serve_connection) 2 else 1;
    try std.testing.expectEqual(expected, shared.served);
    try std.testing.expectEqual(expected, shared.handled);
}

test "HTTP/1 TLS server adopts an accepted stream" {
    try exerciseTlsServerApi(.accept_stream);
}

test "HTTP/1 TLS server serves one request" {
    try exerciseTlsServerApi(.serve_one);
}

test "HTTP/1 TLS server serves a persistent connection" {
    try exerciseTlsServerApi(.serve_connection);
}
