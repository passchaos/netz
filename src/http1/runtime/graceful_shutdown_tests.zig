const std = @import("std");
const runtime = @import("../runtime.zig");
const http1 = @import("../mod.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

test "HTTP/1 graceful shutdown exits before an idle request read" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        served: usize = 1,
        err: ?anyerror = null,

        const Context = struct {
            fn handle(
                _: *@This(),
                _: http1.Request,
            ) runtime.Error!runtime.ResponseOptions {
                return error.InvalidResponse;
            }
        };

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            connection.gracefulShutdown();
            var context: Context = .{};
            self.served = connection.serve(
                &context,
                Context.handle,
                8,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try shared.accepted.wait(io);
    var byte: [1]u8 = undefined;
    var reader = stream.reader(io, &byte);
    try std.testing.expectError(
        error.EndOfStream,
        reader.interface.takeByte(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.served);
}

test "HTTP/1 graceful shutdown drains the active request and closes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Context = struct {
        connection: *runtime.Connection,

        fn handle(self: *@This(), request: http1.Request) runtime.Error!runtime.ResponseOptions {
            if (!std.mem.eql(u8, request.target, "/drain")) {
                return error.InvalidResponse;
            }
            self.connection.gracefulShutdown();
            return .{ .body = "drained" };
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        served: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var context = Context{ .connection = &connection };
            self.served = connection.serve(
                &context,
                Context.handle,
                8,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
    );
    defer client.close();
    var response = try client.request(.{ .target = "/drain" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("drained", response.response.body);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{ .target = "/after-drain" }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
}

test "HTTP/1 TLS graceful shutdown drains the active request" {
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

    const Context = struct {
        connection: *runtime.Connection,

        fn handle(self: *@This(), _: http1.Request) runtime.Error!runtime.ResponseOptions {
            self.connection.gracefulShutdown();
            return .{ .body = "tls-drained" };
        }
    };
    const Shared = struct {
        server: *runtime.TlsServer,
        served: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var context = Context{ .connection = &connection };
            self.served = connection.serve(
                &context,
                Context.handle,
                8,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .verify_host = false },
    );
    defer client.close();
    var response = try client.request(.{ .target = "/tls-drain" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("tls-drained", response.response.body);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
}

test "HTTP/1 graceful shutdown overrides conflicting keep-alive header" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Context = struct {
        connection: *runtime.Connection,

        fn handle(self: *@This(), _: http1.Request) runtime.Error!runtime.ResponseOptions {
            self.connection.gracefulShutdown();
            return .{
                .headers = &.{
                    .{ .name = "Connection", .value = "keep-alive" },
                    .{ .name = "X-Test", .value = "preserved" },
                },
                .body = "override",
            };
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var context = Context{ .connection = &connection };
            const served = connection.serve(
                &context,
                Context.handle,
                8,
            ) catch |err| {
                self.err = err;
                return;
            };
            if (served != 1) self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
    );
    defer client.close();
    var response = try client.request(.{ .target = "/override" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "close",
        response.response.header("connection").?,
    );
    try std.testing.expectEqualStrings(
        "preserved",
        response.response.header("x-test").?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
