const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "WebSocket serveUntil rejects invalid options for every listener" {
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *runtime.Connection,
        ) runtime.Error!void {}
    };
    var context: Handler = .{};
    var shutdown: std.Io.Event = .unset;
    var tcp: runtime.Server = undefined;
    var unix: runtime.UnixServer = undefined;
    var tls: runtime.TlsServer = undefined;

    try std.testing.expectError(
        error.InvalidServeOptions,
        tcp.serveUntil(
            Handler,
            &context,
            Handler.handle,
            0,
            .{},
            .{ .shutdown = &shutdown },
        ),
    );
    try std.testing.expectError(
        error.InvalidServeOptions,
        unix.serveUntil(
            Handler,
            &context,
            Handler.handle,
            0,
            .{},
            .{ .shutdown = &shutdown },
        ),
    );
    try std.testing.expectError(
        error.InvalidServeOptions,
        tls.serveUntil(
            Handler,
            &context,
            Handler.handle,
            0,
            .{},
            .{ .shutdown = &shutdown },
        ),
    );
}

test "WebSocket serveUntil isolates handshake errors and reuses its worker" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        stage: runtime.ServeErrorStage = .connection,

        fn observe(context_ptr: *anyopaque, event: runtime.ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.stage = event.stage;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        handled: std.atomic.Value(usize) = .init(0),

        fn handle(
            self: *@This(),
            connection: *runtime.Connection,
        ) runtime.Error!void {
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            if (message.opcode != .text) return error.ProtocolFailure;
            _ = self.handled.fetchAdd(1, .release);
            try connection.sendText(message.payload);
            if (std.mem.eql(u8, message.payload, "stop")) {
                self.shutdown.set(self.io);
            }
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer,
        context: Context,
        err: ?anyerror = null,

        fn init(server_ptr: *runtime.Server, io_value: std.Io) @This() {
            var shared: @This() = undefined;
            shared.server = server_ptr;
            shared.shutdown = .unset;
            shared.observer = .{ .io = io_value };
            shared.context = .{
                .io = io_value,
                .shutdown = &shared.shutdown,
            };
            shared.err = null;
            return shared;
        }

        fn run(self: *@This()) void {
            // `init` cannot safely retain an interior pointer after the value
            // moves into its caller, so bind it at the stable stack address.
            self.context.shutdown = &self.shutdown;
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                .{},
                .{
                    .shutdown = &self.shutdown,
                    .error_observer = .{
                        .context = &self.observer,
                        .observe = Observer.observe,
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared.init(&server, io);
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    // An incomplete opening handshake is a connection-local admission error.
    // The only worker must continue and accept subsequent valid clients.
    const malformed = try server.address().connect(io, .{ .mode = .stream });
    malformed.close(io);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(runtime.ServeErrorStage.accept, shared.observer.stage);

    for ([_][]const u8{ "first", "stop" }) |payload| {
        var client = try runtime.Client.connect(
            allocator,
            io,
            server.address(),
            .{
                .host = "localhost",
                .target = "/supervised",
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                },
            },
        );
        defer client.close();
        try client.sendText(payload);
        var response = try client.receiveMessage();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
        try std.testing.expectEqualStrings(payload, response.payload);
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.observer.count.load(.acquire),
    );
}

test "WebSocket serveUntil can stop on a handler error" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            connection: *runtime.Connection,
        ) runtime.Error!void {
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            return error.ProtocolFailure;
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        shutdown: std.Io.Event = .unset,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                .{},
                .{
                    .shutdown = &self.shutdown,
                    .connection_error_policy = .stop,
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .host = "localhost", .target = "/stop-on-error" },
    );
    defer client.close();
    try client.sendText("trigger");

    server_thread.join();
    joined = true;
    try std.testing.expectEqual(error.ProtocolFailure, shared.err.?);
}

const tls_testing = @import("../../tls/testing.zig");

test "WebSocket TLS listener rejects non-HTTP/1.1 ALPN offers" {
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
    const certificate_chain = [_][]const u8{&certificate_der};

    try std.testing.expectError(
        error.InvalidAlpn,
        runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = &certificate_chain,
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .alpn_protocols = &.{"h2"},
            },
        ),
    );
}
