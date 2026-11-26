//! HTTP/1 CONNECT tunnel, TLS half-close, and Upgrade tests.

const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
const http1 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const CertificateBundle = runtime.CertificateBundle;
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const Error = runtime.Error;
const IdleSocketState = runtime.IdleSocketState;
const InformationalResponseHead = runtime.InformationalResponseHead;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const TunnelWriteProgress = runtime.TunnelWriteProgress;
const Server = runtime.Server;
const StapledOcspPolicy = runtime.StapledOcspPolicy;
const TlsServer = runtime.TlsServer;
const Tunnel = runtime.Tunnel;
const WriteScratch = runtime.WriteScratch;
const WriteStrategy = runtime.WriteStrategy;
const adjustResponseForServeLoop = runtime.adjustResponseForServeLoop;
const body_writer = runtime.body_writer;
const builtin = runtime.builtin;
const close_delimited = runtime.close_delimited;
const localTestCaBundle = runtime.localTestCaBundle;
const probeIdleSocket = runtime.probeIdleSocket;
const readExactForTest = runtime.readExactForTest;
const readMessageBytesBufferedWithContext = runtime.readMessageBytesBufferedWithContext;
const readRequestFromStream = runtime.readRequestFromStream;
const readResponseFromStreamBuffered = runtime.readResponseFromStreamBuffered;
const readResponseFromStreamBufferedForRequest = runtime.readResponseFromStreamBufferedForRequest;
const readResponseFromStreamForRequest = runtime.readResponseFromStreamForRequest;
const readSome = runtime.readSome;
const requestShouldSendContinue = runtime.requestShouldSendContinue;
const responseBatchWriteStrategy = runtime.responseBatchWriteStrategy;
const responseOptionsKeepAlive = runtime.responseOptionsKeepAlive;
const response_batch_borrow_threshold = runtime.response_batch_borrow_threshold;
const runtime_write = runtime.runtime_write;
const shutdownAfterTlsCloseNotify = runtime.shutdownAfterTlsCloseNotify;
const stream_io = runtime.stream_io;
const tls = runtime.tls;
const tls_stream = runtime.tls_stream;
const uriEndpoint = runtime.uriEndpoint;
const vail = runtime.vail;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const wire = runtime.wire;
const writeAllToStream = runtime.writeAllToStream;
const writeRequestToStream = runtime.writeRequestToStream;
const writeResponseToStream = runtime.writeResponseToStream;
const writeResponsesToTransportScratch = runtime.writeResponsesToTransportScratch;

test "HTTP/1 runtime opens CONNECT tunnel" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expect(request.request.method == .CONNECT);
            try std.testing.expectEqualStrings("example.com:443", request.request.target);
            try std.testing.expectEqualStrings("example.com:443", request.request.header("host").?);

            var tunnel = try connection.acceptConnectTunnel(request.request, &.{});
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.readRequest(.{}),
            );
            try std.testing.expectError(
                error.ConnectionUnusable,
                connection.writeResponse(.{ .status = 204 }),
            );
            var buf: [64]u8 = undefined;
            const n = try tunnel.read(&buf);
            try std.testing.expectEqualStrings("client tunnel bytes", buf[0..n]);
            try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));
            try tunnel.writeParts("server tunnel ", "bytes");
            try tunnel.closeWrite();
            try std.testing.expectError(
                error.ConnectionClosed,
                tunnel.write("late server bytes"),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var tunnel = try client.openConnectTunnelWithTimeout(
        "example.com:443",
        &.{},
        .fromSeconds(2),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .method = .GET,
            .target = "/after-connect",
            .host = "example.com",
        }),
    );
    try tunnel.writeSlices(&.{ "client ", "", "tunnel ", "bytes" });
    try tunnel.closeWrite();
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.closeWrite(),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("late client bytes"),
    );
    var buf: [64]u8 = undefined;
    const n = try tunnel.read(&buf);
    try std.testing.expectEqualStrings("server tunnel bytes", buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&buf));

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(
        error.ConnectionUnusable,
        client.openConnectTunnel("/not-authority", &.{}),
    );
}

test "HTTP/1 TLS tunnels close the write half and retain reads" {
    const allocator = std.testing.allocator;
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    inline for (.{ false, true }) |use_vail_client| {
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();
        var server = try TlsServer.listen(
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
            server: *TlsServer,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                var tunnel = try connection.acceptConnectTunnel(
                    request.request,
                    &.{},
                );
                var received: [12]u8 = undefined;
                var offset: usize = 0;
                while (true) {
                    const count = try tunnel.read(received[offset..]);
                    if (count == 0) break;
                    offset += count;
                }
                try std.testing.expectEqualStrings(
                    "client bytes",
                    received[0..offset],
                );
                try tunnel.writeParts("server ", "bytes");
                try tunnel.closeWrite();
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.write("late server bytes"),
                );
                try std.testing.expectError(
                    error.ConnectionClosed,
                    tunnel.updateTrafficKeys(false),
                );
            }
        };
        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();

        var ca: ?struct { CertificateBundle, std.Io.RwLock } = null;
        defer if (ca) |*value| value[0].deinit(allocator);
        var client = if (use_vail_client)
            try Client.connectVailTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                } },
            )
        else client: {
            ca = try localTestCaBundle(allocator, io);
            break :client try Client.connectTlsHost(
                allocator,
                io,
                "localhost",
                server.address().ip4.port,
                .{},
                .{ .ca_bundle = .{
                    .bundle = &ca.?[0],
                    .lock = &ca.?[1],
                } },
            );
        };
        defer client.close();
        var tunnel = try client.openConnectTunnelWithTimeout(
            "example.com:443",
            &.{},
            .fromSeconds(2),
        );
        try tunnel.writeSlices(&.{ "client", "", " ", "bytes" });
        try tunnel.closeWrite();
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.closeWrite(),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.write("late client bytes"),
        );
        try std.testing.expectError(
            error.ConnectionClosed,
            tunnel.updateTrafficKeys(false),
        );
        var received: [12]u8 = undefined;
        var offset: usize = 0;
        while (true) {
            const count = try tunnel.read(received[offset..]);
            if (count == 0) break;
            offset += count;
        }
        try std.testing.expectEqualStrings(
            "server bytes",
            received[0..offset],
        );

        thread.join();
        joined = true;
        if (shared.err) |err| return err;
    }
}

test "HTTP/1 tunnel write-half close failure is terminal" {
    try native_protocol_io.runStream(tunnelWriteCloseFailure);
}

fn tunnelWriteCloseFailure(io: std.Io) !void {
    const PartialFailWriter = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    const FailingIo = struct {
        delegate: std.Io,
        shutdown_calls: usize = 0,
        write_calls: usize = 0,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.shutdown_calls += 1;
            return error.NetworkDown;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.write_calls += 1;
            return error.NetworkDown;
        }
    };

    var write_failure: FailingIo = .{ .delegate = io };
    var write_failure_inbuf: std.ArrayList(u8) = .empty;
    defer write_failure_inbuf.deinit(std.testing.allocator);
    var write_failure_tunnel = Tunnel{
        .io = forwarded_io.observer(&write_failure, .{ .netWrite = FailingIo.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &write_failure_inbuf,
    };
    try std.testing.expectError(
        error.NetworkDown,
        write_failure_tunnel.write("first-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        write_failure_tunnel.write("must-not-write"),
    );
    try std.testing.expectEqual(@as(usize, 1), write_failure.write_calls);

    var partial: PartialFailWriter = .{ .delegate = io };
    var partial_inbuf: std.ArrayList(u8) = .empty;
    defer partial_inbuf.deinit(std.testing.allocator);
    var partial_tunnel = Tunnel{
        .io = forwarded_io.observer(&partial, .{ .netWrite = PartialFailWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &partial_inbuf,
    };

    try std.testing.expectError(
        error.NetworkDown,
        partial_tunnel.writeParts("head", "payload"),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeParts("must", "not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        partial_tunnel.writeSlices(&.{ "must", "not", "write" }),
    );
    try std.testing.expectEqual(@as(usize, 2), partial.calls);

    var zero_budget: FailingIo = .{ .delegate = io };
    var zero_budget_inbuf: std.ArrayList(u8) = .empty;
    defer zero_budget_inbuf.deinit(std.testing.allocator);
    var zero_budget_tunnel = Tunnel{
        .io = forwarded_io.observer(&zero_budget, .{ .netWrite = FailingIo.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &zero_budget_inbuf,
    };
    var zero_budget_progress: TunnelWriteProgress = .{ .committed_bytes = 99 };
    try std.testing.expectError(
        error.Timeout,
        zero_budget_tunnel.writeSlicesWithTimeout(
            &.{ "must", "not", "write" },
            &zero_budget_progress,
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), zero_budget.write_calls);
    try std.testing.expectEqual(@as(usize, 0), zero_budget_progress.committed_bytes);

    var failing: FailingIo = .{ .delegate = io };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(std.testing.allocator);
    var tunnel = Tunnel{
        .io = forwarded_io.observer(&failing, .{ .netShutdown = FailingIo.shutdown, .netWrite = FailingIo.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &inbuf,
    };

    try std.testing.expectError(error.NetworkDown, tunnel.closeWrite());
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectError(error.ConnectionClosed, tunnel.closeWrite());
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.write("must-not-write"),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        tunnel.updateTrafficKeys(false),
    );
    try std.testing.expectEqual(@as(usize, 1), failing.shutdown_calls);
    try std.testing.expectEqual(@as(usize, 0), failing.write_calls);
}

test "HTTP/1 TLS post-close-notify shutdown treats disconnected peer as complete" {
    try native_protocol_io.runStream(postNotifyPeerShutdown);
}

fn postNotifyPeerShutdown(base_io: std.Io) !void {
    const ShutdownIo = struct {
        delegate: std.Io,
        calls: usize = 0,
        result: enum { disconnected, failed } = .disconnected,

        fn shutdown(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: net.ShutdownHow,
        ) net.ShutdownError!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            return switch (self.result) {
                .disconnected => error.SocketUnconnected,
                .failed => error.NetworkDown,
            };
        }
    };

    var state: ShutdownIo = .{ .delegate = base_io };
    const io = forwarded_io.observer(&state, .{ .netShutdown = ShutdownIo.shutdown });
    const stream: net.Stream = undefined;

    try shutdownAfterTlsCloseNotify(io, stream);
    try std.testing.expectEqual(@as(usize, 1), state.calls);

    state.result = .failed;
    try std.testing.expectError(
        error.NetworkDown,
        shutdownAfterTlsCloseNotify(io, stream),
    );
    try std.testing.expectEqual(@as(usize, 2), state.calls);
}

test "HTTP/1 tunnel deadline preserves buffered bytes and recovers after timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        buffered_read: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.buffered_read.set(self.io);
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-timeout",
                &.{},
            );

            var buffer: [16]u8 = undefined;
            const buffered = try tunnel.readWithTimeout(
                &buffer,
                .fromNanoseconds(0),
            );
            try std.testing.expectEqualStrings(
                "buffered",
                buffer[0..buffered],
            );
            self.buffered_read.set(self.io);

            try std.testing.expectError(
                error.Timeout,
                tunnel.readWithTimeout(
                    &buffer,
                    .fromMilliseconds(20),
                ),
            );
            self.timed_out.set(self.io);

            const resumed = try tunnel.readWithDeadline(
                &buffer,
                .fromNow(
                    self.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            );
            try std.testing.expectEqualStrings(
                "after-timeout",
                buffer[0..resumed],
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: netz-timeout\r\n\r\nbuffered",
    );
    var tunnel = try client.finishUpgradeWithTimeout(
        "netz-timeout",
        .fromSeconds(2),
    );
    try shared.buffered_read.wait(io);
    try shared.timed_out.wait(io);
    try tunnel.write("after-timeout");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime hands off generic Upgrade with buffered bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            var tunnel = try connection.acceptUpgrade(
                request.request,
                "netz-test",
                &.{},
            );
            try tunnel.write("server-preface");
            var payload: [14]u8 = undefined;
            var read: usize = 0;
            while (read < payload.len) {
                const count = try tunnel.read(payload[read..]);
                if (count == 0) return error.ConnectionClosed;
                read += count;
            }
            try std.testing.expectEqualStrings(
                "client-preface",
                &payload,
            );
            try tunnel.closeWrite();
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try writeAllToStream(
        io,
        client.stream,
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\n" ++
            "Connection: keep-alive, Upgrade\r\n" ++
            "Upgrade: netz-test\r\n\r\nclient-preface",
    );
    var tunnel = try client.finishUpgradeWithTimeout(
        "netz-test",
        .fromSeconds(2),
    );
    try tunnel.closeWrite();
    var preface: [14]u8 = undefined;
    var read: usize = 0;
    while (read < preface.len) {
        const count = try tunnel.read(preface[read..]);
        if (count == 0) return error.ConnectionClosed;
        read += count;
    }
    try std.testing.expectEqualStrings("server-preface", &preface);
    try std.testing.expectEqual(@as(usize, 0), try tunnel.read(&preface));

    thread.join();
    if (shared.err) |err| return err;
}

test "CONNECT-UDP tunnel adapter timeout rejects non-positive budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(std.testing.allocator);
    const tunnel = Tunnel{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .inbuf = &inbuf,
    };
    var adapter = runtime.ConnectUdpTunnel.init(
        std.testing.allocator,
        tunnel,
    );
    defer adapter.deinit();
    var progress: TunnelWriteProgress = .{ .committed_bytes = 99 };
    try std.testing.expectError(
        error.Timeout,
        adapter.writeSlicesWithTimeout(
            &.{"must-not-write"},
            false,
            &progress,
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expectError(
        error.Timeout,
        adapter.readWithTimeout(.fromNanoseconds(0)),
    );
}
