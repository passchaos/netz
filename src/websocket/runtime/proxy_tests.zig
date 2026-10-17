const std = @import("std");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

fn acceptProxyTunnel(
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: *net.Server,
    expected_target: []const u8,
) !net.Stream {
    const stream = try listener.accept(io);
    var owned = true;
    errdefer if (owned) stream.close(io);
    var connect = try http1_runtime.readRequestFromStream(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{},
    );
    defer connect.deinit(allocator);
    try std.testing.expect(connect.request.method == .CONNECT);
    try std.testing.expectEqualStrings(
        expected_target,
        connect.request.target,
    );
    try std.testing.expectEqualStrings(
        "Basic d3MtcHJveHk=",
        connect.request.header("proxy-authorization").?,
    );
    try http1_runtime.writeResponseToStream(
        allocator,
        io,
        stream,
        .{ .status = 200, .request_method = .CONNECT },
    );
    owned = false;
    return stream;
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

fn verifyPending(pending: runtime.PendingUpgrade) !void {
    try std.testing.expectEqualStrings("/chat?q=1", pending.target());
    try std.testing.expectEqualStrings("localhost", pending.header("host").?);
    try std.testing.expectEqualStrings(
        "Bearer origin",
        pending.header("authorization").?,
    );
    try std.testing.expect(pending.header("proxy-authorization") == null);
}

test "WebSocket WS URI connects through HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "localhost:80",
            );
            var pending = try self.server.receiveStreamUpgradeRequest(
                stream,
                .{},
            );
            try verifyPending(pending);
            var connection = try pending.accept();
            defer connection.close();
            var request = try connection.receiveMessage();
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings("proxy-ws", request.payload);
            try connection.sendText("echo-proxy-ws");
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const Resolver = struct {
        proxy_address: net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "proxy.resolver.test") or
                port != self.proxy_address.getPort() or deadline == null)
            {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(net.IpAddress, 2);
            addresses[0] = .{ .ip4 = .loopback(0) };
            addresses[1] = self.proxy_address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{ .proxy_address = proxy.socket.address };
    var proxy_uri_buffer: [96]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://proxy.resolver.test:{d}",
        .{proxy.socket.address.getPort()},
    );
    var connection = try runtime.Client.connectUriViaProxyWithTimeout(
        allocator,
        io,
        proxy_uri,
        "ws://localhost/chat?q=1#not-on-wire",
        .{
            .extra_headers = &.{.{
                .name = "Authorization",
                .value = "Bearer origin",
            }},
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
        .{ .headers = &.{.{
            .name = "Proxy-Authorization",
            .value = "Basic d3MtcHJveHk=",
        }} },
        .{},
        .fromSeconds(3),
    );
    defer connection.close();
    try connection.sendText("proxy-ws");
    var response = try connection.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("echo-proxy-ws", response.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
}

test "WebSocket WSS URI authenticates origin through HTTP CONNECT proxy" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var proxy = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer proxy.deinit(io);
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

    const Shared = struct {
        io: std.Io,
        proxy: *net.Server,
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try acceptProxyTunnel(
                allocator,
                self.io,
                self.proxy,
                "localhost:443",
            );
            var pending = try self.server.receiveStreamUpgradeRequest(
                stream,
                .{},
            );
            try verifyPending(pending);
            var connection = try pending.accept();
            defer connection.close();
            var request = try connection.receiveMessage();
            defer request.deinit(allocator);
            try std.testing.expectEqualStrings("proxy-wss", request.payload);
            try connection.sendText("echo-proxy-wss");
        }
    };
    var shared = Shared{ .io = io, .proxy = &proxy, .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var proxy_uri_buffer: [64]u8 = undefined;
    const proxy_uri = try std.fmt.bufPrint(
        &proxy_uri_buffer,
        "http://127.0.0.1:{d}",
        .{proxy.socket.address.getPort()},
    );
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var connection = try runtime.Client.connectUriViaProxyWithTimeout(
        allocator,
        io,
        proxy_uri,
        "wss://localhost/chat?q=1#not-on-wire",
        .{ .extra_headers = &.{.{
            .name = "Authorization",
            .value = "Bearer origin",
        }} },
        .{ .headers = &.{.{
            .name = "Proxy-Authorization",
            .value = "Basic d3MtcHJveHk=",
        }} },
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
        .fromSeconds(3),
    );
    defer connection.close();
    try connection.sendText("proxy-wss");
    var response = try connection.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("echo-proxy-wss", response.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket proxy URI rejects zero timeout before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectUriViaProxyWithTimeout(
            std.testing.allocator,
            threaded.io(),
            "http://127.0.0.1:1",
            "ws://localhost/chat",
            .{},
            .{},
            .{},
            .zero,
        ),
    );
}
