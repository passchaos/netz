//! End-to-end coverage for the shared-endpoint Hysteria v3 server.

const std = @import("std");
const net = std.Io.net;

const netz = @import("../../netz.zig");
const protocol = @import("../v3_protocol.zig");
const server_mod = @import("../v3_server.zig");
const io_helpers = @import("../../internal/io.zig");
const tls_testing = @import("../../../tls/testing.zig");

const quic = netz.quic;
const gpa = std.testing.allocator;

const AcceptResult = union(enum) {
    stream: net.Server.AcceptError!net.Stream,
    timeout: void,
};

fn acceptTask(listener: *net.Server, io: std.Io) net.Server.AcceptError!net.Stream {
    return listener.accept(io);
}

fn timeoutTask(io: std.Io, duration: std.Io.Duration) void {
    std.Io.sleep(io, duration, .awake) catch {};
}

fn acceptWithTimeout(
    io: std.Io,
    listener: *net.Server,
    duration: std.Io.Duration,
) !?net.Stream {
    var storage: [2]AcceptResult = undefined;
    var select: std.Io.Select(AcceptResult) = .init(io, &storage);
    try select.concurrent(.stream, acceptTask, .{ listener, io });
    try select.concurrent(.timeout, timeoutTask, .{ io, duration });
    defer while (select.cancel()) |outcome| switch (outcome) {
        .stream => |result| {
            if (result) |stream| stream.close(io) else |_| {}
        },
        .timeout => {},
    };
    const outcome = try select.await();
    return switch (outcome) {
        .stream => |result| try result,
        .timeout => null,
    };
}

fn echoLoop(io: std.Io, listener: *net.Server, count: usize) void {
    var accepted: usize = 0;
    while (accepted < count) : (accepted += 1) {
        var stream = (acceptWithTimeout(
            io,
            listener,
            .fromSeconds(10),
        ) catch return) orelse return;
        defer stream.close(io);
        var buffer: [1024]u8 = undefined;
        while (true) {
            const read = io_helpers.readSome(
                io,
                stream,
                &buffer,
                null,
            ) catch break;
            if (read == 0) break;
            io_helpers.writeAll(
                io,
                stream,
                buffer[0..read],
                null,
            ) catch break;
        }
    }
}

fn udpEchoLoop(io: std.Io, socket: net.Socket) void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(10),
    });
    var buffer: [1024]u8 = undefined;
    while (deadline.durationFromNow(io).raw.nanoseconds > 0) {
        const message = socket.receiveTimeout(
            io,
            &buffer,
            .{ .duration = .{
                .clock = .awake,
                .raw = .fromMilliseconds(100),
            } },
        ) catch |err| switch (err) {
            error.Timeout => continue,
            else => return,
        };
        socket.send(io, &message.from, message.data) catch return;
    }
}

const ServeContext = struct {
    server: *server_mod.Server,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.server.serve() catch |err| {
            self.err = err;
        };
    }
};

const AcceptAnyTrust = struct {
    fn verify(_: ?*anyopaque, _: quic.tls.auth.TrustContext) anyerror!void {}
};

const ClientContext = struct {
    io: std.Io,
    peer: net.IpAddress,
    target: net.IpAddress,
    udp_target: ?net.IpAddress,
    password: []const u8,
    payload: []const u8,
    index: u8,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        const allocator = gpa;
        var endpoint = try quic.runtime.Endpoint.bind(
            allocator,
            self.io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer endpoint.deinit();
        var original_dcid = [_]u8{0x90} ** 8;
        original_dcid[0] +%= self.index;
        var client_cid = [_]u8{0xa0} ** 8;
        client_cid[0] +%= self.index;
        var established = try quic.handshake.connect(
            &endpoint,
            self.peer,
            .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .alpn_protocols = &.{"hysteria"},
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .server_auth = .{ .verify_trust = AcceptAnyTrust.verify },
                .handshake_recovery = .{
                    .initial_pto_ms = 50,
                    .max_pto_ms = 200,
                    .max_duration_ms = 5_000,
                },
            },
        );
        defer established.deinit();

        const control_stream = try established.connection.openStream();
        const hello = try protocol.buildClientHello(
            allocator,
            0,
            0,
            self.password,
        );
        defer allocator.free(hello);
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = control_stream,
            .offset = 0,
            .data = hello,
            .fin = false,
        } }});
        var control_buffer: [64]u8 = undefined;
        var control_used: usize = 0;
        while (true) {
            const event = try established.connection
                .receiveStreamIdWithTimeout(
                @intCast(control_stream),
                &control_buffer,
                .fromSeconds(5),
            );
            switch (event) {
                .reset => return error.UnexpectedStreamReset,
                .data => |data| {
                    control_used += data.bytes;
                    if (control_used >= 7) break;
                },
            }
        }
        const server_hello = try protocol.parseServerHello(
            control_buffer[0..control_used],
        );
        try std.testing.expect(server_hello.ok);

        const data_stream = try established.connection.openStream();
        const request = try protocol.buildRequest(
            allocator,
            .tcp,
            "127.0.0.1",
            self.target.getPort(),
        );
        defer allocator.free(request);
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = data_stream,
            .offset = 0,
            .data = request,
            .fin = false,
        } }});
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = data_stream,
            .offset = request.len,
            .data = self.payload,
            .fin = true,
        } }});

        const response_len = 7;
        var buffer: [128]u8 = undefined;
        var received_buffer: [256]u8 = undefined;
        var received: usize = 0;
        var saw_fin = false;
        while (!saw_fin) {
            const event = try established.connection
                .receiveStreamIdWithTimeout(
                @intCast(data_stream),
                &buffer,
                .fromSeconds(5),
            );
            switch (event) {
                .reset => return error.UnexpectedStreamReset,
                .data => |data| {
                    if (received + data.bytes > received_buffer.len) {
                        return error.UnexpectedPayload;
                    }
                    @memcpy(
                        received_buffer[received..][0..data.bytes],
                        buffer[0..data.bytes],
                    );
                    received += data.bytes;
                    saw_fin = data.fin;
                },
            }
        }
        try std.testing.expect(received >= response_len + self.payload.len);
        try std.testing.expectEqualSlices(
            u8,
            self.payload,
            received_buffer[response_len..][0..self.payload.len],
        );

        if (self.udp_target) |udp_target| {
            try self.runUdp(&established, udp_target);
        }
    }

    fn runUdp(
        self: *@This(),
        established: *quic.handshake.EstablishedConnection,
        udp_target: net.IpAddress,
    ) !void {
        _ = self;
        const allocator = gpa;
        const stream_id = try established.connection.openStream();
        const request = try protocol.buildRequest(
            allocator,
            .udp,
            "127.0.0.1",
            udp_target.getPort(),
        );
        defer allocator.free(request);
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = 0,
            .data = request,
            .fin = false,
        } }});
        var response: [32]u8 = undefined;
        const event = try established.connection.receiveStreamIdWithTimeout(
            @intCast(stream_id),
            &response,
            .fromSeconds(5),
        );
        const bytes = switch (event) {
            .reset => return error.UnexpectedStreamReset,
            .data => |data| response[0..data.bytes],
        };
        const parsed = try protocol.parseResponse(bytes);
        try std.testing.expect(parsed.ok);
        try std.testing.expect(parsed.udp_session_id != 0);

        const payload = "netz-hysteria-udp";
        const message = try protocol.buildUdpMessage(
            allocator,
            parsed.udp_session_id,
            "127.0.0.1",
            udp_target.getPort(),
            0,
            0,
            1,
            payload,
        );
        defer allocator.free(message);
        try established.connection.sendDatagram(message);
        var datagram: [256]u8 = undefined;
        const reply = try established.connection.receiveDatagramWithTimeout(
            &datagram,
            .fromSeconds(5),
        );
        const parsed_reply = try protocol.parseUdpMessage(reply);
        try std.testing.expectEqualStrings(payload, parsed_reply.data);
    }
};

test "Hysteria shared endpoint serves concurrent TCP and UDP relays" {
    var threaded = std.Io.Threaded.init(gpa, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const echo_address = net.IpAddress{ .ip4 = .loopback(0) };
    var echo_listener = try echo_address.listen(
        io,
        .{ .reuse_address = true },
    );
    defer echo_listener.deinit(io);
    const target = echo_listener.socket.address;
    var echo_thread = try std.Thread.spawn(
        .{},
        echoLoop,
        .{ io, &echo_listener, 2 },
    );
    defer echo_thread.join();

    var udp_socket = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    defer udp_socket.close(io);
    const udp_target = udp_socket.address;
    var udp_thread = try std.Thread.spawn(
        .{},
        udpEchoLoop,
        .{ io, udp_socket },
    );
    defer udp_thread.join();

    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const password = "netz-hysteria-shared-test";
    var server = try server_mod.Server.init(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .password = password,
            .identity = .{
                .certificate_chain = &.{&public_key},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .acl = .{ .default_action = .allow },
            .connect_timeout = .fromSeconds(3),
            .idle_timeout = .fromSeconds(10),
            .auth_timeout = .fromSeconds(3),
        },
    );
    defer server.deinit();
    var serve_context = ServeContext{ .server = &server };
    const serve_thread = try std.Thread.spawn(
        .{},
        ServeContext.run,
        .{&serve_context},
    );
    defer {
        server.requestStop();
        serve_thread.join();
    }

    var clients = [2]ClientContext{
        .{
            .io = io,
            .peer = server.address(),
            .target = target,
            .udp_target = udp_target,
            .password = password,
            .payload = "hello-0",
            .index = 0,
        },
        .{
            .io = io,
            .peer = server.address(),
            .target = target,
            .udp_target = null,
            .password = password,
            .payload = "hello-1",
            .index = 1,
        },
    };
    var threads: [clients.len]std.Thread = undefined;
    for (&clients, &threads) |*client, *thread| {
        thread.* = try std.Thread.spawn(.{}, ClientContext.run, .{client});
    }
    for (&threads) |thread| thread.join();
    if (serve_context.err) |err| return err;
    for (clients) |client| if (client.err) |err| return err;
}
