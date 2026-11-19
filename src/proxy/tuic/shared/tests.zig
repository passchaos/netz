//! End-to-end coverage for the shared-endpoint TUIC server.

const std = @import("std");
const net = std.Io.net;

const netz = @import("../../netz.zig");
const protocol = @import("../protocol.zig");
const server_mod = @import("../server.zig");
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
    uuid: [16]u8,
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
                .alpn_protocols = &.{"h3"},
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

        var token: [32]u8 = undefined;
        try established.exportKeyingMaterial(
            &self.uuid,
            self.password,
            &token,
        );
        const auth = protocol.buildAuthenticate(self.uuid, token);
        const uni = try established.connection.openUnidirectionalStream();
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = uni,
            .offset = 0,
            .data = &auth,
            .fin = true,
        } }});

        const stream_id = try established.connection.openStream();
        const command = try protocol.buildConnect(
            allocator,
            .{ .ip = self.target },
        );
        defer allocator.free(command);
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = 0,
            .data = command,
            .fin = false,
        } }});
        try established.connection.send(&.{.{ .stream = .{
            .stream_id = stream_id,
            .offset = command.len,
            .data = self.payload,
            .fin = true,
        } }});

        var buffer: [128]u8 = undefined;
        var received: usize = 0;
        var saw_fin = false;
        while (!saw_fin) {
            const event = try established.connection
                .receiveStreamIdWithTimeout(
                @intCast(stream_id),
                &buffer,
                .fromSeconds(5),
            );
            switch (event) {
                .reset => return error.UnexpectedStreamReset,
                .data => |data| {
                    if (received + data.bytes > buffer.len) {
                        return error.UnexpectedPayload;
                    }
                    received += data.bytes;
                    saw_fin = data.fin;
                },
            }
        }
        try std.testing.expectEqualSlices(
            u8,
            self.payload,
            buffer[0..received],
        );
    }
};

test "TUIC shared endpoint serves two concurrent TCP relays" {
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

    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const uuid = [_]u8{0x42} ** 16;
    const password = "netz-tuic-shared-test";
    var server = try server_mod.Server.init(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .uuid = uuid,
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
            .uuid = uuid,
            .password = password,
            .payload = "hello-0",
            .index = 0,
        },
        .{
            .io = io,
            .peer = server.address(),
            .target = target,
            .uuid = uuid,
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
    for (clients) |client| if (client.err) |err| {
        return err;
    };
}
