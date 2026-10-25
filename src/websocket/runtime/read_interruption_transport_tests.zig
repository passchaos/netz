//! The same local interruption rules apply to WSS and multiplexed adapters.
const std = @import("std");
const runtime = @import("../runtime.zig");
const http2 = @import("../../http2/runtime.zig");
const h3 = @import("h3.zig");
const tls_testing = @import("../../tls/testing.zig");
const support = @import("testing/read_interruption.zig");
const allocator = std.testing.allocator;
const Backend = enum { vail_tls12, vail_tls13, standard_tls13 };

test "WSS local read interruptions preserve TLS12 and both TLS13 caller-buffer backends" {
    for (std.enums.values(Backend)) |backend| {
        for (std.enums.values(support.Fault)) |fault| try tlsCase(backend, fault);
    }
}

fn tlsCase(backend: Backend, fault: support.Fault) !void {
    const old = backend == .vail_tls12;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    support.InterruptedIo.delegate = base;
    defer support.InterruptedIo.next = null;
    var vtable = base.vtable.*;
    vtable.batchAwaitConcurrent = support.InterruptedIo.awaitConcurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (old) .tls12_only else .tls13_only,
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.TlsServer,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            try self.release.waitTimeout(self.server.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
            try runtime.testing.writeFrame(&connection, .continuation, "\x98\x83", true);
            try connection.sendBinary("following");
            var message = try connection.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("still writable", message.payload);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(base);
        thread.join();
    };
    var client = try runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{
        .host = "localhost",
        .vail_tls = if (backend == .standard_tls13) null else .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() }, .protocol_policy = if (old) .tls12_only else .tls13_only },
        .limits = .{ .max_message_bytes = 64 },
    }, .{ .verify_host = false });
    defer client.close();
    try support.caller(&client, base, &peer.release, fault);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "WebSocket HTTP2 local read interruptions preserve tunnel and caller-buffer messages" {
    for (std.enums.values(support.Fault)) |fault| try h2Case(fault);
}

fn h2Case(fault: support.Fault) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    support.InterruptedIo.delegate = base;
    defer support.InterruptedIo.next = null;
    var vtable = base.vtable.*;
    vtable.batchAwaitConcurrent = support.InterruptedIo.awaitConcurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var server = try http2.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{ .enable_connect_protocol = true });
    defer server.deinit();
    const Peer = struct {
        server: *http2.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var transport = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer transport.close();
            var connection = try runtime.H2Server.accept(allocator, &transport, .{});
            defer connection.close();
            try self.release.waitTimeout(self.server.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
            const bytes = try support.suffix(allocator);
            defer allocator.free(bytes);
            try connection.tunnel.write(bytes, false);
            var message = try connection.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("still writable", message.payload);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(base);
        thread.join();
    };
    var transport = try http2.Client.connect(allocator, io, server.address(), .{});
    defer transport.close();
    var client = try runtime.H2Client.open(allocator, &transport, .{ .authority = "localhost", .limits = .{ .max_message_bytes = 64 } });
    defer client.close();
    try support.caller(&client, base, &peer.release, fault);
    try std.testing.expect(!transport.aggregate_timeout_unusable);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "WebSocket HTTP3 local read interruptions preserve protected stream and caller-buffer messages" {
    for (std.enums.values(support.Fault)) |fault| try h3Case(fault);
}

fn h3Case(fault: support.Fault) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    support.InterruptedIo.delegate = base;
    defer support.InterruptedIo.next = null;
    var vtable = base.vtable.*;
    vtable.batchAwaitConcurrent = support.InterruptedIo.awaitConcurrent;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    const original = [_]u8{ 0x77, 0x73, 0x14, 1, 2, 3, 4, 5 };
    const server_cid = [_]u8{ 0x77, 0x73, 0x14, 6 };
    const client_cid = [_]u8{ 0x77, 0x73, 0x14, 7 };
    var server = try h3.Server.bind(allocator, base, .{ .ip4 = .loopback(0) }, .{}, .{ .handshake = .{
        .local_connection_id = &server_cid,
        .initial_one_rtt_config = .{ .enable_pacing = false },
        .random = [_]u8{0x91} ** 32,
        .x25519_secret_key = [_]u8{0x92} ** 32,
    } });
    defer server.deinit();
    const Peer = struct {
        server: *h3.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.{}, .fromSeconds(2));
            defer connection.deinit();
            try self.release.waitTimeout(self.server.transport.quic_server.endpoint.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
            const bytes = try support.suffix(allocator);
            defer allocator.free(bytes);
            try connection.h3.sendResponseBody(connection.stream_id, bytes, false);
            var message = try connection.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(allocator);
            try std.testing.expectEqualStrings("still writable", message.payload);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.release.set(base);
        thread.join();
    };
    var client = try h3.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{}, .{ .handshake = .{
        .original_destination_connection_id = &original,
        .local_connection_id = &client_cid,
        .server_name = "localhost",
        .initial_one_rtt_config = .{ .enable_pacing = false },
        .random = [_]u8{0x93} ** 32,
        .x25519_secret_key = [_]u8{0x94} ** 32,
    } }, .{ .authority = "localhost", .limits = .{ .max_message_bytes = 64 } });
    defer client.deinit();
    try support.caller(&client, base, &peer.release, fault);
    try std.testing.expect(!client.h3.established.connection.closing());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
