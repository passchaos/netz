//! An owned server stream must retire even when terminal output is blocked.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const grpc = @import("../../../grpc/stream/mod.zig");
const tls = @import("../../../tls/mod.zig");
const frame_wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const Action = enum { response_reset, response_drop, duplex_reset, duplex_drop, grpc_reset, grpc_drop, abandon };
const Mode = enum { blocked, partial, disabled, unusable, oom };
const Writer = struct {
    var active: std.atomic.Value(?*Writer) = .init(null);
    io: std.Io,
    mode: Mode,
    calls: std.atomic.Value(usize) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),
    wait: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, bytes: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        const count = self.calls.fetchAdd(1, .monotonic);
        switch (self.mode) {
            .blocked => {
                self.wait.wait(self.io) catch |err| {
                    self.cancelled.store(true, .release);
                    return err;
                };
                return bytes.len;
            },
            .partial => return if (count == 0) @min(bytes.len, 4) else error.NetworkDown,
            .disabled, .unusable, .oom => return error.NetworkDown,
        }
    }

    fn rescue(self: *Writer) void {
        std.Io.sleep(self.io, .fromMilliseconds(500), .awake) catch {};
        self.wait.set(self.io);
    }
};

fn queueRequest(connection: *runtime.Connection, id: u31) !void {
    return queueRequestFlags(connection, id, 5);
}

fn queueRequestFlags(connection: *runtime.Connection, id: u31, flags: u8) !void {
    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/fixture.Termination/Call" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-type", .value = "application/grpc+proto" },
        .{ .name = "te", .value = "trailers" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &headers);
    try frame_wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, flags, id, encoded.items);
}

test "HTTP/2 server stream terminal cleanup bounds reset abandonment and destruction" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (std.enums.values(Action)) |action| try exercise(action, .blocked);
}

test "HTTP/2 server stream terminal cleanup releases failed and disabled reset state" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (std.enums.values(Action)) |action| {
        inline for (.{ Mode.partial, Mode.disabled, Mode.unusable, Mode.oom }) |mode| try exercise(action, mode);
    }
}

test "HTTP/2 server stream terminal cleanup preserves an admitted sibling" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    connection.limits.terminal_cleanup_timeout = .fromSeconds(1);
    try queueRequest(connection, 1);
    try queueRequest(connection, 3);
    var first = try connection.readRequestWithTimeout(.fromSeconds(1));
    defer first.deinit(allocator);
    var sibling = try connection.readRequestWithTimeout(.fromSeconds(1));
    defer sibling.deinit(allocator);
    var writer = try connection.startResponse(first.stream_id, .{});
    defer writer.deinit();
    try writer.reset(.cancel);
    try std.testing.expectEqual(@as(usize, 1), connection.activePeerStreamCount());
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.terminal_write_failed);
    try connection.writeResponse(sibling.stream_id, .{ .body = "healthy" });
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.response_semantics.items.len);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}

test "HTTP/2 server stream terminal cleanup retires incomplete request trailers" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try queueRequestFlags(connection, 1, 4);
    var stream = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1));
    defer stream.deinit();
    try frame_wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 1, 1, &.{});
    try std.testing.expectError(error.Timeout, stream.readRequestEventWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectError(error.ConnectionClosed, stream.reset(.cancel));
    try std.testing.expect(stream.released);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expect(!connection.duplex_reader_active);
}

test "HTTP/2 server stream terminal cleanup bounds real TLS12 and TLS13 resets" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ false, true }) |tls12| {
        try tlsReset(tls12, false);
        try tlsReset(tls12, true);
    }
}

fn tlsReset(tls12: bool, comptime duplex: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var listener = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .limits = .{ .terminal_cleanup_timeout = .fromMilliseconds(20) },
        .tls_handshake_timeout = .fromSeconds(2),
    });
    defer listener.deinit();
    const Peer = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        key: []const u8,
        tls12: bool,
        finished: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var client = try runtime.Client.connectTlsAddress(allocator, self.io, self.address, "localhost", "localhost", .{}, .{
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = self.key[0..65].* },
                .protocol_policy = if (self.tls12) .tls12_only else .tls13_only,
            });
            defer client.close();
            var request = try client.startRequest(.{ .method = "POST", .path = "/terminal", .authority = "localhost" });
            defer request.deinit();
            try request.finish();
            try self.finished.wait(self.io);
        }
    };
    const public_key = key.public_key.toUncompressedSec1();
    var peer: Peer = .{ .io = io, .address = listener.address(), .key = &public_key, .tls12 = tls12 };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        peer.finished.set(io);
        thread.join();
    };
    var connection = try listener.acceptWithTimeout(.fromSeconds(2));
    defer connection.close();
    var owner = if (duplex) try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1)) else blk: {
        var request = try connection.readRequestWithTimeout(.fromSeconds(1));
        defer request.deinit(allocator);
        break :blk try connection.startResponse(request.stream_id, .{});
    };
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    const transport = switch (connection.transport.?) {
        .tls_server => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var writer: Writer = .{ .io = io, .mode = .blocked };
    Writer.active.store(&writer, .release);
    defer Writer.active.store(null, .release);
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    transport.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer transport.io = io;
    const rescue = try std.Thread.spawn(.{}, Writer.rescue, .{&writer});
    defer rescue.join();
    try std.testing.expectError(error.Timeout, owner.reset(.cancel));
    try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expect(!connection.duplex_reader_active);
    try std.testing.expect(writer.cancelled.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), writer.calls.load(.acquire));
    const pending = switch (transport.records) {
        inline else => |records| records.pending_write_len,
    };
    try std.testing.expect(pending >= 13 + 16 + 5);
    owner.deinit();
    owner_live = false;
    try std.testing.expectEqual(@as(usize, 1), writer.calls.load(.acquire));
    try std.testing.expectEqual(pending, switch (transport.records) {
        inline else => |records| records.pending_write_len,
    });
    peer.finished.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn exercise(comptime action: Action, mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    try queueRequest(connection, 1);
    const duplex = action == .duplex_reset or action == .duplex_drop;
    const grpc_duplex = action == .grpc_reset or action == .grpc_drop;
    var owner = if (grpc_duplex) try grpc.acceptDuplexWithTimeout(connection, allocator, 1024, .fromSeconds(1)) else if (duplex) try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1)) else blk: {
        var request = try connection.readRequestWithTimeout(.fromSeconds(1));
        defer request.deinit(allocator);
        break :blk try connection.startResponse(request.stream_id, .{});
    };
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    _ = try runtime.testing.sendStreamWindow(connection, 1);
    _ = try runtime.testing.recvStreamWindow(connection, 1);
    connection.limits.terminal_cleanup_timeout = if (mode == .disabled) .zero else .fromMilliseconds(20);
    if (mode == .unusable) connection.aggregate_timeout_unusable = true;
    var writer: Writer = .{ .io = io, .mode = mode };
    Writer.active.store(&writer, .release);
    defer Writer.active.store(null, .release);
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    const rescue: ?std.Thread = if (mode == .blocked) try std.Thread.spawn(.{}, Writer.rescue, .{&writer}) else null;
    defer if (rescue) |thread| thread.join();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    if (mode == .oom) connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    const started = std.Io.Clock.awake.now(io);
    if (action == .abandon) {
        connection.abandonPeerRequest(1, .internal_error);
        owner.finished = true;
    } else if (action == .response_drop or action == .duplex_drop or action == .grpc_drop) {
        owner.deinit();
        owner_live = false;
    } else {
        try std.testing.expectError(switch (mode) {
            .blocked, .disabled => error.Timeout,
            .partial => error.NetworkDown,
            .unusable => error.ConnectionClosed,
            .oom => error.OutOfMemory,
        }, owner.reset(.internal_error));
    }
    connection.allocator = allocator;
    if (mode == .oom) try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.response_semantics.items.len);
    try std.testing.expect(!connection.duplex_reader_active);
    const expected: usize = switch (mode) {
        .blocked => 1,
        .partial => 2,
        .disabled, .unusable, .oom => 0,
    };
    try std.testing.expectEqual(expected, writer.calls.load(.acquire));
    if (mode == .blocked) try std.testing.expect(writer.cancelled.load(.acquire));
    if (owner_live) {
        owner.deinit();
        owner_live = false;
        try std.testing.expectEqual(expected, writer.calls.load(.acquire));
    }
}
