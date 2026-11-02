//! Connection attempts must not pin every listener worker indefinitely.
const std = @import("std");
const endpoint = @import("../endpoint_listener.zig");
const http2 = @import("../../../http2/mod.zig");
const tls = @import("../../../tls/testing.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const allocator = std.testing.allocator;

fn eof(io: std.Io, peer: std.Io.net.Stream) !void {
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    var bytes: [512]u8 = undefined;
    while (true) {
        const n = stream_io.readSomeWithDeadline(io, peer, &bytes, until) catch |err| switch (err) {
            error.ConnectionResetByPeer => return,
            else => return err,
        };
        if (n == 0) return;
    }
}

fn connected(io: std.Io, listener: endpoint.EndpointListener) !void {
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (endpoint.EndpointListener.testing.snapshot(listener).connected != 1) {
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}

fn options() endpoint.Options {
    return .{ .max_connections = 1, .max_pending_requests = 1, .accept_workers = 1, .connection_timeout = .fromMilliseconds(100) };
}

test "WebTransport HTTP2 EndpointListener connection budget releases a silent HTTP2 peer and retries" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const raw = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    var listener = try endpoint.EndpointListener.initServer(allocator, raw, options());
    defer listener.deinit();
    // An idle listener must still grant a newly accepted peer its full budget.
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    const silent = try listener.address().connect(io, .{ .mode = .stream });
    defer silent.close(io);
    try eof(io, silent);
    var healthy = try http2.runtime.Client.connectWithTimeout(allocator, io, listener.address(), .{}, .fromSeconds(2));
    defer healthy.close();
    try connected(io, listener);
    const snapshot = endpoint.EndpointListener.testing.snapshot(listener);
    try std.testing.expectEqual(@as(usize, 1), snapshot.connected);
    try std.testing.expectEqual(@as(usize, 0), snapshot.reserved);
}

test "WebTransport HTTP2 EndpointListener connection budget releases a silent TLS peer" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    const raw = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
    });
    var listener = try endpoint.EndpointListener.initTlsServer(allocator, raw, options());
    defer listener.deinit();
    const silent = try listener.address().connect(io, .{ .mode = .stream });
    defer silent.close(io);
    try eof(io, silent);
    var healthy = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, listener.address(), "localhost", "localhost", .{}, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(2));
    defer healthy.close();
    try connected(io, listener);
}

const LateOwner = struct {
    base: std.Io,
    caller: std.Thread.Id,
    armed: std.atomic.Value(bool) = .init(false),
    shifted: std.atomic.Value(bool) = .init(false),
    owner: std.atomic.Value(?[*]u8) = .init(null),
    freed: std.Io.Event = .unset,
    var active: ?*LateOwner = null;

    fn allocator(self: *LateOwner) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *LateOwner = @ptrCast(@alignCast(context));
        const bytes = std.testing.allocator.rawAlloc(len, alignment, ra);
        if (bytes != null and std.Thread.getCurrentId() != self.caller and self.armed.swap(false, .acq_rel)) {
            // The raw HTTP/2 listener has a separate allocator. This allocation
            // starts ManagedConnection after the bootstrap has completed.
            self.owner.store(bytes, .release);
            self.shifted.store(true, .release);
        }
        return bytes;
    }
    fn resize(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        return std.testing.allocator.rawResize(bytes, alignment, len, ra);
    }
    fn remap(_: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        return std.testing.allocator.rawRemap(bytes, alignment, len, ra);
    }
    fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *LateOwner = @ptrCast(@alignCast(context));
        const matched = self.owner.load(.acquire) == bytes.ptr;
        std.testing.allocator.rawFree(bytes, alignment, ra);
        if (matched) self.freed.set(self.base);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = active.?;
        const original = self.base.vtable.now(userdata, clock);
        return if (clock == .awake and self.shifted.load(.acquire)) original.addDuration(.fromSeconds(1)) else original;
    }
};

test "WebTransport HTTP2 EndpointListener connection budget is not renewed for managed owner allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var probe = LateOwner{ .base = base, .caller = std.Thread.getCurrentId() };
    LateOwner.active = &probe;
    defer LateOwner.active = null;
    var table = base.vtable.*;
    table.now = LateOwner.now;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    const raw = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    var listener = try endpoint.EndpointListener.initServer(probe.allocator(), raw, options());
    defer listener.deinit();
    probe.armed.store(true, .release);
    var healthy = http2.runtime.Client.connectWithTimeout(allocator, base, listener.address(), .{}, .fromSeconds(2)) catch |err| switch (err) {
        error.ConnectionClosed, error.ConnectionResetByPeer, error.UnexpectedEof, error.SocketUnconnected => null,
        else => return err,
    };
    defer if (healthy) |*connection| connection.close();
    try probe.freed.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
    try std.testing.expect(probe.shifted.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), endpoint.EndpointListener.testing.snapshot(listener).connected);
    if (healthy) |connection| try eof(base, connection.stream);
}

test "WebTransport HTTP2 EndpointListener rejects a nonpositive connection budget" {
    for ([_]std.Io.Duration{ .zero, .fromNanoseconds(-1) }) |timeout| {
        var value = options();
        value.connection_timeout = timeout;
        try std.testing.expectError(error.InvalidListenerOptions, value.validate());
    }
}
