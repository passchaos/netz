//! Actual native H3 DATA prefix timeout, suffix retry and connection reuse.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const allocator = std.testing.allocator;

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    armed: std.atomic.Value(bool) = .init(false),
    expired: std.atomic.Value(bool) = .init(false),
    prefix: usize = 0,
    shutdown: std.Io.Event = .unset,
    body: [512]u8 = undefined,

    fn io(self: *Probe) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.now = now;
        self.table.netSend = send;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }
    fn from(userdata: ?*anyopaque) *Probe {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        const base = self.backend.io();
        const value = base.vtable.now(base.userdata, clock);
        return if (clock == .awake and self.expired.load(.acquire)) value.addDuration(.fromSeconds(2)) else value;
    }
    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self = from(userdata);
        const base = self.backend.io();
        const result = base.vtable.netSend(base.userdata, socket, messages, flags);
        if (result[1] != 0 and self.armed.swap(false, .acq_rel)) self.expired.store(true, .release);
        return result;
    }
};

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

test "HTTP/3 concurrent DATA native socket prefix timeout retains progress and connection reuse" {
    var probe: Probe = .{ .backend = .init(allocator, .{ .async_limit = .unlimited }) };
    defer probe.backend.deinit();
    for (&probe.body, 0..) |*byte, i| byte.* = @intCast(33 + i % 80);
    const server_io = probe.io();
    const client_io = probe.backend.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{ .max_datagram_size = 4096 }, .max_stream_frame_data = 128 };
    var server = try runtime.HandshakeServer.bind(allocator, server_io, .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer server.deinit();
    const Handler = struct {
        fn run(ctx: *Probe, stream: *runtime.HandshakeServerSession.ConcurrentStream) anyerror!void {
            if (std.mem.eql(u8, stream.head().path, "/reuse")) {
                try stream.startResponseWithBody(.{ .status = 200 }, 5, "reuse", true);
                return;
            }
            try stream.startResponse(.{ .status = 200 }, ctx.body.len);
            const until = std.Io.Clock.Timestamp.fromNow(ctx.backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            ctx.armed.store(true, .release);
            defer {
                ctx.armed.store(false, .release);
                ctx.expired.store(false, .release);
            }
            var progress: runtime.HandshakeServerSession.ConcurrentStream.DataWriteProgress = .{};
            const result = stream.writeDataWithProgressAndDeadline(&ctx.body, true, &progress, until);
            ctx.armed.store(false, .release);
            ctx.expired.store(false, .release);
            try std.testing.expectError(error.Timeout, result);
            try std.testing.expect(progress.committed_bytes > 0 and progress.committed_bytes < ctx.body.len);
            try std.testing.expect(progress.retryable and !progress.fin_committed);
            ctx.prefix = progress.committed_bytes;
            try stream.writeDataWithProgressAndDeadline(ctx.body[ctx.prefix..], true, &progress, until);
            try std.testing.expectEqual(ctx.body.len - ctx.prefix, progress.committed_bytes);
            try std.testing.expect(progress.retryable and progress.fin_committed);
        }
    };
    const Worker = struct {
        fn run(listener: *runtime.HandshakeServer, ctx: *Probe) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            session.options.paced_body_chunk_bytes = 64;
            session.established.connection.config.enable_pacing = false;
            const summary = try session.serveConcurrentStreams(Probe, ctx, Handler.run, .{ .max_streams = 2, .shutdown = &ctx.shutdown });
            try std.testing.expectEqual(@as(usize, 2), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };
    var serving = try client_io.concurrent(Worker.run, .{ &server, &probe });
    defer {
        probe.shutdown.set(server_io);
        _ = serving.cancel(client_io) catch {};
    }
    var client = try runtime.HandshakeClient.connect(allocator, client_io, .{ .ip4 = .loopback(0) }, server.address(), limits, .{
        .handshake = .{ .original_destination_connection_id = &.{ 9, 8, 7, 6, 5, 4, 3, 2 }, .local_connection_id = &.{ 2, 3, 4, 5, 6, 7, 8, 9 }, .server_name = "localhost", .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key } },
    });
    defer client.deinit();
    var response = try client.requestWithDeadline(.{ .method = "GET", .path = "/prefix", .authority = "localhost" }, deadline(client_io));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(&probe.body, response.response.body);
    var reused = try client.requestWithDeadline(.{ .method = "GET", .path = "/reuse", .authority = "localhost" }, deadline(client_io));
    defer reused.deinit(allocator);
    try std.testing.expectEqualStrings("reuse", reused.response.body);
    probe.shutdown.set(server_io);
    try serving.await(client_io);
    try std.testing.expectEqual(@as(usize, 64), probe.prefix);
}
