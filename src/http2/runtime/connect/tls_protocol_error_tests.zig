//! TLS close_notify must not outlive the HTTP/2 protocol-error cleanup budget.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const tls = @import("../../../tls/mod.zig");
const BlockedTlsWrite = @import("../testing/blocked_tls_write.zig").BlockedTlsWrite;
const allocator = std.testing.allocator;
const Mode = @import("../testing/blocked_tls_write.zig").Mode;

test "HTTP/2 handshake protocol error bounds TLS12 and TLS13 GOAWAY and close notify" {
    if (comptime builtin.os.tag != .linux) return;
    for ([_]bool{ false, true }) |tls12| {
        for (std.enums.values(Mode)) |mode| try exercise(tls12, mode);
    }
}

fn exercise(tls12: bool, mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.testing.certificate_base64);
    const key = try tls.testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        .limits = .{ .terminal_cleanup_timeout = if (mode == .disabled) .zero else .fromMilliseconds(20) },
    });
    defer server.deinit();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var peer_owned = true;
    defer if (peer_owned) stream.close(io);
    const accepted = try server.listener.accept(io);
    var writer = BlockedTlsWrite{ .io = io, .mode = mode, .socket = accepted.socket.handle };
    var vtable: std.Io.VTable = undefined;
    server.io = writer.install(&vtable, io);
    defer {
        server.io = io;
        BlockedTlsWrite.clear();
    }
    const Shared = struct {
        server: *runtime.TlsServer,
        stream: std.Io.net.Stream,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            var connection = self.server.acceptStream(self.stream) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server, .stream = accepted };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        writer.wait.set(io);
        accepted.shutdown(io, .both) catch {};
        thread.join();
    };
    const peer = try tls.stream.ClientConnection.initWithDeadline(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .alpn_protocols = &.{"h2"},
        .protocol_policy = if (tls12) .tls12_only else .tls13_only,
    }, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    peer_owned = false;
    defer peer.deinit();
    try std.testing.expectEqualStrings("h2", peer.selected_alpn.?);
    writer.armed.store(true, .release);
    const rescue = try std.Thread.spawn(.{}, BlockedTlsWrite.rescue, .{&writer});
    defer rescue.join();
    const started = std.Io.Clock.awake.now(io);
    try peer.writeAll("x" ** http2.connection_preface.len);
    try shared.done.wait(io);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.InvalidPreface, shared.err.?);
    try std.testing.expectEqual(@as(usize, switch (mode) {
        .disabled => 0,
        .blocked => 1,
        .healthy, .partial, .close_blocked => 2,
    }), writer.calls.load(.acquire));
    if (mode == .blocked or mode == .close_blocked) try std.testing.expect(writer.canceled.load(.acquire));
    if (mode == .healthy) {
        var buffer: [128]u8 = undefined;
        const len = try peer.readWithDeadline(&buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        const frame = try http2.Frame.parse(buffer[0..len]);
        const goaway = try http2.GoAwayPayload.parse(frame);
        try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.error_code);
        try std.testing.expectEqualStrings("invalid-preface", goaway.debug_data);
        try std.testing.expectEqual(@as(usize, 0), try peer.readWithDeadline(&buffer, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expect(switch (peer.records) {
            inline else => |records| records.receivedCloseNotify(),
        });
    }
}
