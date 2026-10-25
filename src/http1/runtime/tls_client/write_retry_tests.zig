//! Standard TLS preserves pending-record input across retries and buffer moves.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls_stream = @import("../../../tls/mod.zig").stream;
const tls_testing = @import("../../../tls/testing.zig");
const support = @import("../../../internal/testing/write_interruption.zig");
const allocator = std.testing.allocator;

test "standard TLS bounded write rejects changed pending input and accepts a relocated larger retry" {
    for (std.enums.values(support.Stage)) |stage| try exercise(stage, false);
}

test "standard TLS explicit pending write completion releases retry identity" {
    try exercise(.after_prefix, true);
}

fn exercise(stage: support.Stage, finish_explicitly: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var probe = support.Probe{ .delegate = base, .stage = stage, .prefix_len = if (stage == .before_write) 0 else 6, .armed = false };
    support.Probe.active = &probe;
    var vtable = base.vtable.*;
    vtable.groupConcurrent = support.Probe.groupConcurrent;
    vtable.netWrite = support.Probe.netWrite;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
    defer listener.deinit(base);
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const first = "pending plaintext";
    const next = "/new tail";
    const Peer = struct {
        listener: *@TypeOf(listener),
        io: std.Io,
        certificate: []const u8,
        key: @TypeOf(key),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            const socket = try self.listener.accept(self.io);
            var owned = true;
            errdefer if (owned) socket.close(self.io);
            const connection = try tls_stream.ServerConnection.init(allocator, self.io, socket, .{
                .identity = .{ .certificate_chain = &.{self.certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } } },
            });
            owned = false;
            defer connection.deinit();
            var received: [first.len + next.len]u8 = undefined;
            var count: usize = 0;
            while (count < received.len) {
                const read = try connection.readWithDeadline(received[count..], .fromNow(self.io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
                try std.testing.expect(read != 0);
                count += read;
            }
            try std.testing.expectEqualStrings(first ++ next, &received);
            try connection.writeAll("ack");
        }
    };
    var peer = Peer{ .listener = &listener, .io = base, .certificate = &certificate, .key = key };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const socket = try listener.socket.address.connect(base, .{ .mode = .stream });
    var owned = true;
    defer if (owned) socket.close(base);
    const connection = try runtime.TlsClientConnection.init(allocator, io, socket, "localhost", .{ .verify_host = false });
    owned = false;
    defer connection.deinit();
    probe.written = 0;
    probe.armed = true;
    var committed: usize = 99;
    var original: [first.len]u8 = first.*;
    try std.testing.expectError(error.ConcurrencyUnavailable, connection.writeAllWithDeadline(&original, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectEqual(@as(usize, 0), committed);
    probe.armed = false;
    const before = probe.written;
    const pending_ciphertext_len = connection.net_writer.interface.buffered().len;
    original[0] ^= 1;
    for ([_][]const u8{ "", original[0..1], &original }) |bad| {
        try std.testing.expectError(error.WriteInProgress, connection.writeAllWithDeadline(bad, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expectEqual(before, probe.written);
        try std.testing.expectEqual(first.len, connection.pending_timed_plaintext_len);
        try std.testing.expectEqual(pending_ciphertext_len, connection.net_writer.interface.buffered().len);
    }
    if (finish_explicitly) {
        try connection.finishPendingTimedWrite(&committed);
        try std.testing.expectEqual(first.len, committed);
        try connection.writeAll(next);
    } else {
        var relocated: [first.len + next.len]u8 = (first ++ next).*;
        try connection.writeAllWithDeadline(&relocated, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        try std.testing.expectEqual(relocated.len, committed);
    }
    try std.testing.expectEqual(@as(usize, 0), connection.pending_timed_plaintext_len);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &connection.pending_timed_plaintext_fingerprint.digest);
    var ack: [3]u8 = undefined;
    const ack_len = try connection.readWithDeadline(&ack, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    try std.testing.expectEqualStrings("ack", ack[0..ack_len]);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
